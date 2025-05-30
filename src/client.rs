use tokio::net::TcpStream;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{Mutex, mpsc};
use std::collections::HashMap;
use std::sync::Arc;
use std::error::Error;
use crate::auth::authorize_user;
use crate::message::{broadcast_message, send_to_user};
use crate::log::log_message;
use colored::Color;
use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rand::{rngs::OsRng, RngCore};
use hex;

type Tx = mpsc::UnboundedSender<String>;

#[derive(Debug, Clone)]
pub enum ClientState {
    PublicChat,
    WaitingForPrivateChatResponse { target_nick: String, sent_key: Vec<u8> },
    HasPendingPrivateChatRequest { from_nick: String, shared_key: Vec<u8> },
    InPrivateChat { with_nick: String, shared_key: Vec<u8> },
}

pub async fn handle_client(
    socket: TcpStream,
    users_db: Arc<Mutex<HashMap<String, String>>>,
    connected_users: Arc<Mutex<HashMap<String, Tx>>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (reader_half, writer_half) = socket.into_split();
    let mut reader = BufReader::new(reader_half);
    let writer_arc = Arc::new(Mutex::new(writer_half));

    {
        let mut writer_guard = writer_arc.lock().await;
        writer_guard.write_all("Добро пожаловать в чат! Введите /help для списка команд.\n".as_bytes()).await?;
        writer_guard.flush().await?;
    }

    let nickname = authorize_user(&mut reader, &writer_arc, users_db).await?;

    {
        let users_guard = connected_users.lock().await;
        if users_guard.contains_key(&nickname) {
            let mut writer_guard = writer_arc.lock().await;
            writer_guard.write_all("Пользователь с таким ником уже в сети. Отключение.\n".as_bytes()).await?;
            writer_guard.flush().await?;
            log_message("Auth", &format!("Обнаружен дубликат никнейма '{}'. Отключение клиента.", nickname), Color::Red).await?;
            return Err("Дубликат никнейма".into());
        }
    }

    {
        let users_guard = connected_users.lock().await;
        let connected_list: Vec<String> = users_guard.keys()
            .filter(|name| *name != &nickname)
            .cloned()
            .collect();
        let mut writer_guard = writer_arc.lock().await;
        if connected_list.is_empty() {
            writer_guard.write_all("Пока никто больше не подключён.\n".as_bytes()).await?;
        } else {
            writer_guard.write_all(format!("Сейчас в сети: {}\n", connected_list.join(", ")).as_bytes()).await?;
        }
        writer_guard.flush().await?;
    }

    let (tx_to_client, rx_from_others) = mpsc::unbounded_channel::<String>();
    {
        let mut users_guard = connected_users.lock().await;
        users_guard.insert(nickname.clone(), tx_to_client);
    }

    let join_msg = format!("Пользователь '{}' вошёл в чат", nickname);
    log_message("Auth", &join_msg, Color::Yellow).await?;
    broadcast_message(&connected_users, &nickname, &join_msg, true).await;
    let client_state = Arc::new(Mutex::new(ClientState::PublicChat));

    let read_task = tokio::spawn({
        let writer_arc_clone = writer_arc.clone();
        let connected_users_read = connected_users.clone();
        let nickname_read = nickname.clone();
        let client_state_read = client_state.clone();
        let mut reader = reader;

        async move {
            let res: Result<(), Box<dyn Error + Send + Sync>> = loop {
                let mut line = String::new();
                let _bytes_read = match reader.read_line(&mut line).await {
                    Ok(0) => {
                        log_message("Client", &format!("{}: Клиент отключился (прочитано 0 байт).", nickname_read), Color::Cyan).await?;
                        break Ok(());
                    },
                    Ok(n) => n,
                    Err(e) => {
                        log_message("Error", &format!("Ошибка чтения от {}: {}", nickname_read, e), Color::Red).await?;
                        break Err(e.into());
                    },
                };

                let msg_trimmed = line.trim();
                if msg_trimmed.is_empty() { continue; }

                if msg_trimmed.to_lowercase() == "выход" {
                    let mut state_guard = client_state_read.lock().await;
                    if let ClientState::InPrivateChat { with_nick, shared_key: _ } = &*state_guard {
                        let partner_nick = with_nick.clone();
                        *state_guard = ClientState::PublicChat;
                        drop(state_guard);

                        let _ = send_to_user(
                            &connected_users_read,
                            &partner_nick,
                            format!("SYSTEM:PRIVATE_CHAT_ENDED:{}", nickname_read)
                        ).await;

                        let mut writer_guard = writer_arc_clone.lock().await;
                        writer_guard.write_all("Вы вышли из личного чата. Возвращение в общий чат.\n".as_bytes()).await?;
                        writer_guard.flush().await?;
                        drop(writer_guard);

                        log_message("Info", &format!("'{}' вышел из приватного чата с '{}'", nickname_read, partner_nick), Color::Cyan).await?;
                        continue;
                    }
                    drop(state_guard);
                }

                if msg_trimmed.starts_with('/') {
                    let mut parts = msg_trimmed[1..].splitn(2, ' ');
                    let command = parts.next().unwrap_or("").to_lowercase();
                    let args = parts.next().unwrap_or("").trim();

                    match command.as_str() {
                        "help" => {
                            let mut writer_guard = writer_arc_clone.lock().await;
                            writer_guard.write_all(
                                "Доступные команды:\n\
                                 \t/help - Показать это сообщение\n\
                                 \t/list - Показать список подключённых пользователей\n\
                                 \t/pm <ник> - Предложить личный чат пользователю <ник>\n\
                                 \t/accept - Принять запрос на личный чат\n\
                                 \t/reject - Отклонить запрос на личный чат\n\
                                 \t'выход' - (в приватном чате) Выйти из приватного чата\n\
                                 \tлюбое_сообщение - Отправить сообщение всем в публичный чат\n"
                                .as_bytes()
                            ).await?;
                            writer_guard.flush().await?;
                            drop(writer_guard);
                            log_message("Cmd", &format!("'{}' запросил /help", nickname_read), Color::Magenta).await?;
                        }
                        "list" => {
                            let users = connected_users_read.lock().await;
                            let connected_list: Vec<String> = users.keys()
                                .filter(|name| *name != &nickname_read)
                                .cloned()
                                .collect();
                            drop(users);

                            let mut writer_guard = writer_arc_clone.lock().await;
                            if connected_list.is_empty() {
                                writer_guard.write_all("Пока никто больше не подключён.\n".as_bytes()).await?;
                            } else {
                                writer_guard.write_all(format!("Сейчас в сети: {}\n", connected_list.join(", ")).as_bytes()).await?;
                            }
                            writer_guard.flush().await?;
                            drop(writer_guard);
                            log_message("Cmd", &format!("'{}' запросил /list. Онлайн пользователи: {}", nickname_read, connected_list.join(", ")), Color::Magenta).await?;
                        }
                        "pm" => {
                            if args.is_empty() {
                                let mut writer_guard = writer_arc_clone.lock().await;
                                writer_guard.write_all("Укажите ник пользователя для личного чата: /pm <ник>\n".as_bytes()).await?;
                                writer_guard.flush().await?;
                                drop(writer_guard);
                                log_message("Cmd", &format!("'{}' ввел /pm без цели.", nickname_read), Color::Red).await?;
                            } else if args == nickname_read {
                                let mut writer_guard = writer_arc_clone.lock().await;
                                writer_guard.write_all("Вы не можете начать личный чат с самим собой.\n".as_bytes()).await?;
                                writer_guard.flush().await?;
                                drop(writer_guard);
                                log_message("Cmd", &format!("'{}' пытался начать /pm с самим собой.", nickname_read), Color::Red).await?;
                            }
                            else {
                                let mut state_guard = client_state_read.lock().await;
                                match &mut *state_guard {
                                    ClientState::PublicChat => {
                                        let target_nick = args.to_string();
                                        let mut key_bytes = [0u8; 32];
                                        OsRng.fill_bytes(&mut key_bytes);
                                        let shared_key = key_bytes.to_vec();
                                        let key_hex = hex::encode(&shared_key);

                                        let current_nickname = nickname_read.clone();
                                        let target_nick_clone = target_nick.clone();
                                        let shared_key_clone = shared_key.clone();
                                        *state_guard = ClientState::WaitingForPrivateChatResponse { target_nick: target_nick.clone(), sent_key: shared_key_clone };
                                        drop(state_guard);

                                        if send_to_user(&connected_users_read, &target_nick_clone, format!("SYSTEM:PRIVATE_CHAT_REQUEST:{}:{}", current_nickname, key_hex)).await.is_ok() {
                                            let mut writer_guard = writer_arc_clone.lock().await;
                                            writer_guard.write_all(format!("Запрос на личный чат отправлен пользователю '{}'. Ожидание ответа...\n", target_nick_clone).as_bytes()).await?;
                                            writer_guard.flush().await?;
                                            drop(writer_guard);
                                            log_message("Private chat", &format!("'{}' запросил приватный чат у '{}'", current_nickname, target_nick_clone), Color::Cyan).await?;
                                        } else {
                                            let mut writer_guard = writer_arc_clone.lock().await;
                                            writer_guard.write_all(format!("Пользователь '{}' не найден или не в сети.\n", target_nick_clone).as_bytes()).await?;
                                            writer_guard.flush().await?;
                                            drop(writer_guard);
                                            log_message("Private chat", &format!("'{}' пытался запросить приватный чат у оффлайн пользователя '{}'", current_nickname, target_nick_clone), Color::Red).await?;
                                        }
                                    }
                                    _ => {
                                        let state_for_log = format!("{:?}", *state_guard);
                                        drop(state_guard);
                                        let mut writer_guard = writer_arc_clone.lock().await;
                                        writer_guard.write_all("Вы не можете начать новый личный чат, находясь не в общем чате.\n".as_bytes()).await?;
                                        writer_guard.flush().await?;
                                        drop(writer_guard);
                                        log_message("Private chat", &format!("'{}' пытался инициировать ЛС, находясь не в общем чате (текущее состояние: {})", nickname_read, state_for_log), Color::Red).await?;
                                    }
                                }
                            }
                        }
                        "accept" => {
                            let mut state_guard = client_state_read.lock().await;
                            if let ClientState::HasPendingPrivateChatRequest { from_nick, shared_key } = &mut *state_guard {
                                let partner_nick = from_nick.clone();
                                let key_to_use = shared_key.clone();
                                let current_nickname = nickname_read.clone();
                                *state_guard = ClientState::InPrivateChat { with_nick: partner_nick.clone(), shared_key: key_to_use };
                                drop(state_guard);

                                if send_to_user(&connected_users_read, &partner_nick, format!("SYSTEM:PRIVATE_CHAT_ACCEPTED:{}", current_nickname)).await.is_ok() {
                                    let mut writer_guard = writer_arc_clone.lock().await;
                                    writer_guard.write_all(format!("Вы начали личный чат с '{}'. Напишите 'выход' для возврата в общий чат.\n", partner_nick).as_bytes()).await?;
                                    writer_guard.flush().await?;
                                    drop(writer_guard);
                                    log_message("Private chat", &format!("'{}' обновил статус: приватный чат с '{}'", current_nickname, partner_nick), Color::Cyan).await?;
                                } else {
                                    let mut writer_guard = writer_arc_clone.lock().await;
                                    writer_guard.write_all(format!("Не удалось уведомить '{}', возможно, он отключился. Вы возвращены в общий чат.\n", partner_nick).as_bytes()).await?;
                                    writer_guard.flush().await?;
                                    drop(writer_guard);
                                    log_message("Private chat", &format!("'{}' принял приватный чат от '{}', но не смог уведомить партнера.", current_nickname, partner_nick), Color::Red).await?;
                                    let mut state_guard_revert = client_state_read.lock().await;
                                    *state_guard_revert = ClientState::PublicChat;
                                    drop(state_guard_revert);
                                }
                            } else {
                                drop(state_guard);
                                let mut writer_guard = writer_arc_clone.lock().await;
                                writer_guard.write_all("Нет активных запросов на личный чат для принятия.\n".as_bytes()).await?;
                                writer_guard.flush().await?;
                                drop(writer_guard);
                                log_message("Cmd", &format!("'{}' пытался /accept без ожидающего запроса.", nickname_read), Color::Yellow).await?;
                            }
                        }
                        "reject" => {
                            let mut state_guard = client_state_read.lock().await;
                            if let ClientState::HasPendingPrivateChatRequest { from_nick, shared_key: _ } = &mut *state_guard {
                                let partner_nick = from_nick.clone();
                                let current_nickname = nickname_read.clone();
                                *state_guard = ClientState::PublicChat;
                                drop(state_guard);

                                if send_to_user(&connected_users_read, &partner_nick, format!("SYSTEM:PRIVATE_CHAT_REJECTED:{}", current_nickname)).await.is_ok() {
                                    let mut writer_guard = writer_arc_clone.lock().await;
                                    writer_guard.write_all(format!("Вы отклонили запрос на личный чат от '{}'.\n", partner_nick).as_bytes()).await?;
                                    writer_guard.flush().await?;
                                    drop(writer_guard);
                                    log_message("Private chat", &format!("'{}' отклонил приватный чат от '{}'", current_nickname, partner_nick), Color::Cyan).await?;
                                } else {
                                    let mut writer_guard = writer_arc_clone.lock().await;
                                    writer_guard.write_all(format!("Не удалось уведомить '{}' об отклонении, возможно, он отключился.\n", partner_nick).as_bytes()).await?;
                                    writer_guard.flush().await?;
                                    drop(writer_guard);
                                    log_message("Private chat", &format!("'{}' отклонил приватный чат от '{}', но не смог уведомить партнера.", current_nickname, partner_nick), Color::Red).await?;
                                }
                            } else {
                                drop(state_guard);
                                let mut writer_guard = writer_arc_clone.lock().await;
                                writer_guard.write_all("Нет активных запросов на личный чат для отклонения.\n".as_bytes()).await?;
                                writer_guard.flush().await?;
                                drop(writer_guard);
                                log_message("Cmd", &format!("'{}' пытался /reject без ожидающего запроса.", nickname_read), Color::Yellow).await?;
                            }
                        }
                        _ => {
                            let mut writer_guard = writer_arc_clone.lock().await;
                            writer_guard.write_all(format!("Неизвестная команда: '{}'. Введите /help.\n", command).as_bytes()).await?;
                            writer_guard.flush().await?;
                            drop(writer_guard);
                            log_message("Cmd", &format!("'{}' ввел неизвестную команду: '{}'", nickname_read, command), Color::Red).await?;
                        }
                    }
                }
                else {
                    let current_state_clone;
                    {
                        let state_guard = client_state_read.lock().await;
                        current_state_clone = state_guard.clone();
                    }

                    match current_state_clone {
                        ClientState::InPrivateChat { with_nick, shared_key } => {
                            let cipher = Aes256Gcm::new_from_slice(&shared_key).expect("Key length is 32 bytes");
                            let mut nonce_array = [0u8; 12];
                            OsRng.fill_bytes(&mut nonce_array);
                            let nonce = Nonce::from_slice(&nonce_array);

                            let ciphertext_result = cipher.encrypt(&nonce, msg_trimmed.as_bytes());
                            match ciphertext_result {
                                Ok(ciphertext) => {
                                    let encrypted_msg = format!(
                                        "SYSTEM:ENCRYPTED_PRIVATE_MSG:{}:{}:{}",
                                        nickname_read,
                                        hex::encode(nonce_array),
                                        hex::encode(ciphertext)
                                    );
                                    if send_to_user(&connected_users_read, &with_nick, encrypted_msg).await.is_ok() {
                                        log_message("Private", &format!("'{}' отправил зашифрованное ЛС '{}'", nickname_read, with_nick), Color::Blue).await?;
                                    } else {
                                        let mut writer_guard = writer_arc_clone.lock().await;
                                        writer_guard.write_all(format!("Не удалось отправить сообщение '{}'. Возможно, пользователь отключился. Вы возвращены в общий чат.\n", with_nick).as_bytes()).await?;
                                        writer_guard.flush().await?;
                                        drop(writer_guard);
                                        log_message("Private", &format!("'{}' не смог отправить зашифрованное ЛС '{}'. Партнер отключился.", nickname_read, with_nick), Color::Red).await?;
                                        let mut state_guard_revert = client_state_read.lock().await;
                                        *state_guard_revert = ClientState::PublicChat;
                                        drop(state_guard_revert);
                                    }
                                }
                                Err(e) => {
                                    log_message("Error", &format!("Ошибка шифрования для {}: {:?}", nickname_read, e), Color::Red).await?;
                                    let mut writer_guard = writer_arc_clone.lock().await;
                                    writer_guard.write_all("Ошибка шифрования сообщения. Попробуйте снова.\n".as_bytes()).await?;
                                    writer_guard.flush().await?;
                                    drop(writer_guard);
                                }
                            }
                        }
                        ClientState::PublicChat => {
                            if let Some(idx) = msg_trimmed.find(':') {
                                let recipient = msg_trimmed[..idx].trim().to_string();
                                let message_content = msg_trimmed[idx + 1..].trim().to_string();

                                if recipient == nickname_read {
                                     let mut writer_guard = writer_arc_clone.lock().await;
                                     writer_guard.write_all("Вы не можете отправить ЛС самому себе.\n".as_bytes()).await?;
                                     writer_guard.flush().await?;
                                     drop(writer_guard);
                                     log_message("Message", &format!("'{}' пытался отправить ЛС самому себе.", nickname_read), Color::Red).await?;
                                } else {
                                    let full_msg = format!("{} {}: {}\n", colored::Colorize::cyan("Вам"), nickname_read, message_content);
                                    if send_to_user(&connected_users_read, &recipient, full_msg).await.is_ok() {
                                        log_message("Message", &format!("'{}' отправил прямое сообщение '{}'", nickname_read, recipient), Color::Green).await?;
                                    } else {
                                        let mut writer_guard = writer_arc_clone.lock().await;
                                        writer_guard.write_all(format!("{} Пользователь '{}' не найден или не в сети.\n", colored::Colorize::red("Ошибка:"), recipient).as_bytes()).await?;
                                        writer_guard.flush().await?;
                                        drop(writer_guard);
                                        log_message("Message", &format!("'{}' не смог отправить прямое сообщение оффлайн пользователю '{}'", nickname_read, recipient), Color::Red).await?;
                                    }
                                }
                            } else {
                                broadcast_message(&connected_users_read, &nickname_read, msg_trimmed, false).await;
                            }
                        }
                        ClientState::WaitingForPrivateChatResponse { target_nick, sent_key: _ } => {
                            let mut writer_guard = writer_arc_clone.lock().await;
                            writer_guard.write_all(format!("Вы ожидаете ответа от '{}'. Чтобы отправить сообщение в общий чат, сначала отмените запрос (пока не реализовано) или дождитесь ответа.\n", target_nick).as_bytes()).await?;
                            writer_guard.flush().await?;
                            drop(writer_guard);
                            log_message("Client state", &format!("'{}' пытался отправить сообщение в состоянии WaitingForPrivateChatResponse.", nickname_read), Color::Yellow).await?;
                        }
                        ClientState::HasPendingPrivateChatRequest { from_nick, shared_key: _ } => {
                            let mut writer_guard = writer_arc_clone.lock().await;
                            writer_guard.write_all(format!("У вас есть запрос на личный чат от '{}'. Введите /accept или /reject.\n", from_nick).as_bytes()).await?;
                            writer_guard.flush().await?;
                            drop(writer_guard);
                            log_message("Client state", &format!("'{}' пытался отправить сообщение в состоянии HasPendingPrivateChatRequest.", nickname_read), Color::Yellow).await?;
                        }
                    }
                }
            };
            res
        }
    });

    let write_task = tokio::spawn({
        let writer_arc_for_task = writer_arc.clone();
        let client_state_write = client_state.clone();
        let connected_users_write = connected_users.clone();
        let nickname_write = nickname.clone();
        let mut rx_from_others = rx_from_others;

        async move {
            let res: Result<(), Box<dyn Error + Send + Sync>> = loop {
                let msg_str = match rx_from_others.recv().await {
                    Some(msg) => {
                        log_message("Recieve", &format!("Получено write_task ({}): {}", nickname_write, msg.trim()), Color::Yellow).await?;
                        msg
                    },
                    None => {
                        log_message("Client", &format!("{}: Канал rx_from_others закрыт (write_task завершается).", nickname_write), Color::Cyan).await?;
                        break Ok(());
                    },
                };

                if msg_str.starts_with("SYSTEM:") {
                    let parts: Vec<&str> = msg_str.splitn(2, ':').collect();
                    if parts.len() < 2 {
                        log_message("Error", &format!("Некорректное системное сообщение: {}", msg_str), Color::Red).await?;
                        continue;
                    }

                    let command_and_args = parts[1];
                    let mut command_parts = command_and_args.splitn(2, ':');
                    let command = command_parts.next().unwrap_or("");
                    let args = command_parts.next().unwrap_or("");

                    match command {
                        "PRIVATE_CHAT_REQUEST" => {
                            let request_args: Vec<&str> = args.splitn(2, ':').collect();
                            if request_args.len() == 2 {
                                let sender_nick = request_args[0].to_string();
                                let key_hex = request_args[1];
                                match hex::decode(key_hex) {
                                    Ok(shared_key) => {
                                        let mut state_guard = client_state_write.lock().await;
                                        match &mut *state_guard {
                                            ClientState::PublicChat => {
                                                *state_guard = ClientState::HasPendingPrivateChatRequest { from_nick: sender_nick.clone(), shared_key };
                                                drop(state_guard);
                                                let mut writer_guard = writer_arc_for_task.lock().await;
                                                if writer_guard.write_all(format!("Пользователь '{}' хочет начать с вами личный чат. Введите /accept или /reject.\n", sender_nick).as_bytes()).await.is_err() { break Ok(()); }
                                                writer_guard.flush().await?;
                                                drop(writer_guard);
                                                log_message("Private chat", &format!("'{}' получил запрос на приватный чат от '{}'", nickname_write, sender_nick), Color::Cyan).await?;
                                            }
                                            _ => {
                                                drop(state_guard);
                                                let _ = send_to_user(&connected_users_write, &sender_nick, format!("SYSTEM:PRIVATE_CHAT_BUSY:{}", nickname_write)).await;
                                                log_message("Private chat", &format!("'{}' получил запрос на приватный чат от '{}', но был занят.", nickname_write, sender_nick), Color::Yellow).await?;
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        let mut writer_guard = writer_arc_for_task.lock().await;
                                        if writer_guard.write_all("Получен некорректный запрос на приватный чат (ошибка ключа).\n".as_bytes()).await.is_err() { break Ok(()); }
                                        writer_guard.flush().await?;
                                        drop(writer_guard);
                                        log_message("Error", &format!("Неверный формат ключа в PRIVATE_CHAT_REQUEST от {}", sender_nick), Color::Red).await?;
                                    }
                                }
                            } else {
                                let mut writer_guard = writer_arc_for_task.lock().await;
                                if writer_guard.write_all("Получен некорректный запрос на приватный чат.\n".as_bytes()).await.is_err() { break Ok(()); }
                                writer_guard.flush().await?;
                                drop(writer_guard);
                                log_message("Error", &format!("Некорректный формат PRIVATE_CHAT_REQUEST: {}", msg_str), Color::Red).await?;
                            }
                        }
                        "PRIVATE_CHAT_ACCEPTED" => {
                            let originator_nick = args.to_string();
                            let mut state_guard = client_state_write.lock().await;
                            match &mut *state_guard {
                                ClientState::WaitingForPrivateChatResponse { target_nick, sent_key } if target_nick == &originator_nick => {
                                    *state_guard = ClientState::InPrivateChat { with_nick: originator_nick.clone(), shared_key: sent_key.clone() };
                                    drop(state_guard);
                                    let mut writer_guard = writer_arc_for_task.lock().await;
                                    if writer_guard.write_all(format!("{} Пользователь '{}' принял ваш запрос на личный чат. Вы теперь в приватном чате.\n", colored::Colorize::green("ИНФО:"), originator_nick).as_bytes()).await.is_err() { break Ok(()); }
                                    writer_guard.flush().await?;
                                    drop(writer_guard);
                                    log_message("Private chat", &format!("'{}' обновил статус: приватный чат с '{}'", nickname_write, originator_nick), Color::Cyan).await?;
                                }
                                _ => {
                                    drop(state_guard);
                                    log_message("Error", &format!("Undefined chat accept от {} для {}", originator_nick, nickname_write), Color::Red).await?;
                                    let mut writer_guard = writer_arc_for_task.lock().await;
                                    if writer_guard.write_all(format!("Пользователь '{}' принял ваш запрос, но вы не находитесь в ожидающем состоянии. Возможно, чат уже начат или отменен.\n", originator_nick).as_bytes()).await.is_err() { break Ok(()); }
                                    writer_guard.flush().await?;
                                    drop(writer_guard);
                                }
                            }
                        }
                        "PRIVATE_CHAT_REJECTED" => {
                            let originator_nick = args.to_string();
                            let mut state_guard = client_state_write.lock().await;
                            match &mut *state_guard {
                                ClientState::WaitingForPrivateChatResponse { target_nick, sent_key: _ } if target_nick == &originator_nick => {
                                    *state_guard = ClientState::PublicChat;
                                    drop(state_guard);
                                    let mut writer_guard = writer_arc_for_task.lock().await;
                                    if writer_guard.write_all(format!("{} Пользователь '{}' отклонил ваш запрос на личный чат. Вы возвращены в общий чат.\n", colored::Colorize::green("ИНФО:"), originator_nick).as_bytes()).await.is_err() { break Ok(()); }
                                    writer_guard.flush().await?;
                                    drop(writer_guard);
                                    log_message("Private chat", &format!("'{}' отклонил приватный чат от '{}'", originator_nick, nickname_write), Color::Cyan).await?;
                                }
                                _ => {
                                    drop(state_guard);
                                    log_message("Error", &format!("Undefined chat reject от {} для {}", originator_nick, nickname_write), Color::Red).await?;
                                    let mut writer_guard = writer_arc_for_task.lock().await;
                                    if writer_guard.write_all(format!("Пользователь '{}' отклонил ваш запрос, но вы не находитесь в ожидающем состоянии. Возможно, чат уже начат или отменен.\n", originator_nick).as_bytes()).await.is_err() { break Ok(()); }
                                    writer_guard.flush().await?;
                                    drop(writer_guard);
                                }
                            }
                        }
                        "PRIVATE_CHAT_ENDED" => {
                            let originator_nick = args.to_string();
                            let mut state_guard = client_state_write.lock().await;
                            match &mut *state_guard {
                                ClientState::InPrivateChat { with_nick, shared_key: _ } if with_nick == &originator_nick => {
                                    *state_guard = ClientState::PublicChat;
                                    drop(state_guard);
                                    let mut writer_guard = writer_arc_for_task.lock().await;
                                    if writer_guard.write_all(format!("{} Пользователь '{}' вышел из личного чата. Вы возвращены в общий чат.\n", colored::Colorize::green("ИНФО:"), originator_nick).as_bytes()).await.is_err() { break Ok(()); }
                                    writer_guard.flush().await?;
                                    drop(writer_guard);
                                    log_message("Private chat", &format!("'{}' вышел из приватного чата с '{}'", originator_nick, nickname_write), Color::Cyan).await?;
                                }
                                _ => {
                                    drop(state_guard);
                                    log_message("Error", &format!("Undefined chat end от {} для {}", originator_nick, nickname_write), Color::Red).await?;
                                }
                            }
                        }
                        "PRIVATE_CHAT_BUSY" => {
                            let originator_nick = args.to_string();
                            let mut state_guard = client_state_write.lock().await;
                            match &mut *state_guard {
                                ClientState::WaitingForPrivateChatResponse { target_nick, sent_key: _ } if target_nick == &originator_nick => {
                                    *state_guard = ClientState::PublicChat;
                                    drop(state_guard);
                                    let mut writer_guard = writer_arc_for_task.lock().await;
                                    if writer_guard.write_all(format!("{} Пользователь '{}' занят или уже в другом приватном чате. Вы возвращены в общий чат.\n", colored::Colorize::green("ИНФО:"), originator_nick).as_bytes()).await.is_err() { break Ok(()); }
                                    writer_guard.flush().await?;
                                    drop(writer_guard);
                                    log_message("Private chat", &format!("'{}' занят для приватного чата с '{}'", originator_nick, nickname_write), Color::Cyan).await?;
                                }
                                _ => {
                                    drop(state_guard);
                                    log_message("Error", &format!("Undefined chat busy от {} для {}", originator_nick, nickname_write), Color::Red).await?;
                                }
                            }
                        }
                        "ENCRYPTED_PRIVATE_MSG" => {
                            let msg_parts: Vec<&str> = args.splitn(3, ':').collect();
                            if msg_parts.len() == 3 {
                                let sender_nick = msg_parts[0];
                                let nonce_hex = msg_parts[1];
                                let ciphertext_hex = msg_parts[2];

                                let mut state_guard = client_state_write.lock().await;
                                match &mut *state_guard {
                                    ClientState::InPrivateChat { with_nick, shared_key } if with_nick == sender_nick => {
                                        let shared_key_clone = shared_key.clone();
                                        drop(state_guard);

                                        match hex::decode(nonce_hex) {
                                            Ok(nonce_bytes) if nonce_bytes.len() == 12 => {
                                                match hex::decode(ciphertext_hex) {
                                                    Ok(ciphertext_bytes) => {
                                                        let cipher = Aes256Gcm::new_from_slice(&shared_key_clone).expect("Key length is 32 bytes");
                                                        let nonce = Nonce::from_slice(&nonce_bytes);
                                                        match cipher.decrypt(nonce, ciphertext_bytes.as_ref()) {
                                                            Ok(plaintext_bytes) => {
                                                                if let Ok(plaintext_msg) = String::from_utf8(plaintext_bytes) {
                                                                    let mut writer_guard = writer_arc_for_task.lock().await;
                                                                    if writer_guard.write_all(format!("[ЛС от {}]: {}\n", colored::Colorize::cyan(sender_nick), plaintext_msg).as_bytes()).await.is_err() { break Ok(()); }
                                                                    writer_guard.flush().await?;
                                                                    drop(writer_guard);
                                                                    log_message("Private", &format!("'{}' получил зашифрованное ЛС от '{}'", nickname_write, sender_nick), Color::Cyan).await?;
                                                                } else {
                                                                    let mut writer_guard = writer_arc_for_task.lock().await;
                                                                    writer_guard.write_all("Получено некорректное UTF-8 сообщение (дешифровка).\n".as_bytes()).await?;
                                                                    writer_guard.flush().await?;
                                                                    drop(writer_guard);
                                                                    log_message("Error", &format!("Ошибка декодирования UTF-8 для {}: {}", nickname_write, sender_nick), Color::Red).await?;
                                                                }
                                                            },
                                                            Err(e) => {
                                                                let mut writer_guard = writer_arc_for_task.lock().await;
                                                                writer_guard.write_all("Ошибка дешифрования сообщения. Возможно, ключ неверный.\n".as_bytes()).await?;
                                                                writer_guard.flush().await?;
                                                                drop(writer_guard);
                                                                log_message("Error", &format!("Ошибка дешифрования для {}: {:?}", nickname_write, e), Color::Red).await?;
                                                            }
                                                        }
                                                    },
                                                    Err(e) => {
                                                        let mut writer_guard = writer_arc_for_task.lock().await;
                                                        writer_guard.write_all("Получено некорректное зашифрованное сообщение (ошибка hex-декодирования).\n".as_bytes()).await?;
                                                        writer_guard.flush().await?;
                                                        drop(writer_guard);
                                                        log_message("Error", &format!("Ошибка декодирования hex для ciphertext: {:?}", e), Color::Red).await?;
                                                    }
                                                }
                                            },
                                            _ => {
                                                let mut writer_guard = writer_arc_for_task.lock().await;
                                                writer_guard.write_all("Получено некорректное зашифрованное сообщение (ошибка hex-декодирования nonce или неверная длина).\n".as_bytes()).await?;
                                                writer_guard.flush().await?;
                                                drop(writer_guard);
                                                log_message("Error", &format!("Ошибка декодирования hex для nonce или неверная длина: {:?}", nonce_hex), Color::Red).await?;
                                            }
                                        }
                                    },
                                    _ => {
                                        drop(state_guard);
                                        let mut writer_guard = writer_arc_for_task.lock().await;
                                        writer_guard.write_all(format!("Получено зашифрованное сообщение от '{}', но вы не находитесь в приватном чате с ним.\n", sender_nick).as_bytes()).await?;
                                        writer_guard.flush().await?;
                                        drop(writer_guard);
                                        log_message("Error", &format!("Получено ENCRYPTED_PRIVATE_MSG от {} для {} в некорректном состоянии.", sender_nick, nickname_write), Color::Red).await?;
                                    }
                                }
                            } else {
                                let mut writer_guard = writer_arc_for_task.lock().await;
                                if writer_guard.write_all("Получено некорректное зашифрованное сообщение.\n".as_bytes()).await.is_err() { break Ok(()); }
                                writer_guard.flush().await?;
                                drop(writer_guard);
                                log_message("Error", &format!("Некорректный формат ENCRYPTED_PRIVATE_MSG: {}", msg_str), Color::Red).await?;
                            }
                        }
                        _ => { log_message("Error", &format!("Неизвестная системная команда: {}", command), Color::Red).await?; }
                    }
                } else {
                    let display_message;
                    {
                        let state_guard = client_state_write.lock().await;
                        display_message = match &*state_guard {
                            ClientState::InPrivateChat {..} => !msg_str.starts_with(&format!("{} ", colored::Colorize::blue("Всем"))),
                            _ => true,
                        };
                    }

                    if display_message {
                        let mut writer_guard = writer_arc_for_task.lock().await;
                        if writer_guard.write_all(msg_str.as_bytes()).await.is_err() { break Ok(()); }
                        writer_guard.flush().await?;
                        drop(writer_guard);
                    }
                }
            };
            res
        }
    });

    tokio::select! {
        res = read_task => {
            if let Err(e) = res { log_message("SYSTEM", &format!("Ошибка в задаче чтения для {}: {:?}", nickname, e), Color::Magenta).await?; }
            log_message("Info", &format!("{}: read_task завершилась в select.", nickname), Color::Cyan).await?;
        },
        res = write_task => {
            if let Err(e) = res { log_message("SYSTEM", &format!("Ошибка в задаче записи для {}: {:?}", nickname, e), Color::Magenta).await?; }
            log_message("Info", &format!("{}: write_task завершилась в select.", nickname), Color::Cyan).await?;
        },
    }

    let final_client_state = client_state.lock().await.clone();
    {
        let mut users_guard = connected_users.lock().await;
        users_guard.remove(&nickname);
        log_message("Client", &format!("Пользователь '{}' отключился. В сети: {}", nickname, users_guard.len()), Color::Yellow).await?;
    }

    if let ClientState::InPrivateChat { with_nick, shared_key: _ } = final_client_state {
        let _ = send_to_user(&connected_users, &with_nick, format!("SYSTEM:PRIVATE_CHAT_ENDED:{}", nickname)).await;
        log_message("Info", &format!("Уведомлен '{}' о выходе '{}' из их приватного чата", with_nick, nickname), Color::Cyan).await?;
    }

    let leave_msg = format!("Пользователь '{}' вышел из чата", nickname);
    broadcast_message(&connected_users, &nickname, &leave_msg, true).await;
    Ok(())
}
