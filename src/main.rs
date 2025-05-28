use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use std::collections::HashMap;
use std::sync::Arc;
use colored::*;
use tokio::fs::{OpenOptions as TokioOpenOptions, File as TokioFile};
use std::path::Path;
use std::error::Error;

type Tx = mpsc::UnboundedSender<String>;

#[derive(Debug, Clone)]
enum ClientState {
    PublicChat,
    WaitingForPrivateChatResponse { target_nick: String },
    HasPendingPrivateChatRequest { from_nick: String },
    InPrivateChat { with_nick: String },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    #[cfg(windows)]
    {
        use std::process::Command;
        let _ = Command::new("cmd")
            .args(&["/C", "chcp 65001"])
            .status();
    }

    let users_db = Arc::new(Mutex::new(load_users("users.txt").await?));
    let connected_users: Arc<Mutex<HashMap<String, Tx>>> = Arc::new(Mutex::new(HashMap::new()));

    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    println!("{}", "Сервер запущен на 0.0.0.0:8080".green());

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("{} {}", "Новое подключение:".yellow(), addr);

        let users_db = users_db.clone();
        let connected_users = connected_users.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_client(socket, users_db, connected_users).await {
                eprintln!("{} {}: {:?}", "Ошибка с клиентом".red(), addr, e);
            }
            println!("{} {}", "Клиент отключился:".yellow(), addr);
        });
    }
}

// Загрузка пользователей в HashMap
async fn load_users(path: &str) -> Result<HashMap<String, String>, Box<dyn Error + Send + Sync>> {
    let mut users = HashMap::new();
    let path_obj = Path::new(path);

    // Если файла нет, то создаём пустой
    if !path_obj.exists() {
        TokioFile::create(path).await?;
        println!("{} {}", "Создан пустой файл пользователей:".blue(), path);
        return Ok(users);
    }

    // Читаем построчно
    let file = TokioFile::open(path).await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let parts: Vec<&str> = line.trim().splitn(2, ':').collect();
        if parts.len() == 2 {
            users.insert(parts[0].to_string(), parts[1].to_string());
        } else if !line.trim().is_empty() {
            eprintln!("{} Неверный формат строки в users.txt: {}", "ВНИМАНИЕ:".red(), line);
        }
    }
    println!("{} {} пользователей загружено из {}", "Загружено".green(), users.len(), path);
    Ok(users)
}

// добавление нового пользователя при регистрации
async fn add_user_to_file(path: &str, username: &str, password: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut file = TokioOpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .await?;
    file.write_all(format!("{}:{}\n", username, password).as_bytes()).await?;
    file.flush().await?;
    Ok(())
}

// Модифицируем broadcast_message для добавления флага системного сообщения
// и чтобы не отправлять широковещательные сообщения тем, кто в приватном чате
async fn broadcast_message(
    connected_users: &Arc<Mutex<HashMap<String, Tx>>>,
    sender: &str,
    message: &str,
    is_system_message: bool, // true для сообщений о входе/выходе
) {
    let users = connected_users.lock().await;
    for (nick, tx) in users.iter() {
        if nick != sender { // Не отправляем отправителю
            let full_msg = if is_system_message {
                format!("{}\n", message) // Системные сообщения как есть (уже отформатированы)
            } else {
                format!("{} {}: {}\n", "Всем".blue(), sender, message)
            };
            // Прямая отправка. Фильтрация (показывать или нет) будет на стороне получателя в write_task
            // на основе его client_state.
            let _ = tx.send(full_msg);
        }
    }
}


async fn send_to_user(
    connected_users: &Arc<Mutex<HashMap<String, Tx>>>,
    recipient_nick: &str,
    message: String,
) -> Result<(), String> {
    let users = connected_users.lock().await;
    if let Some(tx) = users.get(recipient_nick) {
        if tx.send(message).is_err() {
            // Получатель отсоединился
            Err(format!("Не удалось отправить сообщение пользователю {}", recipient_nick))
        } else {
            Ok(())
        }
    } else {
        Err(format!("Пользователь {} не найден или не в сети.", recipient_nick))
    }
}


async fn handle_client(
    socket: TcpStream,
    users_db: Arc<Mutex<HashMap<String, String>>>,
    connected_users: Arc<Mutex<HashMap<String, Tx>>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (reader_half, writer_half) = socket.into_split();
    let mut reader = BufReader::new(reader_half);
    let mut writer = writer_half; // Не оборачиваем в Mutex сразу, т.к. writer_arc будет для задач

    writer.write_all("Добро пожаловать в чат! Введите /help для списка команд.\n".as_bytes()).await?;
    writer.flush().await?;

    let nickname: String;

    // авторизация
    let mut attempts = 3;
    loop {
        if attempts == 0 {
            writer.write_all("Превышено количество попыток. Отключение.\n".as_bytes()).await?;
            writer.flush().await?;
            return Err("Неудачная авторизация".into());
        }

        writer.write_all("Введите никнейм:\n".as_bytes()).await?;
        writer.flush().await?;
        let mut nick_input = String::new();
        if reader.read_line(&mut nick_input).await? == 0 { return Err("Клиент отключился до авторизации".into()); }
        let nick_input = nick_input.trim().to_string();

        writer.write_all("Введите пароль:\n".as_bytes()).await?;
        writer.flush().await?;
        let mut pass_input = String::new();
        if reader.read_line(&mut pass_input).await? == 0 { return Err("Клиент отключился до авторизации".into()); }
        let pass_input = pass_input.trim().to_string();

        let mut db_guard = users_db.lock().await;
        match db_guard.get(&nick_input) {
            Some(stored_pass) if *stored_pass == pass_input => {
                nickname = nick_input;
                writer.write_all("Авторизация успешна!\n".as_bytes()).await?;
                writer.flush().await?;
                println!("{}", format!("Пользователь '{}' авторизовался", nickname).green());
                break;
            }
            None => {
                writer.write_all("Пользователь не найден. Хотите зарегистрироваться? (да/нет):\n".as_bytes()).await?;
                writer.flush().await?;
                let mut answer = String::new();
                if reader.read_line(&mut answer).await? == 0 { return Err("Клиент отключился во время регистрации".into()); }
                let answer = answer.trim().to_lowercase();
                if answer == "да" || answer == "yes" {
                    db_guard.insert(nick_input.clone(), pass_input.clone());
                    let nick_clone_for_file = nick_input.clone();
                    let pass_clone_for_file = pass_input.clone();
                    drop(db_guard); // Освобождаем мьютекс перед асинхронной операцией
                    add_user_to_file("users.txt", &nick_clone_for_file, &pass_clone_for_file).await?;
                    nickname = nick_clone_for_file;
                    writer.write_all("Регистрация успешна! Вы авторизованы.\n".as_bytes()).await?;
                    writer.flush().await?;
                    println!("{}", format!("Пользователь '{}' зарегистрировался", nickname).green());
                    break;
                } else {
                    writer.write_all("Попробуйте снова.\n".as_bytes()).await?;
                    writer.flush().await?;
                    attempts -= 1;
                }
            }
            Some(_) => {
                writer.write_all("Неверный пароль. Попробуйте снова.\n".as_bytes()).await?;
                writer.flush().await?;
                attempts -= 1;
            }
        }
    } 

    // Проверка, если никнейм уже в сети
    {
        let users_guard = connected_users.lock().await;
        if users_guard.contains_key(&nickname) {
            writer.write_all("Пользователь с таким ником уже в сети. Отключение.\n".as_bytes()).await?;
            writer.flush().await?;
            return Err("Дубликат никнейма".into());
        }
    }

    // вывод списка онлайн-пользователей
    {
        let users_guard = connected_users.lock().await;
        let connected_list: Vec<String> = users_guard.keys()
            .filter(|name| *name != &nickname)
            .cloned()
            .collect();
        if connected_list.is_empty() {
            writer.write_all("Пока никто больше не подключён.\n".as_bytes()).await?;
        } else {
            writer.write_all(format!("Сейчас в сети: {}\n", connected_list.join(", ")).as_bytes()).await?;
        }
        writer.flush().await?;
    }


    let (tx_to_client, mut rx_from_others) = mpsc::unbounded_channel::<String>();
    {
        let mut users_guard = connected_users.lock().await;
        users_guard.insert(nickname.clone(), tx_to_client);
    }

    let join_msg = format!("Пользователь '{}' вошёл в чат", nickname);
    println!("{}", join_msg.yellow()); //уведомление на сервере, потом сделаем логи
    broadcast_message(&connected_users, &nickname, &join_msg, true).await;

    let client_state = Arc::new(Mutex::new(ClientState::PublicChat));
    let writer_arc = Arc::new(Mutex::new(writer));

    // tokio задача чтения сообщения
    let read_task = {
        let writer_arc_clone = writer_arc.clone();
        let connected_users_read = connected_users.clone();
        let nickname_read = nickname.clone();
        let client_state_read = client_state.clone();

        tokio::spawn(async move {
            let mut line = String::new();
            loop {
                line.clear();
                let _bytes_read = match reader.read_line(&mut line).await {
                    Ok(0) => break, // клиент отключился
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("{} Ошибка чтения от {}: {}", "ОШИБКА:".red(), nickname_read, e);
                        break;
                    }
                };

                let msg_trimmed = line.trim();
                if msg_trimmed.is_empty() { continue; }

                let mut current_writer_guard = writer_arc_clone.lock().await;
                let mut state_guard = client_state_read.lock().await;

                // проверка на команду "выход" из приватного чата
                if msg_trimmed.to_lowercase() == "выход" {
                    if let ClientState::InPrivateChat { with_nick } = &*state_guard {
                        let partner_nick = with_nick.clone();
                        // уведомить партнера
                        let _ = send_to_user(
                            &connected_users_read,
                            &partner_nick,
                            format!("SYSTEM:PRIVATE_CHAT_ENDED:{}", nickname_read)
                        ).await;
                        // уведомление в собственный чат
                        current_writer_guard.write_all("Вы вышли из личного чата. Возвращение в общий чат.\n".as_bytes()).await?;
                        current_writer_guard.flush().await?;
                        *state_guard = ClientState::PublicChat;
                        println!("{} '{}' вышел из приватного чата с '{}'", "ИНФО:".cyan(), nickname_read, partner_nick);
                        continue;
                    }
                }


                // Обработка команд /help, /list, /pm, /accept, /reject
                if msg_trimmed.starts_with('/') {
                    let mut parts = msg_trimmed[1..].splitn(2, ' ');
                    let command = parts.next().unwrap_or("").to_lowercase();
                    let args = parts.next().unwrap_or("").trim();

                    match command.as_str() {
                        "help" => {
                            current_writer_guard.write_all(
                                "Доступные команды:\n\
                                 /help - Показать это сообщение\n\
                                 /list - Показать список подключённых пользователей\n\
                                 /pm <ник> - Предложить личный чат пользователю <ник>\n\
                                 /accept - Принять запрос на личный чат\n\
                                 /reject - Отклонить запрос на личный чат\n\
                                 получатель: сообщение - Отправить старое личное сообщение (не рекомендуется)\n\
                                 'выход' - (в приватном чате) Выйти из приватного чата\n\
                                 любое_сообщение - Отправить сообщение всем в публичный чат\n"
                                .as_bytes()
                            ).await?;
                        }
                        "list" => {
                            let users = connected_users_read.lock().await;
                            let connected_list: Vec<String> = users.keys()
                                .filter(|name| *name != &nickname_read)
                                .cloned()
                                .collect();
                            if connected_list.is_empty() {
                                current_writer_guard.write_all("Пока никто больше не подключён.\n".as_bytes()).await?;
                            } else {
                                current_writer_guard.write_all(format!("Сейчас в сети: {}\n", connected_list.join(", ")).as_bytes()).await?;
                            }
                        }
                        "pm" => {
                            if args.is_empty() {
                                current_writer_guard.write_all("Укажите ник пользователя для личного чата: /pm <ник>\n".as_bytes()).await?;
                            } else if args == nickname_read {
                                current_writer_guard.write_all("Вы не можете начать личный чат с самим собой.\n".as_bytes()).await?;
                            }
                            else {
                                match &*state_guard {
                                    ClientState::PublicChat => {
                                        let target_nick = args.to_string();
                                        if send_to_user(&connected_users_read, &target_nick, format!("SYSTEM:PRIVATE_CHAT_REQUEST:{}", nickname_read)).await.is_ok() {
                                            current_writer_guard.write_all(format!("Запрос на личный чат отправлен пользователю '{}'. Ожидание ответа...\n", target_nick).as_bytes()).await?;
                                            *state_guard = ClientState::WaitingForPrivateChatResponse { target_nick: target_nick.clone() };
                                            println!("{} '{}' запросил приватный чат у '{}'", "ИНФО:".cyan(), nickname_read, target_nick);
                                        } else {
                                            current_writer_guard.write_all(format!("Пользователь '{}' не найден или не в сети.\n", target_nick).as_bytes()).await?;
                                        }
                                    }
                                    _ => {
                                        current_writer_guard.write_all("Вы не можете начать новый личный чат, находясь не в общем чате.\n".as_bytes()).await?;
                                    }
                                }
                            }
                        }
                        "accept" => {
                            if let ClientState::HasPendingPrivateChatRequest { from_nick } = &*state_guard {
                                let partner_nick = from_nick.clone();
                                if send_to_user(&connected_users_read, &partner_nick, format!("SYSTEM:PRIVATE_CHAT_ACCEPTED:{}", nickname_read)).await.is_ok() {
                                    current_writer_guard.write_all(format!("Вы начали личный чат с '{}'. Напишите 'выход' для возврата в общий чат.\n", partner_nick).as_bytes()).await?;
                                    *state_guard = ClientState::InPrivateChat { with_nick: partner_nick.clone() };
                                     println!("{} '{}' принял приватный чат от '{}'", "ИНФО:".cyan(), nickname_read, partner_nick);
                                } else {
                                     current_writer_guard.write_all(format!("Не удалось уведомить '{}', возможно, он отключился.\n", partner_nick).as_bytes()).await?;
                                     *state_guard = ClientState::PublicChat; // возврат в общий чат
                                }
                            } else {
                                current_writer_guard.write_all("Нет активных запросов на личный чат для принятия.\n".as_bytes()).await?;
                            }
                        }
                        "reject" => {
                             if let ClientState::HasPendingPrivateChatRequest { from_nick } = &*state_guard {
                                let partner_nick = from_nick.clone();
                                if send_to_user(&connected_users_read, &partner_nick, format!("SYSTEM:PRIVATE_CHAT_REJECTED:{}", nickname_read)).await.is_ok() {
                                     current_writer_guard.write_all(format!("Вы отклонили запрос на личный чат от '{}'.\n", partner_nick).as_bytes()).await?;
                                     println!("{} '{}' отклонил приватный чат от '{}'", "ИНФО:".cyan(), nickname_read, partner_nick);
                                } else {
                                     current_writer_guard.write_all(format!("Не удалось уведомить '{}' об отклонении, возможно, он отключился.\n", partner_nick).as_bytes()).await?;
                                }
                                *state_guard = ClientState::PublicChat;
                            } else {
                                current_writer_guard.write_all("Нет активных запросов на личный чат для отклонения.\n".as_bytes()).await?;
                            }
                        }
                        _ => {
                            current_writer_guard.write_all(format!("Неизвестная команда: '{}'. Введите /help.\n", command).as_bytes()).await?;
                        }
                    }
                    current_writer_guard.flush().await?;
                }
                // обработка обычных сообщений или старых личных сообщений
                else {
                    match &*state_guard {
                        ClientState::InPrivateChat { with_nick } => {
                            let private_msg_to_partner = format!("[ЛС от {}]: {}\n", nickname_read, msg_trimmed);
                            let private_msg_echo = format!("[ЛС для {}]: {}\n", with_nick, msg_trimmed);

                            if send_to_user(&connected_users_read, with_nick, private_msg_to_partner).await.is_ok() {
                                current_writer_guard.write_all(private_msg_echo.as_bytes()).await?;
                            } else {
                                current_writer_guard.write_all(format!("Не удалось отправить сообщение '{}'. Возможно, пользователь. Вы возвращены в общий чат.\n", with_nick).as_bytes()).await?;
                                *state_guard = ClientState::PublicChat; // возврат в общий чат
                            }
                            current_writer_guard.flush().await?;
                        }
                        ClientState::PublicChat => {
                            // старый формат ЛС или публичное сообщение
                            if let Some(idx) = msg_trimmed.find(':') {
                                let recipient = msg_trimmed[..idx].trim();
                                let message_content = msg_trimmed[idx + 1..].trim();
                                if recipient == nickname_read {
                                     current_writer_guard.write_all("Вы не можете отправить ЛС самому себе.\n".as_bytes()).await?;
                                } else {
                                    let full_msg = format!("{} {}: {}\n", "Вам".cyan(), nickname_read, message_content);
                                    if send_to_user(&connected_users_read, recipient, full_msg).await.is_ok() {
                                        current_writer_guard.write_all(format!("[ЛС для {}]: {}\n", recipient, message_content).as_bytes()).await?;
                                    } else {
                                        current_writer_guard.write_all(format!("{} Пользователь '{}' не найден или не в сети.\n", "Ошибка:".red(), recipient).as_bytes()).await?;
                                    }
                                }
                                current_writer_guard.flush().await?;
                            } else {
                                // публичное сообщение
                                broadcast_message(&connected_users_read, &nickname_read, msg_trimmed, false).await;
                            }
                        }
                        ClientState::WaitingForPrivateChatResponse { target_nick } => {
                            current_writer_guard.write_all(format!("Вы ожидаете ответа от '{}'. Чтобы отправить сообщение в общий чат, сначала отмените запрос (пока не реализовано) или дождитесь ответа.\n", target_nick).as_bytes()).await?;
                            current_writer_guard.flush().await?;
                        }
                        ClientState::HasPendingPrivateChatRequest { from_nick } => {
                            current_writer_guard.write_all(format!("У вас есть запрос на личный чат от '{}'. Введите /accept или /reject.\n", from_nick).as_bytes()).await?;
                            current_writer_guard.flush().await?;
                        }
                    }
                }
            } // конец loop read_line
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        })
    };


    let write_task = {
    // клонируем Arc для передачи во владении задаче
    let writer_arc_for_task = writer_arc.clone();
    let client_state_write = client_state.clone();
    let connected_users_write = connected_users.clone();
    let nickname_write = nickname.clone();

    tokio::spawn(async move { // writer_arc_for_task, client_state_write и прочее перемещаются сюда
        while let Some(msg_str) = rx_from_others.recv().await {
            // блокируем мьютекс внутри цикла для каждого сообщения
            let mut writer_guard = writer_arc_for_task.lock().await;
            let mut state_guard = client_state_write.lock().await;

            if msg_str.starts_with("SYSTEM:") {
                let parts: Vec<&str> = msg_str.splitn(3, ':').collect();
                if parts.len() < 3 {
                    eprintln!("{} Некорректное системное сообщение: {}", "ОШИБКА СЕРВЕРА:".red(), msg_str);
                    continue;
                }

                let command = parts[1];
                let originator_nick = parts[2].to_string();

                match command {
                    "PRIVATE_CHAT_REQUEST" => {
                        match &*state_guard {
                            ClientState::PublicChat => {
                                *state_guard = ClientState::HasPendingPrivateChatRequest { from_nick: originator_nick.clone() };
                                if writer_guard.write_all(format!("Пользователь '{}' хочет начать с вами личный чат. Введите /accept или /reject.\n", originator_nick).as_bytes()).await.is_err() { break; }
                                println!("{} '{}' получил запрос на приватный чат от '{}'", "ИНФО:".cyan(), nickname_write, originator_nick);
                            }
                            _ => {
                                // не используем writer_guard здесь, так как отправляем другому пользователю
                                drop(writer_guard); // освобождаем guard перед .await на send_to_user
                                let _ = send_to_user(&connected_users_write, &originator_nick, format!("SYSTEM:PRIVATE_CHAT_BUSY:{}", nickname_write)).await;
                                continue; // пропускаем flush для writer_guard в этой итерации
                            }
                        }
                    }
                    "PRIVATE_CHAT_ACCEPTED" => {
                        if let ClientState::WaitingForPrivateChatResponse { target_nick } = &*state_guard {
                            if target_nick == &originator_nick {
                                *state_guard = ClientState::InPrivateChat { with_nick: originator_nick.clone() };
                                if writer_guard.write_all(format!("Пользователь '{}' принял ваш запрос. Вы теперь в личном чате. Напишите 'выход' для возврата.\n", originator_nick).as_bytes()).await.is_err() { break; }
                                println!("{} '{}' начал приватный чат с '{}'", "ИНФО:".cyan(), nickname_write, originator_nick);
                            }
                        }
                    }
                    "PRIVATE_CHAT_REJECTED" => {
                         if let ClientState::WaitingForPrivateChatResponse { target_nick } = &*state_guard {
                            if target_nick == &originator_nick {
                                *state_guard = ClientState::PublicChat;
                                if writer_guard.write_all(format!("Пользователь '{}' отклонил ваш запрос на личный чат.\n", originator_nick).as_bytes()).await.is_err() { break; }
                                println!("{} Запрос на приватный чат от '{}' к '{}' отклонен", "ИНФО:".cyan(), nickname_write, originator_nick);
                            }
                        }
                    }
                    "PRIVATE_CHAT_ENDED" => {
                        if let ClientState::InPrivateChat { with_nick } = &*state_guard {
                            if with_nick == &originator_nick {
                                *state_guard = ClientState::PublicChat;
                                if writer_guard.write_all(format!("Пользователь '{}' завершил личный чат. Вы возвращены в общий чат.\n", originator_nick).as_bytes()).await.is_err() { break; }
                                println!("{} Приватный чат между '{}' и '{}' завершен по инициативе второго пользователя", "ИНФО:".cyan(), nickname_write, originator_nick);
                            }
                        }
                    }
                    "PRIVATE_CHAT_BUSY" => {
                        if let ClientState::WaitingForPrivateChatResponse { target_nick } = &*state_guard {
                            if target_nick == &originator_nick {
                                *state_guard = ClientState::PublicChat;
                                if writer_guard.write_all(format!("Пользователь '{}' сейчас занят и не может начать личный чат.\n", originator_nick).as_bytes()).await.is_err() { break; }
                            }
                        }
                    }
                    _ => { eprintln!("{} Неизвестная системная команда: {}", "ОШИБКА СЕРВЕРА:".red(), command); }
                }
                } else {
                    // обычное сообщение
                    let display_message = match &*state_guard {
                        ClientState::InPrivateChat {..} => !msg_str.starts_with(&format!("{} ", "Всем".blue())),
                        _ => true,
                    };

                    if display_message {
                        if writer_guard.write_all(msg_str.as_bytes()).await.is_err() { break; }
                    }
                }

                drop(state_guard);
                if writer_guard.flush().await.is_err() { break; }
            }
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        })
    };

    // ожидание завершения одной из задач
    tokio::select! {
        res = read_task => {
            if let Err(e) = res { eprintln!("{} Ошибка в задаче чтения для {}: {:?}", "СИСТЕМА:".magenta(), nickname, e); }
            // если read_task завершилась (например, клиент закрыл соединение),
            // то write_task тоже должна завершиться, так как rx_from_others закроется после удаления из connected_users
        },
        res = write_task => {
            if let Err(e) = res { eprintln!("{} Ошибка в задаче записи для {}: {:?}", "СИСТЕМА:".magenta(), nickname, e); }
            // если write_task завершилась (например, ошибка записи в сокет),
            // то read_task тоже должна быть уведомлена о необходимости завершения (пока не реализовано)
        },
    }

    // очистка чата при отключении клиента
    let final_client_state = client_state.lock().await.clone(); //получаем итоговое состояние
    {
        let mut users_guard = connected_users.lock().await;
        users_guard.remove(&nickname);
        println!("{}", format!("Пользователь '{}' отключился. В сети: {}", nickname, users_guard.len()).yellow());
    }

    // если клиент был в приватном чате, уведомить партнера
    if let ClientState::InPrivateChat { with_nick } = final_client_state {
        let _ = send_to_user(&connected_users, &with_nick, format!("SYSTEM:PRIVATE_CHAT_ENDED:{}", nickname)).await;
         println!("{} Уведомлен '{}' о выходе '{}' из их приватного чата", "ИНФО:".cyan(), with_nick, nickname);
    }

    let leave_msg = format!("Пользователь '{}' вышел из чата", nickname);
    broadcast_message(&connected_users, &nickname, &leave_msg, true).await;

    Ok(())
}