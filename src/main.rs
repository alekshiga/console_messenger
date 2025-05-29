use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use std::collections::HashMap;
use std::sync::Arc;
use colored::*; // для цветного вывода в консоли
use tokio::fs::{OpenOptions as TokioOpenOptions, File as TokioFile};
use std::path::Path;
use std::error::Error;
use aes_gcm::{Aes256Gcm, Nonce}; // для шифрования AES-GCM
use aes_gcm::aead::{Aead, KeyInit}; // для трейтов Aead и KeyInit
use rand::{rngs::OsRng, RngCore}; // для генерации случайных чисел (шифрование) (nonce, shared key)
use hex; // для кодирования/декодирования в/из hex-строк

// Тип для отправки сообщений между задачами (UnboundedSender)
type Tx = mpsc::UnboundedSender<String>;

// перечисление для отслеживания состояния клиента в чате
#[derive(Debug, Clone)]
enum ClientState {
    PublicChat, // клиент находится в общем чате
    // клиент отправил запрос на приватный чат и ожидает ответа
    WaitingForPrivateChatResponse { target_nick: String, sent_key: Vec<u8> },
    // клиент получил запрос на приватный чат и ожидает принятия/отклонения
    HasPendingPrivateChatRequest { from_nick: String, shared_key: Vec<u8> },
    // клиент находится в приватном чате с указанным ником и общим ключом
    InPrivateChat { with_nick: String, shared_key: Vec<u8> },
}

// основная функция сервера, запускаемая Tokio
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    // устанавливает кодовую страницу 65001 (UTF-8) (всё равно запускается только на сервере,
    // на клиентах нужно вводить при каждом запуске)
    #[cfg(windows)]
    {
        use std::process::Command;
        let _ = Command::new("cmd")
            .args(&["/C", "chcp 65001"])
            .status();
    }

    // загрузка базы данных пользователей из файла "users.txt"
    let users_db = Arc::new(Mutex::new(load_users("users.txt").await?));
    // hashMap для хранения подключенных пользователей
    let connected_users: Arc<Mutex<HashMap<String, Tx>>> = Arc::new(Mutex::new(HashMap::new()));

    // запуск TCP-слушателя на всех сетевых интерфейсах по порту 8080
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("{}", "Сервер запущен на 127.0.0.1:8080".green());

    // бесконечный цикл для принятия входящих соединений
    loop {
        let (socket, addr) = listener.accept().await?; // принимаем новое соединение
        println!("{} {}", "Новое подключение:".yellow(), addr);

        // клонируем Arc-указатели для передачи владения новой задаче
        let users_db_clone = users_db.clone();
        let connected_users_clone = connected_users.clone();

        // запускаем асинхронную задачу для обработки нового клиента
        tokio::spawn(async move {
            let client_addr = addr; // сохраняем адрес клиента для логирования
            // обрабатываем клиента, логируя результат (успех или ошибка) (возможно логирование некоторых вещей уже избыточно, но мне нужно было для отладки)
            match handle_client(socket, users_db_clone, connected_users_clone).await {
                Ok(_) => println!("{} {} {}", "Клиент".yellow(), client_addr, "отключился корректно."),
                Err(e) => eprintln!("{} {}: {:?} {}", "ОШИБКА С КЛИЕНТОМ".red(), client_addr, e, "Клиент отключился с ошибкой."),
            }
        });
    }
}

// асинхронная функция для загрузки пользователей из файла
async fn load_users(path: &str) -> Result<HashMap<String, String>, Box<dyn Error + Send + Sync>> {
    let mut users = HashMap::new();
    let path_obj = Path::new(path);

    // если файла нет, создаем его
    if !path_obj.exists() {
        TokioFile::create(path).await?;
        println!("{} {}", "Создан пустой файл пользователей:".blue(), path);
        return Ok(users);
    }

    // открываем файл и читаем его построчно
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

// асинхронная функция для добавления нового пользователя в файл
async fn add_user_to_file(path: &str, username: &str, password: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut file = TokioOpenOptions::new()
        .append(true) // Открываем файл в режиме добавления
        .create(true) // Создаем файл, если он не существует
        .open(path)
        .await?;
    file.write_all(format!("{}:{}\n", username, password).as_bytes()).await?;
    file.flush().await?; // Сбрасываем буфер, чтобы данные были записаны на диск
    Ok(())
}

// асинхронная функция для широковещательной рассылки сообщений
async fn broadcast_message(
    connected_users: &Arc<Mutex<HashMap<String, Tx>>>,
    sender: &str,
    message: &str,
    is_system_message: bool, // флаг: true для системных сообщений (вход/выход)
) {
    let users = connected_users.lock().await; // блокируем мьютекс для доступа к HashMap
    for (nick, tx) in users.iter() {
        if nick != sender { // не отправляем сообщение отправителю
            let full_msg = if is_system_message {
                format!("{}\n", message) // системные сообщения отправляются как есть
            } else {
                format!("{} {}: {}\n", "Всем".blue(), sender, message) // обычные сообщения форматируются
            };
            // прямая отправка сообщения через канал.
            // Фильтрация (показывать или нет) будет происходить на стороне получателя сообщение
            // на основе его клиентского состояния
            let _ = tx.send(full_msg); // игнорируем ошибку, если получатель уже отключился
        }
    }
}

// асинхронная функция для отправки сообщения конкретному пользователю
async fn send_to_user(
    connected_users: &Arc<Mutex<HashMap<String, Tx>>>,
    recipient_nick: &str,
    message: String,
) -> Result<(), String> {
    let users = connected_users.lock().await; // блокируем мьютекс для доступа к HashMap
    if let Some(tx) = users.get(recipient_nick) { // ищем получателя
        // клонируем сообщение перед отправкой, чтобы можно было использовать его для логирования
        if tx.send(message.clone()).is_err() {
            // если канал закрыт (получатель отключился)
            eprintln!("{} ОШИБКА: Канал к пользователю '{}' закрыт. Возможно, клиент отключился.", "СЕРВЕР:".red(), recipient_nick);
            Err(format!("Не удалось отправить сообщение пользователю {}", recipient_nick))
        } else {
            // сообщение успешно отправлено в канал
            println!("{} ОТПРАВЛЕНО: Сообщение для '{}' (начало: {})", "СЕРВЕР:".green(), recipient_nick, &message[..std::cmp::min(message.len(), 50)]);
            Ok(())
        }
    } else {
        // пользователь не найден в списке подключенных
        eprintln!("{} ОШИБКА: Пользователь '{}' не найден в connected_users.", "СЕРВЕР:".red(), recipient_nick);
        Err(format!("Пользователь {} не найден или не в сети.", recipient_nick))
    }
}

// ОСНОВНАЯ ФУНКЦИЯ ОБРАБОТКИ
async fn handle_client(
    socket: TcpStream,
    users_db: Arc<Mutex<HashMap<String, String>>>,
    connected_users: Arc<Mutex<HashMap<String, Tx>>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    // разделяем TCP-сокет на части для чтения и записи
    let (reader_half, writer_half) = socket.into_split();
    let mut reader = BufReader::new(reader_half);
    let writer_arc = Arc::new(Mutex::new(writer_half)); // мьютекс для безопасного доступа

    // отправляем приветственное сообщение новому клиенту
    {
        let mut writer_guard = writer_arc.lock().await;
        writer_guard.write_all("Добро пожаловать в чат! Введите /help для списка команд.\n".as_bytes()).await?;
        writer_guard.flush().await?;
    }

    let nickname: String;
    let mut attempts = 3; // 3 попытки для авторизации/регистрации

    // Цикл авторизации/регистрации
    loop {
        if attempts == 0 {
            let mut writer_guard = writer_arc.lock().await;
            writer_guard.write_all("Превышено количество попыток. Отключение.\n".as_bytes()).await?;
            writer_guard.flush().await?;
            return Err("Неудачная авторизация".into()); // выход с ошибкой
        }

        // Запрос никнейма
        {
            let mut writer_guard = writer_arc.lock().await;
            writer_guard.write_all("Введите никнейм:\n".as_bytes()).await?;
            writer_guard.flush().await?;
        }
        let mut nick_input = String::new();
        if reader.read_line(&mut nick_input).await? == 0 { return Err("Клиент отключился до авторизации".into()); }
        let nick_input = nick_input.trim().to_string();

        // Запрос пароля
        {
            let mut writer_guard = writer_arc.lock().await;
            writer_guard.write_all("Введите пароль:\n".as_bytes()).await?;
            writer_guard.flush().await?;
        }
        let mut pass_input = String::new();
        if reader.read_line(&mut pass_input).await? == 0 { return Err("Клиент отключился до авторизации".into()); }
        let pass_input = pass_input.trim().to_string();

        let mut db_guard = users_db.lock().await; // Блокируем БД пользователей
        match db_guard.get(&nick_input) {
            Some(stored_pass) if *stored_pass == pass_input => {
                // Авторизация успешна
                nickname = nick_input;
                let mut writer_guard = writer_arc.lock().await;
                writer_guard.write_all("Авторизация успешна!\n".as_bytes()).await?;
                writer_guard.flush().await?;
                println!("{}", format!("Пользователь '{}' авторизовался", nickname).green());
                break;
            }
            None => {
                // если пользователь не найден, предлагаем регистрацию
                let mut writer_guard = writer_arc.lock().await;
                writer_guard.write_all("Пользователь не найден. Хотите зарегистрироваться? (да/нет):\n".as_bytes()).await?;
                writer_guard.flush().await?;
                let mut answer = String::new();
                if reader.read_line(&mut answer).await? == 0 { return Err("Клиент отключился во время регистрации".into()); }
                let answer = answer.trim().to_lowercase();
                if answer == "да" || answer == "yes" {
                    db_guard.insert(nick_input.clone(), pass_input.clone());
                    let nick_clone_for_file = nick_input.clone();
                    let pass_clone_for_file = pass_input.clone();
                    drop(db_guard); // освобождаем мьютекс перед асинхронной записью в файл
                    add_user_to_file("users.txt", &nick_clone_for_file, &pass_clone_for_file).await?; // Записываем в файл
                    nickname = nick_clone_for_file;
                    let mut writer_guard = writer_arc.lock().await;
                    writer_guard.write_all("Регистрация успешна! Вы авторизованы.\n".as_bytes()).await?;
                    writer_guard.flush().await?;
                    println!("{}", format!("Пользователь '{}' зарегистрировался", nickname).green());
                    break; // Выходим из цикла авторизации
                } else {
                    writer_guard.write_all("Попробуйте снова.\n".as_bytes()).await?;
                    writer_guard.flush().await?;
                    attempts -= 1; // Уменьшаем количество попыток
                }
            }
            Some(_) => {
                // Неверный пароль
                let mut writer_guard = writer_arc.lock().await;
                writer_guard.write_all("Неверный пароль. Попробуйте снова.\n".as_bytes()).await?;
                writer_guard.flush().await?;
                attempts -= 1; // Уменьшаем количество попыток
            }
        }
    } 

    // Проверка, если никнейм уже в сети
    {
        let users_guard = connected_users.lock().await;
        if users_guard.contains_key(&nickname) {
            let mut writer_guard = writer_arc.lock().await;
            writer_guard.write_all("Пользователь с таким ником уже в сети. Отключение.\n".as_bytes()).await?;
            writer_guard.flush().await?;
            return Err("Дубликат никнейма".into()); // Выходим с ошибкой
        }
    }

    // Вывод списка онлайн-пользователей
    {
        let users_guard = connected_users.lock().await;
        let connected_list: Vec<String> = users_guard.keys()
            .filter(|name| *name != &nickname) // Исключаем текущего пользователя
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

    // Создаем канал для связи между read_task и write_task данного клиента
    let (tx_to_client, rx_from_others) = mpsc::unbounded_channel::<String>();
    // добавляем нового пользователя в список подключенных
    {
        let mut users_guard = connected_users.lock().await;
        users_guard.insert(nickname.clone(), tx_to_client);
    }

    // сообщение о входе нового пользователя
    let join_msg = format!("Пользователь '{}' вошёл в чат", nickname);
    println!("{}", join_msg.yellow());
    broadcast_message(&connected_users, &nickname, &join_msg, true).await;
    let client_state = Arc::new(Mutex::new(ClientState::PublicChat));

    // Запускаем задачу чтения сообщений от клиента
    let read_task = tokio::spawn({
        let writer_arc_clone = writer_arc.clone();
        let connected_users_read = connected_users.clone();
        let nickname_read = nickname.clone();
        let client_state_read = client_state.clone();
        let mut reader = reader; // Перемещаем reader во владение этой задаче

        async move {
            let res: Result<(), Box<dyn Error + Send + Sync>> = loop {
                let mut line = String::new();
                let _bytes_read = match reader.read_line(&mut line).await {
                    Ok(0) => { // Клиент отключился
                        println!("{} {}: Клиент отключился (return 0).", "ИНФО:".cyan(), nickname_read);
                        break Ok(()); // Завершаем задачу успешно
                    },
                    Ok(n) => n, // Успешно прочитано(кол-во байт)
                    Err(e) => { // Ошибка чтения
                        eprintln!("{} Ошибка чтения от {}: {}", "ОШИБКА:".red(), nickname_read, e);
                        break Err(e.into()); // Завершаем задачу с ошибкой
                    },
                };

                let msg_trimmed = line.trim();
                if msg_trimmed.is_empty() { continue; } // Пропускаем пустые строки

                let mut current_writer_guard = writer_arc_clone.lock().await;
                let mut state_guard = client_state_read.lock().await;

                // Проверка на команду "выход" из приватного чата
                if msg_trimmed.to_lowercase() == "выход" {
                    if let ClientState::InPrivateChat { with_nick, shared_key: _ } = &*state_guard {
                        let partner_nick = with_nick.clone();
                        // Уведомляем партнера о выходе из приватного чата
                        let _ = send_to_user(
                            &connected_users_read,
                            &partner_nick,
                            format!("SYSTEM:PRIVATE_CHAT_ENDED:{}", nickname_read)
                        ).await;
                        // Уведомляем текущего клиента
                        current_writer_guard.write_all("Вы вышли из личного чата. Возвращение в общий чат.\n".as_bytes()).await?;
                        current_writer_guard.flush().await?;
                        *state_guard = ClientState::PublicChat; // Возвращаем клиента в общий чат
                        println!("{} '{}' вышел из приватного чата с '{}'", "ИНФО:".cyan(), nickname_read, partner_nick);
                        continue;
                    }
                }

                // Обработка команд (/help, /list, /pm, /accept, /reject)
                if msg_trimmed.starts_with('/') {
                    let mut parts = msg_trimmed[1..].splitn(2, ' ');
                    let command = parts.next().unwrap_or("").to_lowercase();
                    let args = parts.next().unwrap_or("").trim();

                    match command.as_str() {
                        "help" => {
                            current_writer_guard.write_all(
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
                                match &mut *state_guard { // Используем &mut * для изменения состояния
                                    ClientState::PublicChat => {
                                        let target_nick = args.to_string();
                                        // Генерируем ключ для приватного чата
                                        let mut key_bytes = [0u8; 32];
                                        OsRng.fill_bytes(&mut key_bytes);
                                        let shared_key = key_bytes.to_vec();
                                        let key_hex = hex::encode(&shared_key);

                                        if send_to_user(&connected_users_read, &target_nick, format!("SYSTEM:PRIVATE_CHAT_REQUEST:{}:{}", nickname_read, key_hex)).await.is_ok() {
                                            current_writer_guard.write_all(format!("Запрос на личный чат отправлен пользователю '{}'. Ожидание ответа...\n", target_nick).as_bytes()).await?;
                                            // Сохраняем отправленный ключ в состоянии
                                            *state_guard = ClientState::WaitingForPrivateChatResponse { target_nick: target_nick.clone(), sent_key: shared_key };
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
                            if let ClientState::HasPendingPrivateChatRequest { from_nick, shared_key } = &mut *state_guard {
                                let partner_nick = from_nick.clone();
                                let key_to_use = shared_key.clone(); // Ключ получен с запросом
                                if send_to_user(&connected_users_read, &partner_nick, format!("SYSTEM:PRIVATE_CHAT_ACCEPTED:{}", nickname_read)).await.is_ok() {
                                    current_writer_guard.write_all(format!("Вы начали личный чат с '{}'. Напишите 'выход' для возврата в общий чат.\n", partner_nick).as_bytes()).await?;
                                    *state_guard = ClientState::InPrivateChat { with_nick: partner_nick.clone(), shared_key: key_to_use };
                                    println!("{} '{}' принял приватный чат от '{}'", "ИНФО:".cyan(), nickname_read, partner_nick);
                                } else {
                                    current_writer_guard.write_all(format!("Не удалось уведомить '{}', возможно, он отключился. Вы возвращены в общий чат.\n", partner_nick).as_bytes()).await?;
                                    *state_guard = ClientState::PublicChat; // Возврат в общий чат
                                }
                            } else {
                                current_writer_guard.write_all("Нет активных запросов на личный чат для принятия.\n".as_bytes()).await?;
                            }
                        }
                        "reject" => {
                            if let ClientState::HasPendingPrivateChatRequest { from_nick, shared_key: _ } = &mut *state_guard {
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
                // Обработка обычных сообщений или старых личных сообщений
                else {
                    match &*state_guard {
                        ClientState::InPrivateChat { with_nick, shared_key } => {
                            let cipher = Aes256Gcm::new_from_slice(shared_key).expect("Key length is 32 bytes");
                            let mut nonce_array = [0u8; 12]; // GCM nonces are 12 bytes
                            OsRng.fill_bytes(&mut nonce_array);
                            let nonce = Nonce::from_slice(&nonce_array); // Создаем Nonce из среза массива

                            let ciphertext_result = cipher.encrypt(&nonce, msg_trimmed.as_bytes());

                            match ciphertext_result {
                                Ok(ciphertext) => {
                                    let encrypted_msg = format!(
                                        "SYSTEM:ENCRYPTED_PRIVATE_MSG:{}:{}:{}",
                                        nickname_read,
                                        hex::encode(nonce_array), // Кодируем массив nonce в hex
                                        hex::encode(ciphertext) // Кодируем зашифрованный текст в hex
                                    );
                                    let private_msg_echo = format!("[ЛС для {}]: {}\n", with_nick.magenta(), msg_trimmed);

                                    if send_to_user(&connected_users_read, with_nick, encrypted_msg).await.is_ok() {
                                        current_writer_guard.write_all(private_msg_echo.as_bytes()).await?;
                                    } else {
                                        current_writer_guard.write_all(format!("Не удалось отправить сообщение '{}'. Возможно, пользователь отключился. Вы возвращены в общий чат.\n", with_nick).as_bytes()).await?;
                                        *state_guard = ClientState::PublicChat; // Возврат в общий чат
                                    }
                                }
                                Err(e) => {
                                    eprintln!("{} Ошибка шифрования для {}: {:?}", "ОШИБКА:".red(), nickname_read, e);
                                    current_writer_guard.write_all("Ошибка шифрования сообщения. Попробуйте снова.\n".as_bytes()).await?;
                                }
                            }
                            current_writer_guard.flush().await?;
                        }
                        ClientState::PublicChat => {
                            // Старый формат ЛС (не рекомендуется) или публичное сообщение
                            if let Some(idx) = msg_trimmed.find(':') {
                                let recipient = msg_trimmed[..idx].trim();
                                let message_content = msg_trimmed[idx + 1..].trim();
                                if recipient == nickname_read {
                                     current_writer_guard.write_all("Вы не можете отправить ЛС самому себе.\n".as_bytes()).await?;
                                } else {
                                    // Здесь старые ЛС не шифруются, т.к. нет общего ключа
                                    let full_msg = format!("{} {}: {}\n", "Вам".cyan(), nickname_read, message_content);
                                    if send_to_user(&connected_users_read, recipient, full_msg).await.is_ok() {
                                        current_writer_guard.write_all(format!("[ЛС для {}]: {}\n", recipient, message_content).as_bytes()).await?;
                                    } else {
                                        current_writer_guard.write_all(format!("{} Пользователь '{}' не найден или не в сети.\n", "Ошибка:".red(), recipient).as_bytes()).await?;
                                    }
                                }
                                current_writer_guard.flush().await?;
                            } else {
                                // Публичное сообщение
                                broadcast_message(&connected_users_read, &nickname_read, msg_trimmed, false).await;
                            }
                        }
                        ClientState::WaitingForPrivateChatResponse { target_nick, sent_key: _ } => {
                            current_writer_guard.write_all(format!("Вы ожидаете ответа от '{}'. Чтобы отправить сообщение в общий чат, сначала отмените запрос (пока не реализовано) или дождитесь ответа.\n", target_nick).as_bytes()).await?;
                            current_writer_guard.flush().await?;
                        }
                        ClientState::HasPendingPrivateChatRequest { from_nick, shared_key: _ } => {
                            current_writer_guard.write_all(format!("У вас есть запрос на личный чат от '{}'. Введите /accept или /reject.\n", from_nick).as_bytes()).await?;
                            current_writer_guard.flush().await?;
                        }
                    }
                }
            };
            res // Возвращаем результат выполнения задачи
        }
    });

    // Запускаем задачу записи сообщений клиенту
    let write_task = tokio::spawn({
        let writer_arc_for_task = writer_arc.clone();
        let client_state_write = client_state.clone();
        let connected_users_write = connected_users.clone();
        let nickname_write = nickname.clone();
        let mut rx_from_others = rx_from_others; // Перемещаем receiver во владение этой задаче

        async move {
            // Внутренний Result для логирования завершения задачи
            let res: Result<(), Box<dyn Error + Send + Sync>> = loop {
                let msg_str = match rx_from_others.recv().await {
                    Some(msg) => {
                        println!("{} RECEIVED_BY_WRITE_TASK ({}): {}", "ИНФО:".yellow(), nickname_write, msg.trim()); // Логируем полученное сообщение
                        msg
                    },
                    None => { // Канал закрыт, задача записи завершается
                        println!("{} {}: Канал rx_from_others закрыт (write_task завершается).", "ИНФО:".cyan(), nickname_write);
                        break Ok(()); // Завершаем задачу успешно
                    },
                };
                
                let mut writer_guard = writer_arc_for_task.lock().await;
                let mut state_guard = client_state_write.lock().await;

                if msg_str.starts_with("SYSTEM:") {
                    // Разделяем системное сообщение на команду и аргументы
                    let parts: Vec<&str> = msg_str.splitn(2, ':').collect();
                    if parts.len() < 2 {
                        eprintln!("{} Некорректное системное сообщение: {}", "ОШИБКА СЕРВЕРА:".red(), msg_str);
                        continue; // Продолжаем цикл, чтобы не прерывать задачу из-за одного плохого сообщения
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
                                        match &mut *state_guard {
                                            ClientState::PublicChat => {
                                                *state_guard = ClientState::HasPendingPrivateChatRequest { from_nick: sender_nick.clone(), shared_key };
                                                if writer_guard.write_all(format!("Пользователь '{}' хочет начать с вами личный чат. Введите /accept или /reject.\n", sender_nick).as_bytes()).await.is_err() { break Ok(()); } // Corrected break
                                                println!("{} '{}' получил запрос на приватный чат от '{}'", "ИНФО:".cyan(), nickname_write, sender_nick);
                                            }
                                            _ => { // Клиент уже в другом состоянии
                                                drop(writer_guard); // Освобождаем guard перед send_to_user
                                                let _ = send_to_user(&connected_users_write, &sender_nick, format!("SYSTEM:PRIVATE_CHAT_BUSY:{}", nickname_write)).await;
                                                continue;
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        eprintln!("{} Неверный формат ключа в PRIVATE_CHAT_REQUEST от {}", "ОШИБКА СЕРВЕРА:".red(), sender_nick);
                                        if writer_guard.write_all("Получен некорректный запрос на приватный чат (ошибка ключа).\n".as_bytes()).await.is_err() { break Ok(()); } // Corrected break
                                    }
                                }
                            } else {
                                eprintln!("{} Некорректный формат PRIVATE_CHAT_REQUEST: {}", "ОШИБКА СЕРВЕРА:".red(), msg_str);
                                if writer_guard.write_all("Получен некорректный запрос на приватный чат.\n".as_bytes()).await.is_err() { break Ok(()); } // Corrected break
                            }
                        }
                        "PRIVATE_CHAT_ACCEPTED" => {
                            let originator_nick = args.to_string();
                            match &mut *state_guard {
                                ClientState::WaitingForPrivateChatResponse { target_nick, sent_key } if target_nick == &originator_nick => {
                                    *state_guard = ClientState::InPrivateChat { with_nick: originator_nick.clone(), shared_key: sent_key.clone() };
                                    if writer_guard.write_all(format!("{} Пользователь '{}' принял ваш запрос на личный чат. Вы теперь в приватном чате.\n", "ИНФО:".green(), originator_nick).as_bytes()).await.is_err() { break Ok(()); } // Corrected break
                                    println!("{} '{}' обновил статус: приватный чат с '{}'", "ИНФО:".cyan(), nickname_write, originator_nick);
                                }
                                _ => {
                                    eprintln!("{} Неожиданный PRIVATE_CHAT_ACCEPTED от {} для {}", "ОШИБКА СЕРВЕРА:".red(), originator_nick, nickname_write);
                                    if writer_guard.write_all(format!("Пользователь '{}' принял ваш запрос, но вы не находитесь в ожидающем состоянии. Возможно, чат уже начат или отменен.\n", originator_nick).as_bytes()).await.is_err() { break Ok(()); } // Corrected break
                                }
                            }
                        }
                        "PRIVATE_CHAT_REJECTED" => {
                            let originator_nick = args.to_string();
                            match &mut *state_guard {
                                ClientState::WaitingForPrivateChatResponse { target_nick, sent_key: _ } if target_nick == &originator_nick => {
                                    *state_guard = ClientState::PublicChat;
                                    if writer_guard.write_all(format!("{} Пользователь '{}' отклонил ваш запрос на личный чат. Вы возвращены в общий чат.\n", "ИНФО:".green(), originator_nick).as_bytes()).await.is_err() { break Ok(()); } // Corrected break
                                    println!("{} '{}' отклонил приватный чат от '{}'", "ИНФО:".cyan(), originator_nick, nickname_write);
                                }
                                _ => {
                                    eprintln!("{} Неожиданный PRIVATE_CHAT_REJECTED от {} для {}", "ОШИБКА СЕРВЕРА:".red(), originator_nick, nickname_write);
                                    if writer_guard.write_all(format!("Пользователь '{}' отклонил ваш запрос, но вы не находитесь в ожидающем состоянии. Возможно, чат уже начат или отменен.\n", originator_nick).as_bytes()).await.is_err() { break Ok(()); } // Corrected break
                                }
                            }
                        }
                        "PRIVATE_CHAT_ENDED" => {
                            let originator_nick = args.to_string();
                            match &mut *state_guard {
                                ClientState::InPrivateChat { with_nick, shared_key: _ } if with_nick == &originator_nick => {
                                    *state_guard = ClientState::PublicChat;
                                    if writer_guard.write_all(format!("{} Пользователь '{}' вышел из личного чата. Вы возвращены в общий чат.\n", "ИНФО:".green(), originator_nick).as_bytes()).await.is_err() { break Ok(()); } // Corrected break
                                    println!("{} '{}' вышел из приватного чата с '{}'", "ИНФО:".cyan(), originator_nick, nickname_write);
                                }
                                _ => {
                                    eprintln!("{} Неожиданный PRIVATE_CHAT_ENDED от {} для {}", "ОШИБКА СЕРВЕРА:".red(), originator_nick, nickname_write);
                                }
                            }
                        }
                        "PRIVATE_CHAT_BUSY" => {
                            let originator_nick = args.to_string();
                            match &mut *state_guard {
                                ClientState::WaitingForPrivateChatResponse { target_nick, sent_key: _ } if target_nick == &originator_nick => {
                                    *state_guard = ClientState::PublicChat;
                                    if writer_guard.write_all(format!("{} Пользователь '{}' занят или уже в другом приватном чате. Вы возвращены в общий чат.\n", "ИНФО:".green(), originator_nick).as_bytes()).await.is_err() { break Ok(()); } // Corrected break
                                    println!("{} '{}' занят для приватного чата с '{}'", "ИНФО:".cyan(), originator_nick, nickname_write);
                                }
                                _ => {
                                    eprintln!("{} Неожиданный PRIVATE_CHAT_BUSY от {} для {}", "ОШИБКА СЕРВЕРА:".red(), originator_nick, nickname_write);
                                }
                            }
                        }
                        "ENCRYPTED_PRIVATE_MSG" => {
                            let msg_parts: Vec<&str> = args.splitn(3, ':').collect(); // sender_nick:nonce_hex:ciphertext_hex
                            if msg_parts.len() == 3 {
                                let sender_nick = msg_parts[0];
                                let nonce_hex = msg_parts[1];
                                let ciphertext_hex = msg_parts[2];
                                
                                match &mut *state_guard {
                                    ClientState::InPrivateChat { with_nick, shared_key } if with_nick == sender_nick => {
                                        match hex::decode(nonce_hex) {
                                            Ok(nonce_bytes) if nonce_bytes.len() == 12 => { // Проверяем длину nonce
                                                match hex::decode(ciphertext_hex) {
                                                    Ok(ciphertext_bytes) => {
                                                        let cipher = Aes256Gcm::new_from_slice(shared_key).expect("Key length is 32 bytes");
                                                        let nonce = Nonce::from_slice(&nonce_bytes); // Создаем Nonce из среза
                                                        match cipher.decrypt(nonce, ciphertext_bytes.as_ref()) {
                                                            Ok(plaintext_bytes) => {
                                                                if let Ok(plaintext_msg) = String::from_utf8(plaintext_bytes) {
                                                                    if writer_guard.write_all(format!("[ЛС от {}]: {}\n", sender_nick.cyan(), plaintext_msg).as_bytes()).await.is_err() { break Ok(()); } // Corrected break
                                                                    println!("{} '{}' получил зашифрованное ЛС от '{}'", "ИНФО:".cyan(), nickname_write, sender_nick);
                                                                } else {
                                                                    eprintln!("{} Ошибка декодирования UTF-8 для {}: {}", "ОШИБКА:".red(), nickname_write, sender_nick);
                                                                    if writer_guard.write_all("Получено некорректное UTF-8 сообщение (дешифровка).\n".as_bytes()).await.is_err() { break Ok(()); } // Corrected break
                                                                }
                                                            },
                                                            Err(e) => {
                                                                eprintln!("{} Ошибка дешифрования для {}: {:?}", "ОШИБКА:".red(), nickname_write, e);
                                                                if writer_guard.write_all("Ошибка дешифрования сообщения. Возможно, ключ неверный.\n".as_bytes()).await.is_err() { break Ok(()); } // Corrected break
                                                            }
                                                        }
                                                    },
                                                    Err(e) => {
                                                        eprintln!("{} Ошибка декодирования hex для ciphertext: {:?}", "ОШИБКА:".red(), e);
                                                        if writer_guard.write_all("Получено некорректное зашифрованное сообщение (ошибка hex-декодирования).\n".as_bytes()).await.is_err() { break Ok(()); } // Corrected break
                                                    }
                                                }
                                            },
                                            _ => { // Некорректная длина nonce
                                                eprintln!("{} Ошибка декодирования hex для nonce или неверная длина: {:?}", "ОШИБКА:".red(), nonce_hex);
                                                if writer_guard.write_all("Получено некорректное зашифрованное сообщение (ошибка hex-декодирования nonce или неверная длина).\n".as_bytes()).await.is_err() { break Ok(()); } // Corrected break
                                            }
                                        }
                                    },
                                    _ => { // Клиент не в приватном чате или не с тем партнером
                                        eprintln!("{} Получено ENCRYPTED_PRIVATE_MSG от {} для {} в некорректном состоянии.", "ОШИБКА СЕРВЕРА:".red(), sender_nick, nickname_write);
                                        if writer_guard.write_all(format!("Получено зашифрованное сообщение от '{}', но вы не находитесь в приватном чате с ним.\n", sender_nick).as_bytes()).await.is_err() { break Ok(()); } // Corrected break
                                    }
                                }
                            } else {
                                eprintln!("{} Некорректный формат ENCRYPTED_PRIVATE_MSG: {}", "ОШИБКА СЕРВЕРА:".red(), msg_str);
                                if writer_guard.write_all("Получено некорректное зашифрованное сообщение.\n".as_bytes()).await.is_err() { break Ok(()); } // Corrected break
                            }
                        }
                        _ => { eprintln!("{} Неизвестная системная команда: {}", "ОШИБКА СЕРВЕРА:".red(), command); }
                    }
                } else { // Обычное сообщение (не системное)
                    let display_message = match &*state_guard {
                        ClientState::InPrivateChat {..} => !msg_str.starts_with(&format!("{} ", "Всем".blue())),
                        _ => true,
                    };
                    if display_message {
                        if writer_guard.write_all(msg_str.as_bytes()).await.is_err() { break Ok(()); } // Corrected break
                    }
                }

                drop(state_guard); // Явно освобождаем guard
                if writer_guard.flush().await.is_err() { break Ok(()); } // Corrected break
            };
            res // Возвращаем результат выполнения задачи
        }
    });

    // Ожидание завершения одной из задач (read_task или write_task)
    tokio::select! {
        res = read_task => {
            if let Err(e) = res { eprintln!("{} Ошибка в задаче чтения для {}: {:?}", "СИСТЕМА:".magenta(), nickname, e); }
            println!("{} {}: read_task завершилась в select.", "ИНФО:".cyan(), nickname);
        },
        res = write_task => {
            if let Err(e) = res { eprintln!("{} Ошибка в задаче записи для {}: {:?}", "СИСТЕМА:".magenta(), nickname, e); }
            println!("{} {}: write_task завершилась в select.", "ИНФО:".cyan(), nickname);
        },
    }

    // Очистка чата при отключении клиента
    let final_client_state = client_state.lock().await.clone(); // Получаем итоговое состояние клиента
    {
        let mut users_guard = connected_users.lock().await;
        users_guard.remove(&nickname); // Удаляем клиента из списка подключенных
        println!("{}", format!("Пользователь '{}' отключился. В сети: {}", nickname, users_guard.len()).yellow());
    }

    // Если клиент был в приватном чате, уведомляем партнера о выходе
    if let ClientState::InPrivateChat { with_nick, shared_key: _ } = final_client_state {
        let _ = send_to_user(&connected_users, &with_nick, format!("SYSTEM:PRIVATE_CHAT_ENDED:{}", nickname)).await;
        println!("{} Уведомлен '{}' о выходе '{}' из их приватного чата", "ИНФО:".cyan(), with_nick, nickname);
    }

    // Широковещательное сообщение о выходе клиента
    let leave_msg = format!("Пользователь '{}' вышел из чата", nickname);
    broadcast_message(&connected_users, &nickname, &leave_msg, true).await;
    Ok(()) // Успешное завершение handle_client
}
