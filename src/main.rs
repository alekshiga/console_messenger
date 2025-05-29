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
use chrono::Local; // Для получения текущего времени и даты
use once_cell::sync::Lazy; // Для ленивой инициализации глобальной переменной

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

// Глобальная лениво инициализируемая переменная для файла логов.
// Используем Arc<Mutex<TokioFile>> для безопасного доступа к файлу из разных асинхронных задач.
static LOG_FILE: Lazy<Arc<Mutex<TokioFile>>> = Lazy::new(|| {
    // Создаем или открываем файл server.log. Unwrap используется, так как ошибка здесь критична.
    Arc::new(Mutex::new(TokioFile::from_std(std::fs::File::create("server.log")
        .expect("Не удалось создать или открыть файл логов"))))
});

/// Асинхронная функция для логирования сообщений.
/// Записывает сообщение в консоль с цветом и в файл логов без цвета.
///
/// # Аргументы
/// * `log_type` - Тип сообщения (например, "Server", "Auth", "info", "ERROR").
/// * `message` - Само сообщение.
/// * `color` - Цвет для вывода в консоль.
async fn log_message(log_type: &str, message: &str, color: Color) -> Result<(), Box<dyn Error + Send + Sync>> {
    let now = Local::now(); // Получаем текущее локальное время
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string(); // Форматируем время
    let colored_log_type = format!("[{}]", log_type).color(color); // Добавляем цвет для консоли
    let log_entry_console = format!("{} {} {}\n", timestamp, colored_log_type, message);

    // Вывод в консоль с цветом
    println!("{}", log_entry_console.trim_end());

    // Запись в файл логов (без кодов цвета)
    let mut file_guard = LOG_FILE.lock().await; // Блокируем мьютекс для доступа к файлу
    file_guard.write_all(format!("{} [{}] {}\n", timestamp, log_type, message).as_bytes()).await?;
    file_guard.flush().await?; // Убеждаемся, что данные записаны на диск
    Ok(())
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

    // Инициализируем файл логов, создавая его (или очищая, если существует)
    let _ = TokioFile::create("server.log").await?;
    log_message("Server", "Файл логов инициализирован.", Color::White).await?;


    // загрузка базы данных пользователей из файла "users.txt"
    let users_db = Arc::new(Mutex::new(load_users("users.txt").await?));
    // hashMap для хранения подключенных пользователей
    let connected_users: Arc<Mutex<HashMap<String, Tx>>> = Arc::new(Mutex::new(HashMap::new()));

    // запуск TCP-слушателя на всех сетевых интерфейсах по порту 8080
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    log_message("Server", "Сервер запущен на 127.0.0.1:8080", Color::Green).await?;

    // бесконечный цикл для принятия входящих соединений
    loop {
        let (socket, addr) = listener.accept().await?; // принимаем новое соединение
        log_message("info", &format!("Новое подключение: {}", addr), Color::Yellow).await?;

        // клонируем Arc-указатели для передачи владения новой задаче
        let users_db_clone = users_db.clone();
        let connected_users_clone = connected_users.clone();

        // запускаем асинхронную задачу для обработки нового клиента
        tokio::spawn(async move {
            let client_addr = addr; // сохраняем адрес клиента для логирования
            // обрабатываем клиента, логируя результат (успех или ошибка) (возможно логирование некоторых вещей уже избыточно, но мне нужно было для отладки)
            match handle_client(socket, users_db_clone, connected_users_clone).await {
                Ok(_) => {
                    let _ = log_message("Client", &format!("Клиент {} отключился корректно.", client_addr), Color::Yellow).await;
                },
                Err(e) => {
                    let _ = log_message("ERROR", &format!("Ошибка с клиентом {}: {:?} Клиент отключился с ошибкой.", client_addr, e), Color::Red).await;
                },
            }
        });
    }
}

/// Асинхронная функция для загрузки пользователей из файла.
async fn load_users(path: &str) -> Result<HashMap<String, String>, Box<dyn Error + Send + Sync>> {
    let mut users = HashMap::new();
    let path_obj = Path::new(path);

    // если файла нет, создаем его
    if !path_obj.exists() {
        TokioFile::create(path).await?;
        log_message("info", &format!("Создан пустой файл пользователей: {}", path), Color::Blue).await?;
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
            log_message("WARNING", &format!("Неверный формат строки в users.txt: {}", line), Color::Red).await?;
        }
    }
    log_message("info", &format!("Загружено {} пользователей из {}", users.len(), path), Color::Green).await?;
    Ok(users)
}

/// Асинхронная функция для добавления нового пользователя в файл.
async fn add_user_to_file(path: &str, username: &str, password: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut file = TokioOpenOptions::new()
        .append(true) // Открываем файл в режиме добавления
        .create(true) // Создаем файл, если он не существует
        .open(path)
        .await?;
    file.write_all(format!("{}:{}\n", username, password).as_bytes()).await?;
    file.flush().await?; // Сбрасываем буфер, чтобы данные были записаны на диск
    log_message("Auth", &format!("Пользователь '{}' зарегистрирован и добавлен в файл.", username), Color::Green).await?;
    Ok(())
}

/// Асинхронная функция для широковещательной рассылки сообщений.
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
    if !is_system_message {
        log_message("Global message", &format!("'{}' отправил в общий чат: {}", sender, message), Color::Blue).await.unwrap_or_else(|e| eprintln!("Ошибка логирования широковещательного сообщения: {:?}", e));
    }
}

/// Асинхронная функция для отправки сообщения конкретному пользователю.
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
            let error_msg = format!("Не удалось отправить сообщение пользователю {}", recipient_nick);
            log_message("ERROR", &format!("Канал к пользователю '{}' закрыт. Возможно, клиент отключился. Ошибка: {}", recipient_nick, error_msg), Color::Red).await.unwrap_or_else(|e| eprintln!("Ошибка логирования send_to_user: {:?}", e));
            Err(error_msg)
        } else {
            // сообщение успешно отправлено в канал
            log_message("Sent", &format!("Сообщение отправлено '{}' (начало: {})", recipient_nick, &message[..std::cmp::min(message.len(), 50)]), Color::Green).await.unwrap_or_else(|e| eprintln!("Ошибка логирования send_to_user: {:?}", e));
            Ok(())
        }
    } else {
        // пользователь не найден в списке подключенных
        let error_msg = format!("Пользователь {} не найден или не в сети.", recipient_nick);
        log_message("ERROR", &format!("Пользователь '{}' не найден в connected_users. Ошибка: {}", recipient_nick, error_msg), Color::Red).await.unwrap_or_else(|e| eprintln!("Ошибка логирования send_to_user: {:?}", e));
        Err(error_msg)
    }
}

// ОСНОВНАЯ ФУНКЦИЯ ОБРАБОТКИ КЛИЕНТА
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
            log_message("Auth", "Неудачная авторизация: Превышено количество попыток.", Color::Red).await?;
            return Err("Неудачная авторизация".into()); // выход с ошибкой
        }

        // Запрос никнейма
        {
            let mut writer_guard = writer_arc.lock().await;
            writer_guard.write_all("Введите никнейм:\n".as_bytes()).await?;
            writer_guard.flush().await?;
        }
        let mut nick_input = String::new();
        if reader.read_line(&mut nick_input).await? == 0 {
            log_message("Client", "Клиент отключился до авторизации (ввод никнейма).", Color::Yellow).await?;
            return Err("Клиент отключился до авторизации".into());
        }
        let nick_input = nick_input.trim().to_string();

        // Запрос пароля
        {
            let mut writer_guard = writer_arc.lock().await;
            writer_guard.write_all("Введите пароль:\n".as_bytes()).await?;
            writer_guard.flush().await?;
        }
        let mut pass_input = String::new();
        if reader.read_line(&mut pass_input).await? == 0 {
            log_message("Client", "Клиент отключился до авторизации (ввод пароля).", Color::Yellow).await?;
            return Err("Клиент отключился до авторизации".into());
        }
        let pass_input = pass_input.trim().to_string();

        let mut db_guard = users_db.lock().await; // Блокируем БД пользователей
        match db_guard.get(&nick_input) {
            Some(stored_pass) if *stored_pass == pass_input => {
                // Авторизация успешна
                nickname = nick_input;
                let mut writer_guard = writer_arc.lock().await;
                writer_guard.write_all("Авторизация успешна!\n".as_bytes()).await?;
                writer_guard.flush().await?;
                log_message("Auth", &format!("Пользователь '{}' авторизовался успешно.", nickname), Color::Green).await?;
                break;
            }
            None => {
                // если пользователь не найден, предлагаем регистрацию
                let mut writer_guard = writer_arc.lock().await;
                writer_guard.write_all("Пользователь не найден. Хотите зарегистрироваться? (да/нет):\n".as_bytes()).await?;
                writer_guard.flush().await?;
                let mut answer = String::new();
                if reader.read_line(&mut answer).await? == 0 {
                    log_message("Client", "Клиент отключился во время запроса регистрации.", Color::Yellow).await?;
                    return Err("Клиент отключился во время регистрации".into());
                }
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
                    log_message("Auth", &format!("Пользователь '{}' зарегистрировался.", nickname), Color::Green).await?;
                    break; // Выходим из цикла авторизации
                } else {
                    writer_guard.write_all("Попробуйте снова.\n".as_bytes()).await?;
                    writer_guard.flush().await?;
                    attempts -= 1; // Уменьшаем количество попыток
                    log_message("Auth", &format!("Пользователь '{}' отклонил регистрацию. Осталось попыток: {}", nick_input, attempts), Color::Yellow).await?;
                }
            }
            Some(_) => {
                // Неверный пароль
                let mut writer_guard = writer_arc.lock().await;
                writer_guard.write_all("Неверный пароль. Попробуйте снова.\n".as_bytes()).await?;
                writer_guard.flush().await?;
                attempts -= 1; // Уменьшаем количество попыток
                log_message("Auth", &format!("Пользователь '{}' ввел неверный пароль. Осталось попыток: {}", nick_input, attempts), Color::Yellow).await?;
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
            log_message("Auth", &format!("Обнаружен дубликат никнейма '{}'. Отключение клиента.", nickname), Color::Red).await?;
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
    log_message("Auth", &join_msg, Color::Yellow).await?;
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
                        log_message("Client", &format!("{}: Клиент отключился (прочитано 0 байт).", nickname_read), Color::Cyan).await?;
                        break Ok(()); // Завершаем задачу успешно
                    },
                    Ok(n) => n, // Успешно прочитано(кол-во байт)
                    Err(e) => { // Ошибка чтения
                        log_message("Error", &format!("Ошибка чтения от {}: {}", nickname_read, e), Color::Red).await?;
                        break Err(e.into()); // Завершаем задачу с ошибкой
                    },
                };

                let msg_trimmed = line.trim();
                if msg_trimmed.is_empty() { continue; } // Пропускаем пустые строки

                // Проверка на команду "выход" из приватного чата
                if msg_trimmed.to_lowercase() == "выход" {
                    let mut state_guard = client_state_read.lock().await; // Захватываем мьютекс
                    if let ClientState::InPrivateChat { with_nick, shared_key: _ } = &*state_guard {
                        let partner_nick = with_nick.clone();
                        *state_guard = ClientState::PublicChat; // Изменяем состояние
                        drop(state_guard); // Освобождаем мьютекс перед await

                        let _ = send_to_user(
                            &connected_users_read,
                            &partner_nick,
                            format!("SYSTEM:PRIVATE_CHAT_ENDED:{}", nickname_read)
                        ).await;

                        let mut writer_guard = writer_arc_clone.lock().await; // Захватываем мьютекс
                        writer_guard.write_all("Вы вышли из личного чата. Возвращение в общий чат.\n".as_bytes()).await?;
                        writer_guard.flush().await?;
                        drop(writer_guard); // Освобождаем мьютекс перед await

                        log_message("info", &format!("'{}' вышел из приватного чата с '{}'", nickname_read, partner_nick), Color::Cyan).await?;
                        continue;
                    }
                    drop(state_guard); // Освобождаем мьютекс, если не в приватном чате
                }

                // Обработка команд (/help, /list, /pm, /accept, /reject)
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
                            drop(users); // Освобождаем мьютекс после использования

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
                                let mut state_guard = client_state_read.lock().await; // Захватываем мьютекс
                                match &mut *state_guard { // Используем &mut * для изменения состояния
                                    ClientState::PublicChat => {
                                        let target_nick = args.to_string();
                                        // Генерируем ключ для приватного чата
                                        let mut key_bytes = [0u8; 32];
                                        OsRng.fill_bytes(&mut key_bytes);
                                        let shared_key = key_bytes.to_vec();
                                        let key_hex = hex::encode(&shared_key);

                                        // Store needed info and drop state_guard before await
                                        let current_nickname = nickname_read.clone();
                                        let target_nick_clone = target_nick.clone();
                                        let shared_key_clone = shared_key.clone(); // Clone shared_key for the state change
                                        *state_guard = ClientState::WaitingForPrivateChatResponse { target_nick: target_nick.clone(), sent_key: shared_key_clone };
                                        drop(state_guard); // Освобождаем мьютекс

                                        if send_to_user(&connected_users_read, &target_nick_clone, format!("SYSTEM:PRIVATE_CHAT_REQUEST:{}:{}", current_nickname, key_hex)).await.is_ok() {
                                            let mut writer_guard = writer_arc_clone.lock().await; // Захватываем мьютекс
                                            writer_guard.write_all(format!("Запрос на личный чат отправлен пользователю '{}'. Ожидание ответа...\n", target_nick_clone).as_bytes()).await?;
                                            writer_guard.flush().await?;
                                            drop(writer_guard); // Освобождаем мьютекс
                                            log_message("Private chat", &format!("'{}' запросил приватный чат у '{}'", current_nickname, target_nick_clone), Color::Cyan).await?;
                                        } else {
                                            let mut writer_guard = writer_arc_clone.lock().await; // Захватываем мьютекс
                                            writer_guard.write_all(format!("Пользователь '{}' не найден или не в сети.\n", target_nick_clone).as_bytes()).await?;
                                            writer_guard.flush().await?;
                                            drop(writer_guard); // Освобождаем мьютекс
                                            log_message("Private chat", &format!("'{}' пытался запросить приватный чат у оффлайн пользователя '{}'", current_nickname, target_nick_clone), Color::Red).await?;
                                        }
                                    }
                                    _ => {
                                        let state_for_log = format!("{:?}", *state_guard); // Клонируем для логирования
                                        drop(state_guard); // Освобождаем мьютекс
                                        let mut writer_guard = writer_arc_clone.lock().await; // Захватываем мьютекс
                                        writer_guard.write_all("Вы не можете начать новый личный чат, находясь не в общем чате.\n".as_bytes()).await?;
                                        writer_guard.flush().await?;
                                        drop(writer_guard); // Освобождаем мьютекс
                                        log_message("Private chat", &format!("'{}' пытался инициировать ЛС, находясь не в общем чате (текущее состояние: {})", nickname_read, state_for_log), Color::Red).await?;
                                    }
                                }
                            }
                        }
                        "accept" => {
                            let mut state_guard = client_state_read.lock().await; // Захватываем мьютекс
                            if let ClientState::HasPendingPrivateChatRequest { from_nick, shared_key } = &mut *state_guard {
                                let partner_nick = from_nick.clone();
                                let key_to_use = shared_key.clone(); // Ключ получен с запросом
                                let current_nickname = nickname_read.clone();
                                *state_guard = ClientState::InPrivateChat { with_nick: partner_nick.clone(), shared_key: key_to_use };
                                drop(state_guard); // Освобождаем мьютекс

                                if send_to_user(&connected_users_read, &partner_nick, format!("SYSTEM:PRIVATE_CHAT_ACCEPTED:{}", current_nickname)).await.is_ok() {
                                    let mut writer_guard = writer_arc_clone.lock().await; // Захватываем мьютекс
                                    writer_guard.write_all(format!("Вы начали личный чат с '{}'. Напишите 'выход' для возврата в общий чат.\n", partner_nick).as_bytes()).await?;
                                    writer_guard.flush().await?;
                                    drop(writer_guard); // Освобождаем мьютекс
                                    log_message("Private chat", &format!("'{}' обновил статус: приватный чат с '{}'", current_nickname, partner_nick), Color::Cyan).await?;
                                } else {
                                    let mut writer_guard = writer_arc_clone.lock().await; // Захватываем мьютекс
                                    writer_guard.write_all(format!("Не удалось уведомить '{}', возможно, он отключился. Вы возвращены в общий чат.\n", partner_nick).as_bytes()).await?;
                                    writer_guard.flush().await?;
                                    drop(writer_guard); // Освобождаем мьютекс
                                    log_message("Private chat", &format!("'{}' принял приватный чат от '{}', но не смог уведомить партнера.", current_nickname, partner_nick), Color::Red).await?;
                                    // Re-acquire state_guard to revert state if partner disconnected
                                    let mut state_guard_revert = client_state_read.lock().await;
                                    *state_guard_revert = ClientState::PublicChat;
                                    drop(state_guard_revert); // Освобождаем мьютекс
                                }
                            } else {
                                drop(state_guard); // Освобождаем мьютекс, если нет запроса
                                let mut writer_guard = writer_arc_clone.lock().await; // Захватываем мьютекс
                                writer_guard.write_all("Нет активных запросов на личный чат для принятия.\n".as_bytes()).await?;
                                writer_guard.flush().await?;
                                drop(writer_guard); // Освобождаем мьютекс
                                log_message("Cmd", &format!("'{}' пытался /accept без ожидающего запроса.", nickname_read), Color::Yellow).await?;
                            }
                        }
                        "reject" => {
                            let mut state_guard = client_state_read.lock().await; // Захватываем мьютекс
                            if let ClientState::HasPendingPrivateChatRequest { from_nick, shared_key: _ } = &mut *state_guard {
                                let partner_nick = from_nick.clone();
                                let current_nickname = nickname_read.clone();
                                *state_guard = ClientState::PublicChat; // Изменяем состояние
                                drop(state_guard); // Освобождаем мьютекс

                                if send_to_user(&connected_users_read, &partner_nick, format!("SYSTEM:PRIVATE_CHAT_REJECTED:{}", current_nickname)).await.is_ok() {
                                    let mut writer_guard = writer_arc_clone.lock().await; // Захватываем мьютекс
                                    writer_guard.write_all(format!("Вы отклонили запрос на личный чат от '{}'.\n", partner_nick).as_bytes()).await?;
                                    writer_guard.flush().await?;
                                    drop(writer_guard); // Освобождаем мьютекс
                                    log_message("Private chat", &format!("'{}' отклонил приватный чат от '{}'", current_nickname, partner_nick), Color::Cyan).await?;
                                } else {
                                    let mut writer_guard = writer_arc_clone.lock().await; // Захватываем мьютекс
                                    writer_guard.write_all(format!("Не удалось уведомить '{}' об отклонении, возможно, он отключился.\n", partner_nick).as_bytes()).await?;
                                    writer_guard.flush().await?;
                                    drop(writer_guard); // Освобождаем мьютекс
                                    log_message("Private chat", &format!("'{}' отклонил приватный чат от '{}', но не смог уведомить партнера.", current_nickname, partner_nick), Color::Red).await?;
                                }
                            } else {
                                drop(state_guard); // Освобождаем мьютекс, если нет запроса
                                let mut writer_guard = writer_arc_clone.lock().await; // Захватываем мьютекс
                                writer_guard.write_all("Нет активных запросов на личный чат для отклонения.\n".as_bytes()).await?;
                                writer_guard.flush().await?;
                                drop(writer_guard); // Освобождаем мьютекс
                                log_message("Cmd", &format!("'{}' пытался /reject без ожидающего запроса.", nickname_read), Color::Yellow).await?;
                            }
                        }
                        _ => {
                            let mut writer_guard = writer_arc_clone.lock().await; // Захватываем мьютекс
                            writer_guard.write_all(format!("Неизвестная команда: '{}'. Введите /help.\n", command).as_bytes()).await?;
                            writer_guard.flush().await?;
                            drop(writer_guard); // Освобождаем мьютекс
                            log_message("Cmd", &format!("'{}' ввел неизвестную команду: '{}'", nickname_read, command), Color::Red).await?;
                        }
                    }
                }
                // Обработка обычных сообщений или старых личных сообщений
                else {
                    let current_state_clone;
                    {
                        let state_guard = client_state_read.lock().await; // Захватываем мьютекс
                        current_state_clone = state_guard.clone(); // Клонируем состояние для использования после освобождения мьютекса
                    } // state_guard автоматически освобождается здесь

                    match current_state_clone {
                        ClientState::InPrivateChat { with_nick, shared_key } => {
                            let cipher = Aes256Gcm::new_from_slice(&shared_key).expect("Key length is 32 bytes");
                            let mut nonce_array = [0u8; 12]; // GCM nonces are 12 bytes
                            OsRng.fill_bytes(&mut nonce_array);
                            let nonce = Nonce::from_slice(&nonce_array);

                            let ciphertext_result = cipher.encrypt(&nonce, msg_trimmed.as_bytes());
                            match ciphertext_result {
                                Ok(ciphertext) => {
                                    let encrypted_msg = format!(
                                        "SYSTEM:ENCRYPTED_PRIVATE_MSG:{}:{}:{}",
                                        nickname_read,
                                        hex::encode(nonce_array), // Кодируем массив nonce в hex
                                        hex::encode(ciphertext) // Кодируем зашифрованный текст в hex
                                    );
                                    if send_to_user(&connected_users_read, &with_nick, encrypted_msg).await.is_ok() {
                                        log_message("Private", &format!("'{}' отправил зашифрованное ЛС '{}'", nickname_read, with_nick), Color::Blue).await?;
                                    } else {
                                        let mut writer_guard = writer_arc_clone.lock().await; // Захватываем мьютекс
                                        writer_guard.write_all(format!("Не удалось отправить сообщение '{}'. Возможно, пользователь отключился. Вы возвращены в общий чат.\n", with_nick).as_bytes()).await?;
                                        writer_guard.flush().await?;
                                        drop(writer_guard); // Освобождаем мьютекс
                                        log_message("Private", &format!("'{}' не смог отправить зашифрованное ЛС '{}'. Партнер отключился.", nickname_read, with_nick), Color::Red).await?;
                                        // Re-acquire state_guard to change state
                                        let mut state_guard_revert = client_state_read.lock().await; // Захватываем мьютекс
                                        *state_guard_revert = ClientState::PublicChat;
                                        drop(state_guard_revert); // Освобождаем мьютекс
                                    }
                                }
                                Err(e) => {
                                    log_message("Error", &format!("Ошибка шифрования для {}: {:?}", nickname_read, e), Color::Red).await?;
                                    let mut writer_guard = writer_arc_clone.lock().await; // Захватываем мьютекс
                                    writer_guard.write_all("Ошибка шифрования сообщения. Попробуйте снова.\n".as_bytes()).await?;
                                    writer_guard.flush().await?;
                                    drop(writer_guard); // Освобождаем мьютекс
                                }
                            }
                        }
                        ClientState::PublicChat => {
                            if let Some(idx) = msg_trimmed.find(':') {
                                let recipient = msg_trimmed[..idx].trim().to_string(); // Клонируем
                                let message_content = msg_trimmed[idx + 1..].trim().to_string(); // Клонируем

                                if recipient == nickname_read {
                                     let mut writer_guard = writer_arc_clone.lock().await; // Захватываем мьютекс
                                     writer_guard.write_all("Вы не можете отправить ЛС самому себе.\n".as_bytes()).await?;
                                     writer_guard.flush().await?;
                                     drop(writer_guard); // Освобождаем мьютекс
                                     log_message("MSG", &format!("'{}' пытался отправить ЛС самому себе.", nickname_read), Color::Red).await?;
                                } else {
                                    let full_msg = format!("{} {}: {}\n", "Вам".cyan(), nickname_read, message_content);
                                    if send_to_user(&connected_users_read, &recipient, full_msg).await.is_ok() {
                                        log_message("MSG", &format!("'{}' отправил прямое сообщение '{}'", nickname_read, recipient), Color::Green).await?;
                                    } else {
                                        let mut writer_guard = writer_arc_clone.lock().await; // Захватываем мьютекс
                                        writer_guard.write_all(format!("{} Пользователь '{}' не найден или не в сети.\n", "Ошибка:".red(), recipient).as_bytes()).await?;
                                        writer_guard.flush().await?;
                                        drop(writer_guard); // Освобождаем мьютекс
                                        log_message("MSG", &format!("'{}' не смог отправить прямое сообщение оффлайн пользователю '{}'", nickname_read, recipient), Color::Red).await?;
                                    }
                                }
                            } else {
                                broadcast_message(&connected_users_read, &nickname_read, msg_trimmed, false).await;
                            }
                        }
                        ClientState::WaitingForPrivateChatResponse { target_nick, sent_key: _ } => {
                            let mut writer_guard = writer_arc_clone.lock().await; // Захватываем мьютекс
                            writer_guard.write_all(format!("Вы ожидаете ответа от '{}'. Чтобы отправить сообщение в общий чат, сначала отмените запрос (пока не реализовано) или дождитесь ответа.\n", target_nick).as_bytes()).await?;
                            writer_guard.flush().await?;
                            drop(writer_guard); // Освобождаем мьютекс
                            log_message("Client state", &format!("'{}' пытался отправить сообщение в состоянии WaitingForPrivateChatResponse.", nickname_read), Color::Yellow).await?;
                        }
                        ClientState::HasPendingPrivateChatRequest { from_nick, shared_key: _ } => {
                            let mut writer_guard = writer_arc_clone.lock().await; // Захватываем мьютекс
                            writer_guard.write_all(format!("У вас есть запрос на личный чат от '{}'. Введите /accept или /reject.\n", from_nick).as_bytes()).await?;
                            writer_guard.flush().await?;
                            drop(writer_guard); // Освобождаем мьютекс
                            log_message("Client state", &format!("'{}' пытался отправить сообщение в состоянии HasPendingPrivateChatRequest.", nickname_read), Color::Yellow).await?;
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
                        log_message("Recieve", &format!("Получено write_task ({}): {}", nickname_write, msg.trim()), Color::Yellow).await?;
                        msg
                    },
                    None => { // Канал закрыт, задача записи завершается
                        log_message("Client", &format!("{}: Канал rx_from_others закрыт (write_task завершается).", nickname_write), Color::Cyan).await?;
                        break Ok(()); // Завершаем задачу успешно
                    },
                };

                if msg_str.starts_with("SYSTEM:") {
                    // Разделяем системное сообщение на команду и аргументы
                    let parts: Vec<&str> = msg_str.splitn(2, ':').collect();
                    if parts.len() < 2 {
                        log_message("Error", &format!("Некорректное системное сообщение: {}", msg_str), Color::Red).await?;
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
                                        let mut state_guard = client_state_write.lock().await; // Захватываем мьютекс
                                        match &mut *state_guard {
                                            ClientState::PublicChat => {
                                                *state_guard = ClientState::HasPendingPrivateChatRequest { from_nick: sender_nick.clone(), shared_key };
                                                drop(state_guard); // Освобождаем мьютекс
                                                let mut writer_guard = writer_arc_for_task.lock().await; // Захватываем мьютекс
                                                if writer_guard.write_all(format!("Пользователь '{}' хочет начать с вами личный чат. Введите /accept или /reject.\n", sender_nick).as_bytes()).await.is_err() { break Ok(()); }
                                                writer_guard.flush().await?;
                                                drop(writer_guard); // Освобождаем мьютекс
                                                log_message("Private chat", &format!("'{}' получил запрос на приватный чат от '{}'", nickname_write, sender_nick), Color::Cyan).await?;
                                            }
                                            _ => { // Клиент уже в другом состоянии
                                                drop(state_guard); // Освобождаем мьютекс
                                                let _ = send_to_user(&connected_users_write, &sender_nick, format!("SYSTEM:PRIVATE_CHAT_BUSY:{}", nickname_write)).await;
                                                log_message("Private chat", &format!("'{}' получил запрос на приватный чат от '{}', но был занят.", nickname_write, sender_nick), Color::Yellow).await?;
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        let mut writer_guard = writer_arc_for_task.lock().await; // Захватываем мьютекс
                                        if writer_guard.write_all("Получен некорректный запрос на приватный чат (ошибка ключа).\n".as_bytes()).await.is_err() { break Ok(()); }
                                        writer_guard.flush().await?;
                                        drop(writer_guard); // Освобождаем мьютекс
                                        log_message("Error", &format!("Неверный формат ключа в PRIVATE_CHAT_REQUEST от {}", sender_nick), Color::Red).await?;
                                    }
                                }
                            } else {
                                let mut writer_guard = writer_arc_for_task.lock().await; // Захватываем мьютекс
                                if writer_guard.write_all("Получен некорректный запрос на приватный чат.\n".as_bytes()).await.is_err() { break Ok(()); }
                                writer_guard.flush().await?;
                                drop(writer_guard); // Освобождаем мьютекс
                                log_message("Error", &format!("Некорректный формат PRIVATE_CHAT_REQUEST: {}", msg_str), Color::Red).await?;
                            }
                        }
                        "PRIVATE_CHAT_ACCEPTED" => {
                            let originator_nick = args.to_string();
                            let mut state_guard = client_state_write.lock().await; // Захватываем мьютекс
                            match &mut *state_guard {
                                ClientState::WaitingForPrivateChatResponse { target_nick, sent_key } if target_nick == &originator_nick => {
                                    *state_guard = ClientState::InPrivateChat { with_nick: originator_nick.clone(), shared_key: sent_key.clone() };
                                    drop(state_guard); // Освобождаем мьютекс
                                    let mut writer_guard = writer_arc_for_task.lock().await; // Захватываем мьютекс
                                    if writer_guard.write_all(format!("{} Пользователь '{}' принял ваш запрос на личный чат. Вы теперь в приватном чате.\n", "ИНФО:".green(), originator_nick).as_bytes()).await.is_err() { break Ok(()); }
                                    writer_guard.flush().await?;
                                    drop(writer_guard); // Освобождаем мьютекс
                                    log_message("Private chat", &format!("'{}' обновил статус: приватный чат с '{}'", nickname_write, originator_nick), Color::Cyan).await?;
                                }
                                _ => {
                                    drop(state_guard); // Освобождаем мьютекс
                                    log_message("Error", &format!("Undefined chat accept от {} для {}", originator_nick, nickname_write), Color::Red).await?;
                                    let mut writer_guard = writer_arc_for_task.lock().await; // Захватываем мьютекс
                                    if writer_guard.write_all(format!("Пользователь '{}' принял ваш запрос, но вы не находитесь в ожидающем состоянии. Возможно, чат уже начат или отменен.\n", originator_nick).as_bytes()).await.is_err() { break Ok(()); }
                                    writer_guard.flush().await?;
                                    drop(writer_guard); // Освобождаем мьютекс
                                }
                            }
                        }
                        "PRIVATE_CHAT_REJECTED" => {
                            let originator_nick = args.to_string();
                            let mut state_guard = client_state_write.lock().await; // Захватываем мьютекс
                            match &mut *state_guard {
                                ClientState::WaitingForPrivateChatResponse { target_nick, sent_key: _ } if target_nick == &originator_nick => {
                                    *state_guard = ClientState::PublicChat;
                                    drop(state_guard); // Освобождаем мьютекс
                                    let mut writer_guard = writer_arc_for_task.lock().await; // Захватываем мьютекс
                                    if writer_guard.write_all(format!("{} Пользователь '{}' отклонил ваш запрос на личный чат. Вы возвращены в общий чат.\n", "ИНФО:".green(), originator_nick).as_bytes()).await.is_err() { break Ok(()); }
                                    writer_guard.flush().await?;
                                    drop(writer_guard); // Освобождаем мьютекс
                                    log_message("Private chat", &format!("'{}' отклонил приватный чат от '{}'", originator_nick, nickname_write), Color::Cyan).await?;
                                }
                                _ => {
                                    drop(state_guard); // Освобождаем мьютекс
                                    log_message("Error", &format!("Undefined chat reject от {} для {}", originator_nick, nickname_write), Color::Red).await?;
                                    let mut writer_guard = writer_arc_for_task.lock().await; // Захватываем мьютекс
                                    if writer_guard.write_all(format!("Пользователь '{}' отклонил ваш запрос, но вы не находитесь в ожидающем состоянии. Возможно, чат уже начат или отменен.\n", originator_nick).as_bytes()).await.is_err() { break Ok(()); }
                                    writer_guard.flush().await?;
                                    drop(writer_guard); // Освобождаем мьютекс
                                }
                            }
                        }
                        "PRIVATE_CHAT_ENDED" => {
                            let originator_nick = args.to_string();
                            let mut state_guard = client_state_write.lock().await; // Захватываем мьютекс
                            match &mut *state_guard {
                                ClientState::InPrivateChat { with_nick, shared_key: _ } if with_nick == &originator_nick => {
                                    *state_guard = ClientState::PublicChat;
                                    drop(state_guard); // Освобождаем мьютекс
                                    let mut writer_guard = writer_arc_for_task.lock().await; // Захватываем мьютекс
                                    if writer_guard.write_all(format!("{} Пользователь '{}' вышел из личного чата. Вы возвращены в общий чат.\n", "ИНФО:".green(), originator_nick).as_bytes()).await.is_err() { break Ok(()); }
                                    writer_guard.flush().await?;
                                    drop(writer_guard); // Освобождаем мьютекс
                                    log_message("Private chat", &format!("'{}' вышел из приватного чата с '{}'", originator_nick, nickname_write), Color::Cyan).await?;
                                }
                                _ => {
                                    drop(state_guard); // Освобождаем мьютекс
                                    log_message("Error", &format!("Undefined chat end от {} для {}", originator_nick, nickname_write), Color::Red).await?;
                                }
                            }
                        }
                        "PRIVATE_CHAT_BUSY" => {
                            let originator_nick = args.to_string();
                            let mut state_guard = client_state_write.lock().await; // Захватываем мьютекс
                            match &mut *state_guard {
                                ClientState::WaitingForPrivateChatResponse { target_nick, sent_key: _ } if target_nick == &originator_nick => {
                                    *state_guard = ClientState::PublicChat;
                                    drop(state_guard); // Освобождаем мьютекс
                                    let mut writer_guard = writer_arc_for_task.lock().await; // Захватываем мьютекс
                                    if writer_guard.write_all(format!("{} Пользователь '{}' занят или уже в другом приватном чате. Вы возвращены в общий чат.\n", "ИНФО:".green(), originator_nick).as_bytes()).await.is_err() { break Ok(()); }
                                    writer_guard.flush().await?;
                                    drop(writer_guard); // Освобождаем мьютекс
                                    log_message("Private chat", &format!("'{}' занят для приватного чата с '{}'", originator_nick, nickname_write), Color::Cyan).await?;
                                }
                                _ => {
                                    drop(state_guard); // Освобождаем мьютекс
                                    log_message("Error", &format!("Undefined chat busy от {} для {}", originator_nick, nickname_write), Color::Red).await?;
                                }
                            }
                        }
                        "ENCRYPTED_PRIVATE_MSG" => {
                            let msg_parts: Vec<&str> = args.splitn(3, ':').collect(); // sender_nick:nonce_hex:ciphertext_hex
                            if msg_parts.len() == 3 {
                                let sender_nick = msg_parts[0];
                                let nonce_hex = msg_parts[1];
                                let ciphertext_hex = msg_parts[2];

                                let mut state_guard = client_state_write.lock().await; // Захватываем мьютекс
                                match &mut *state_guard {
                                    ClientState::InPrivateChat { with_nick, shared_key } if with_nick == sender_nick => {
                                        let shared_key_clone = shared_key.clone(); // Клонируем shared_key для использования после освобождения мьютекса
                                        drop(state_guard); // Освобождаем мьютекс

                                        match hex::decode(nonce_hex) {
                                            Ok(nonce_bytes) if nonce_bytes.len() == 12 => { // Проверяем длину nonce
                                                match hex::decode(ciphertext_hex) {
                                                    Ok(ciphertext_bytes) => {
                                                        let cipher = Aes256Gcm::new_from_slice(&shared_key_clone).expect("Key length is 32 bytes");
                                                        let nonce = Nonce::from_slice(&nonce_bytes); // Создаем Nonce из среза
                                                        match cipher.decrypt(nonce, ciphertext_bytes.as_ref()) {
                                                            Ok(plaintext_bytes) => {
                                                                if let Ok(plaintext_msg) = String::from_utf8(plaintext_bytes) {
                                                                    let mut writer_guard = writer_arc_for_task.lock().await; // Захватываем мьютекс
                                                                    if writer_guard.write_all(format!("[ЛС от {}]: {}\n", sender_nick.cyan(), plaintext_msg).as_bytes()).await.is_err() { break Ok(()); }
                                                                    writer_guard.flush().await?;
                                                                    drop(writer_guard); // Освобождаем мьютекс
                                                                    log_message("Private", &format!("'{}' получил зашифрованное ЛС от '{}'", nickname_write, sender_nick), Color::Cyan).await?;
                                                                } else {
                                                                    let mut writer_guard = writer_arc_for_task.lock().await; // Захватываем мьютекс
                                                                    writer_guard.write_all("Получено некорректное UTF-8 сообщение (дешифровка).\n".as_bytes()).await?;
                                                                    writer_guard.flush().await?;
                                                                    drop(writer_guard); // Освобождаем мьютекс
                                                                    log_message("Error", &format!("Ошибка декодирования UTF-8 для {}: {}", nickname_write, sender_nick), Color::Red).await?;
                                                                }
                                                            },
                                                            Err(e) => {
                                                                let mut writer_guard = writer_arc_for_task.lock().await; // Захватываем мьютекс
                                                                writer_guard.write_all("Ошибка дешифрования сообщения. Возможно, ключ неверный.\n".as_bytes()).await?;
                                                                writer_guard.flush().await?;
                                                                drop(writer_guard); // Освобождаем мьютекс
                                                                log_message("Error", &format!("Ошибка дешифрования для {}: {:?}", nickname_write, e), Color::Red).await?;
                                                            }
                                                        }
                                                    },
                                                    Err(e) => {
                                                        let mut writer_guard = writer_arc_for_task.lock().await; // Захватываем мьютекс
                                                        writer_guard.write_all("Получено некорректное зашифрованное сообщение (ошибка hex-декодирования).\n".as_bytes()).await?;
                                                        writer_guard.flush().await?;
                                                        drop(writer_guard); // Освобождаем мьютекс
                                                        log_message("Error", &format!("Ошибка декодирования hex для ciphertext: {:?}", e), Color::Red).await?;
                                                    }
                                                }
                                            },
                                            _ => { // Некорректная длина nonce
                                                let mut writer_guard = writer_arc_for_task.lock().await; // Захватываем мьютекс
                                                writer_guard.write_all("Получено некорректное зашифрованное сообщение (ошибка hex-декодирования nonce или неверная длина).\n".as_bytes()).await?;
                                                writer_guard.flush().await?;
                                                drop(writer_guard); // Освобождаем мьютекс
                                                log_message("Error", &format!("Ошибка декодирования hex для nonce или неверная длина: {:?}", nonce_hex), Color::Red).await?;
                                            }
                                        }
                                    },
                                    _ => { // Клиент не в приватном чате или не с тем партнером
                                        drop(state_guard); // Освобождаем мьютекс
                                        let mut writer_guard = writer_arc_for_task.lock().await; // Захватываем мьютекс
                                        writer_guard.write_all(format!("Получено зашифрованное сообщение от '{}', но вы не находитесь в приватном чате с ним.\n", sender_nick).as_bytes()).await?;
                                        writer_guard.flush().await?;
                                        drop(writer_guard); // Освобождаем мьютекс
                                        log_message("Error", &format!("Получено ENCRYPTED_PRIVATE_MSG от {} для {} в некорректном состоянии.", sender_nick, nickname_write), Color::Red).await?;
                                    }
                                }
                            } else {
                                let mut writer_guard = writer_arc_for_task.lock().await; // Захватываем мьютекс
                                if writer_guard.write_all("Получено некорректное зашифрованное сообщение.\n".as_bytes()).await.is_err() { break Ok(()); }
                                writer_guard.flush().await?;
                                drop(writer_guard); // Освобождаем мьютекс
                                log_message("Error", &format!("Некорректный формат ENCRYPTED_PRIVATE_MSG: {}", msg_str), Color::Red).await?;
                            }
                        }
                        _ => { log_message("Error", &format!("Неизвестная системная команда: {}", command), Color::Red).await?; }
                    }
                } else { // Обычное сообщение (не системное)
                    let display_message;
                    {
                        let state_guard = client_state_write.lock().await; // Захватываем мьютекс
                        display_message = match &*state_guard {
                            ClientState::InPrivateChat {..} => !msg_str.starts_with(&format!("{} ", "Всем".blue())),
                            _ => true,
                        };
                    } // state_guard автоматически освобождается здесь

                    if display_message {
                        let mut writer_guard = writer_arc_for_task.lock().await; // Захватываем мьютекс
                        if writer_guard.write_all(msg_str.as_bytes()).await.is_err() { break Ok(()); }
                        writer_guard.flush().await?;
                        drop(writer_guard); // Освобождаем мьютекс
                    }
                }
            };
            res // Возвращаем результат выполнения задачи
        }
    });

    // Ожидание завершения одной из задач (read_task или write_task)
    tokio::select! {
        res = read_task => {
            if let Err(e) = res { log_message("SYSTEM", &format!("Ошибка в задаче чтения для {}: {:?}", nickname, e), Color::Magenta).await?; }
            log_message("info", &format!("{}: read_task завершилась в select.", nickname), Color::Cyan).await?;
        },
        res = write_task => {
            if let Err(e) = res { log_message("SYSTEM", &format!("Ошибка в задаче записи для {}: {:?}", nickname, e), Color::Magenta).await?; }
            log_message("info", &format!("{}: write_task завершилась в select.", nickname), Color::Cyan).await?;
        },
    }

    // Очистка чата при отключении клиента
    let final_client_state = client_state.lock().await.clone(); // Получаем итоговое состояние клиента
    {
        let mut users_guard = connected_users.lock().await;
        users_guard.remove(&nickname); // Удаляем клиента из списка подключенных
        log_message("Client", &format!("Пользователь '{}' отключился. В сети: {}", nickname, users_guard.len()), Color::Yellow).await?;
    }

    // Если клиент был в приватном чате, уведомляем партнера о выходе
    if let ClientState::InPrivateChat { with_nick, shared_key: _ } = final_client_state {
        let _ = send_to_user(&connected_users, &with_nick, format!("SYSTEM:PRIVATE_CHAT_ENDED:{}", nickname)).await;
        log_message("info", &format!("Уведомлен '{}' о выходе '{}' из их приватного чата", with_nick, nickname), Color::Cyan).await?;
    }

    // Широковещательное сообщение о выходе клиента
    let leave_msg = format!("Пользователь '{}' вышел из чата", nickname);
    broadcast_message(&connected_users, &nickname, &leave_msg, true).await;
    Ok(()) // Успешное завершение handle_client
}
