use std::collections::HashMap;
use tokio::sync::Mutex;
use std::sync::Arc;
use crate::log::log_message;
use colored::Color;
use tokio::sync::mpsc::UnboundedSender;

type Tx = UnboundedSender<String>;

pub async fn broadcast_message(
    connected_users: &Arc<Mutex<HashMap<String, Tx>>>,
    sender: &str,
    message: &str,
    is_system_message: bool,
) {
    let users = connected_users.lock().await;
    for (nick, tx) in users.iter() {
        if nick != sender {
            let full_msg = if is_system_message {
                format!("{}\n", message)
            } else {
                format!("{} {}: {}\n", colored::Colorize::blue("Всем"), sender, message)
            };
            let _ = tx.send(full_msg);
        }
    }
    if !is_system_message {
        log_message("Global message", &format!("'{}' отправил в общий чат: {}", sender, message), Color::Blue).await.unwrap_or_else(|e| eprintln!("Ошибка логирования широковещательного сообщения: {:?}", e));
    }
}

pub async fn send_to_user(
    connected_users: &Arc<Mutex<HashMap<String, Tx>>>,
    recipient_nick: &str,
    message: String,
) -> Result<(), String> {
    let users = connected_users.lock().await;
    if let Some(tx) = users.get(recipient_nick) {
        if tx.send(message.clone()).is_err() {
            let error_msg = format!("Не удалось отправить сообщение пользователю {}", recipient_nick);
            log_message("ERROR", &format!("Канал к пользователю '{}' закрыт. Возможно, клиент отключился. Ошибка: {}", recipient_nick, error_msg), Color::Red).await.unwrap_or_else(|e| eprintln!("Ошибка логирования send_to_user: {:?}", e));
            Err(error_msg)
        } else {
            log_message("Sent", &format!("Сообщение отправлено '{}' : {}", recipient_nick, message.trim_end()), Color::Green).await.unwrap_or_else(|e| eprintln!("Ошибка логирования send_to_user: {:?}", e));
            Ok(())
        }
    } else {
        let error_msg = format!("Пользователь {} не найден или не в сети.", recipient_nick);
        log_message("ERROR", &format!("Пользователь '{}' не найден в connected_users. Ошибка: {}", recipient_nick, error_msg), Color::Red).await.unwrap_or_else(|e| eprintln!("Ошибка логирования send_to_user: {:?}", e));
        Err(error_msg)
    }
}

