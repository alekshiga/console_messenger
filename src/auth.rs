use crate::users::add_user_to_file;
use crate::log::log_message;
use std::collections::HashMap;
use tokio::sync::Mutex;
use std::sync::Arc;
use colored::Color;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

pub async fn authorize_user(
    reader: &mut BufReader<OwnedReadHalf>,
    writer: &Arc<Mutex<OwnedWriteHalf>>,
    users_db: Arc<Mutex<HashMap<String, String>>>,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let mut attempts = 3;
    loop {
        if attempts == 0 {
            let mut writer_guard = writer.lock().await;
            writer_guard.write_all("Превышено количество попыток. Отключение.\n".as_bytes()).await?;
            writer_guard.flush().await?;
            log_message("Auth", "Неудачная авторизация: Превышено количество попыток.", Color::Red).await?;
            return Err("Неудачная авторизация".into());
        }

        let mut nick_input = String::new();
        {
            let mut writer_guard = writer.lock().await;
            writer_guard.write_all("Введите никнейм:\n".as_bytes()).await?;
            writer_guard.flush().await?;
        }
        if reader.read_line(&mut nick_input).await? == 0 {
            log_message("Client", "Клиент отключился до авторизации (ввод никнейма).", Color::Yellow).await?;
            return Err("Клиент отключился до авторизации".into());
        }
        let nick_input = nick_input.trim().to_string();

        let mut pass_input = String::new();
        {
            let mut writer_guard = writer.lock().await;
            writer_guard.write_all("Введите пароль:\n".as_bytes()).await?;
            writer_guard.flush().await?;
        }
        if reader.read_line(&mut pass_input).await? == 0 {
            log_message("Client", "Клиент отключился до авторизации (ввод пароля).", Color::Yellow).await?;
            return Err("Клиент отключился до авторизации".into());
        }
        let pass_input = pass_input.trim().to_string();

        let mut db_guard = users_db.lock().await;
        match db_guard.get(&nick_input) {
            Some(stored_pass) if *stored_pass == pass_input => {
                let mut writer_guard = writer.lock().await;
                writer_guard.write_all("Авторизация успешна!\n".as_bytes()).await?;
                writer_guard.flush().await?;
                log_message("Auth", &format!("Пользователь '{}' авторизовался успешно.", nick_input), Color::Green).await?;                
                return Ok(nick_input);
            }
            None => {
                let mut writer_guard = writer.lock().await;
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
                    drop(db_guard);
                    add_user_to_file("users.txt", &nick_input, &pass_input).await?;
                    let mut writer_guard = writer.lock().await;
                    writer_guard.write_all("Регистрация успешна! Вы авторизованы.\n".as_bytes()).await?;
                    writer_guard.flush().await?;
                    log_message("Auth", &format!("Пользователь '{}' зарегистрировался.", nick_input), Color::Green).await?;
                    return Ok(nick_input);
                } else {
                    writer_guard.write_all("Попробуйте снова.\n".as_bytes()).await?;
                    writer_guard.flush().await?;
                    attempts -= 1;
                    log_message("Auth", &format!("Пользователь '{}' отклонил регистрацию. Осталось попыток: {}", nick_input, attempts), Color::Yellow).await?;
                }
            }
            Some(_) => {
                let mut writer_guard = writer.lock().await;
                writer_guard.write_all("Неверный пароль. Попробуйте снова.\n".as_bytes()).await?;
                writer_guard.flush().await?;
                attempts -= 1;
                log_message("Auth", &format!("Пользователь '{}' ввел неверный пароль. Осталось попыток: {}", nick_input, attempts), Color::Yellow).await?;
            }
        }
    }
}
