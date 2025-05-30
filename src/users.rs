use std::collections::HashMap;
use std::error::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::fs::{File as TokioFile, OpenOptions as TokioOpenOptions};
use std::path::Path;
use crate::log::log_message;
use colored::Color;

pub async fn load_users(path: &str) -> Result<HashMap<String, String>, Box<dyn Error + Send + Sync>> {
    let mut users = HashMap::new();
    let path_obj = Path::new(path);

    if !path_obj.exists() {
        TokioFile::create(path).await?;
        log_message("Info", &format!("Создан пустой файл пользователей: {}", path), Color::Blue).await?;
        return Ok(users);
    }

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
    log_message("Info", &format!("Загружено {} пользователей из {}", users.len(), path), Color::Green).await?;
    Ok(users)
}

pub async fn add_user_to_file(path: &str, username: &str, password: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut file = TokioOpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .await?;
    file.write_all(format!("{}:{}\n", username, password).as_bytes()).await?;
    file.flush().await?;
    log_message("Auth", &format!("Пользователь '{}' зарегистрирован и добавлен в файл.", username), Color::Green).await?;
    Ok(())
}