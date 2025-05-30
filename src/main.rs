mod auth;
mod client;
mod log;
mod message;
mod users;
use tokio::net::TcpListener;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;
use std::error::Error;
use log::log_message;
use users::{load_users};
use client::handle_client;

#[tokio::main]

async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    #[cfg(windows)]
    {
        use std::process::Command;
        let _ = Command::new("cmd")
            .args(&["/C", "chcp 65001"])
            .status();
    }

    let _ = tokio::fs::File::create("server.log").await?;
    log_message("Server", "Файл логов инициализирован.", colored::Color::White).await?;

    let users_db = Arc::new(Mutex::new(load_users("users.txt").await?));
    let connected_users = Arc::new(Mutex::new(HashMap::new()));

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    log_message("Server", "Сервер запущен на 127.0.0.1:8080", colored::Color::Green).await?;

    loop {
        let (socket, addr) = listener.accept().await?;
        log_message("Info", &format!("Новое подключение: {}", addr), colored::Color::Yellow).await?;

        let users_db_clone = users_db.clone();
        let connected_users_clone = connected_users.clone();

        tokio::spawn(async move {
            let client_addr = addr;
            match handle_client(socket, users_db_clone, connected_users_clone).await {
                Ok(_) => {
                    let _ = log_message("Client", &format!("Клиент {} отключился корректно.", client_addr), colored::Color::Yellow).await;
                },
                Err(e) => {
                    let _ = log_message("ERROR", &format!("Ошибка с клиентом {}: {:?} Клиент отключился с ошибкой.", client_addr, e), colored::Color::Red).await;
                },
            }
        });
    }
}