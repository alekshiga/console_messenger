use std::error::Error;
use tokio::fs::File as TokioFile;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use colored::{Colorize, Color};
use chrono::Local;
use once_cell::sync::Lazy;
use std::sync::Arc;

static LOG_FILE: Lazy<Arc<Mutex<TokioFile>>> = Lazy::new(|| {
    Arc::new(Mutex::new(
        TokioFile::from_std(std::fs::File::create("server.log").expect("Не удалось создать или открыть файл логов"))
    ))
});

pub async fn log_message(log_type: &str, message: &str, color: Color) -> Result<(), Box<dyn Error + Send + Sync>> {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let colored_log_type = format!("[{}]", log_type).color(color);
    let log_entry_console = format!("{} {} {}\n", timestamp, colored_log_type, message);

    println!("{}", log_entry_console.trim_end());

    let mut file_guard = LOG_FILE.lock().await;
    file_guard.write_all(format!("{} [{}] {}\n", timestamp, log_type, message).as_bytes()).await?;
    file_guard.flush().await?;
    Ok(())
}
