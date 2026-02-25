use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::TcpStream,
};

use chrono::{Local, Timelike, Utc};

use crate::decrypt_message;

pub fn timestamp(addr_to: String) {
    let mut chat_log = match std::fs::exists(format!("history/{addr_to}.txt")) {
        Ok(true) => {
            let mut buffer = "".to_string();
            std::fs::File::open(format!("history/{addr_to}.txt"))
                .unwrap()
                .read_to_string(&mut buffer)
                .unwrap();
            let mut chat_log = std::fs::File::create(format!("history/{addr_to}.txt"))
                .expect("failed to create a file");
            chat_log.write_all(buffer.as_bytes()).unwrap();
            chat_log
        }

        _ => {
            let mut chat_log = std::fs::File::create(format!("history/{addr_to}.txt"))
                .expect("failed to create a file");
            chat_log
        }
    };
    chat_log
        .write_all(format!("\n<new conversation on {}>\n\n", Utc::now().to_rfc3339()).as_bytes())
        .unwrap();
}
pub trait SaveStream {
    fn save_stream(&self, addr_to: &str, private_us: &str);
}
pub trait LogMessage {
    fn log_message(&self, addr_to: &str, private_us: &str);
}
pub trait PrintMessage {
    fn print_message(&self, private_us: String);
}
impl PrintMessage for String {
    fn print_message(&self, private_us: String) {
        let time = format!("{}:{}", Local::now().hour(), Local::now().minute());
        let mut status = "/from conversator".to_string();
        let private = private_us.clone();
        let mut msg = self.clone();
        if !private.clone().is_empty() {
            msg = decrypt_message(msg.clone(), private.clone())
                .trim()
                .to_string();
            status = "/decrypted / from convensator".to_string();
        }
        status = format!("// {time} {status}");
        let width = term_size::dimensions().unwrap().0;

        if msg.len() % width < width - status.len() {
            let content = format!(
                "{}",
                msg.to_string()
                    + " "
                        .repeat(width - msg.len() % width - status.len())
                        .as_str()
                    + status.as_str()
            );
            println!("{content}");
        } else {
            let content = format!("{msg}\n{}{status}", " ".repeat(width - status.len()));
            println!("{content}");
        }
    }
}

pub fn print_log(addr_to: &str) -> Result<(), &str> {
    match std::fs::exists(format!("history/{addr_to}.txt")) {
        Ok(true) => {
            let mut buffer = "".to_string();
            std::fs::File::open(format!("history/{addr_to}.txt"))
                .unwrap()
                .read_to_string(&mut buffer)
                .unwrap();
            let width = term_size::dimensions().unwrap().0;
            for line in buffer.trim().split("\n") {
                let msg = line[..line.find(" //").unwrap_or_default()].to_string();
                let status = line[line.find(" //").unwrap_or_default()..].to_string();
                if msg.len() % width < width - status.len() {
                    let content = format!(
                        "{}",
                        msg.to_string()
                            + " "
                                .repeat(width - msg.len() % width - status.len())
                                .as_str()
                            + status.as_str()
                    );
                    println!("{content}");
                } else {
                    let content = format!("{msg}\n{}{status}", " ".repeat(width - status.len()));
                    println!("{content}");
                }
            }
            Ok(())
        }
        _ => Err("There is no history for that adress."),
    }
}
impl LogMessage for String {
    fn log_message(&self, addr_to: &str, private_us: &str) {
        let mut chat_log = match std::fs::exists(format!("history/{addr_to}.txt")) {
            Ok(true) => {
                let mut buffer = "".to_string();
                std::fs::File::open(format!("history/{addr_to}.txt"))
                    .unwrap()
                    .read_to_string(&mut buffer)
                    .unwrap();
                let mut chat_log = std::fs::File::create(format!("history/{addr_to}.txt"))
                    .expect("failed to create a file");
                chat_log.write_all(buffer.as_bytes());
                chat_log
            }

            _ => {
                let mut chat_log = std::fs::File::create(format!("history/{addr_to}.txt"))
                    .expect("failed to create a file");
                chat_log
            }
        };
        let mut status = "/from conversator".to_string();
        let time = format!("{}:{}", Local::now().hour(), Local::now().minute());
        let private = private_us.clone();
        let mut msg = self.to_string();
        if !private.clone().is_empty() {
            msg = decrypt_message(msg.clone(), private.to_string())
                .trim()
                .to_string();
            status = "/decrypted / from convensator".to_string();
        }
        status = "// ".to_string() + time.to_string().as_str() + status.as_str();
        let width = term_size::dimensions().unwrap().0;

        chat_log
            .write_all(format!("{msg} {status}\n").as_bytes())
            .expect("cant write to log");
    }
}

impl SaveStream for TcpStream {
    fn save_stream(&self, addr_to: &str, private_us: &str) {
        let mut chat_log = match std::fs::exists(format!("history/{addr_to}.txt")) {
            Ok(true) => {
                let mut buffer = "".to_string();
                std::fs::File::open(format!("history/{addr_to}.txt"))
                    .unwrap()
                    .read_to_string(&mut buffer)
                    .unwrap();
                let mut chat_log = std::fs::File::create(format!("{addr_to}.txt"))
                    .expect("failed to create a file");

                chat_log
            }

            _ => {
                let mut chat_log = std::fs::File::create(format!("{addr_to}.txt"))
                    .expect("failed to create a file");
                chat_log
            }
        };
        let mut status = "/from conversator".to_string();
        let time = format!("{}:{}", Local::now().hour(), Local::now().minute());
        let buf_reader = BufReader::new(self);
        let private = private_us.clone();
        for line in buf_reader.lines() {
            match line {
                Ok(mut msg) => {
                    if !private.clone().is_empty() {
                        msg = decrypt_message(msg.clone(), private.to_string())
                            .trim()
                            .to_string();
                        status = "/decrypted / from convensator".to_string();
                    }
                    status = "// ".to_string() + time.to_string().as_str() + status.as_str();
                    let width = term_size::dimensions().unwrap().0;

                    chat_log
                        .write_all(format!("{msg} {status}\n").as_bytes())
                        .expect("cant write to log");
                }
                Err(_) => break,
            }
        }
    }
}
