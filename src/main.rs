use std::{
    io::{self, Write},
    net::{self, TcpStream},
};

use crate::Sender::TcpSender;

mod Sender;
mod listener;
fn main() {
    println!("choose operation mode 2-sender 1-listener");
    let mut choose = "".to_string();
    io::stdin().read_line(&mut choose).unwrap();

    match choose.trim() {
        "1" => {
            println!("choosed listener");
            let listener = net::TcpListener::bind("localhost:1212").unwrap();

            for stream in listener.incoming() {
                println!("{stream:?}");
            }
        }
        "2" => {
            println!("choosed sender");
            let mut sender = TcpSender::new("localhost:1212".to_string(), 5);
            sender.reply("Hello world!".to_string()).unwrap();
        }
        &_ => {}
    }
}
