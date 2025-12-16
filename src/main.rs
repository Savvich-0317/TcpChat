use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{self, TcpListener, TcpStream},
    thread,
    time::Duration,
};

use crate::Sender::TcpSender;

mod Listener;
mod Sender;
fn main() {
    println!("choose operation mode 2-sender 1-listener");
    let mut choose = "".to_string();
    io::stdin().read_line(&mut choose).unwrap();

    match choose.trim() {
        "1" => {
            let listener = TcpListener::bind("localhost:1212").unwrap();

            for stream in listener.incoming() {
                println!("Got stream connection");
                let stream = stream.unwrap();
                let buf_reader = BufReader::new(&stream);

                for line in buf_reader.lines() {
                    match line {
                        Ok(msg) => println!("{}", msg),
                        Err(_) => break,
                    }
                }
                println!("Finished");
            }
        }
        "2" => {
            println!("choosed sender");
            let mut sender = TcpSender::new("localhost:1212".to_string(), 5).unwrap();
            sender.reply("aboba".to_string()).unwrap();
        }
        &_ => {}
    }
}
