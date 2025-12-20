use std::{
    io::{self, BufRead, BufReader, Write},
    net::TcpListener,
    thread,
};

use crate::{listen::PrintStream, sender::TcpSender};

mod listen;
mod sender;
fn main() {
    println!("choose operation mode 2-sender 1-listener 3 - client + server");
    let mut choose = "".to_string();
    io::stdin().read_line(&mut choose).unwrap();

    match choose.trim() {
        "1" => {
            let listener = TcpListener::bind("localhost:1212").unwrap();

            for mut stream in listener.incoming() {
                println!("Got stream connection");
                stream.unwrap().print_stream();
                println!("connection closed");
            }
        }
        "2" => {
            let mut sender = TcpSender::new("localhost:1212".to_string(), 5).unwrap(); //drops stream if goes out of scope

            loop {
                let mut message = "".to_string();
                io::stdin().read_line(&mut message).unwrap();
                sender.reply(message.to_string()).unwrap();
            }
        }
        "3" => {
            let mut addr_us = "".to_string(); //localhost:2121
            let mut addr_to = "".to_string(); //localhost:1212
            println!("who is we chatting with? Leave blank if we want only receive");
            std::io::stdin().read_line(&mut addr_to).unwrap();
            println!("who are we? Leave blank if we want only send and not receive");
            std::io::stdin().read_line(&mut addr_us).unwrap();

            let thread_listen = thread::spawn(move || {
                let listener = TcpListener::bind(addr_us.trim());
                match listener {
                    Ok(_) => {
                        for stream in listener.unwrap().incoming() {
                            println!("Got stream connection");
                            stream.unwrap().print_stream();
                            println!("connection closed");
                        }
                        
                    }
                    Err(_) => println!(
                        "This is one sided conversation. You cant receive messages, only send."
                    ),
                }
            });
            //1212
            let thread_sender = thread::spawn(move || {
                let mut sender = TcpSender::new(addr_to.trim().to_string(), 5); //drops stream if goes out of scope
                match sender {
                    Ok(_) => loop {
                        let mut message = "".to_string();
                        io::stdin().read_line(&mut message).unwrap();
                        sender.as_mut().unwrap().reply(message.to_string()).unwrap();
                    },
                    Err(_) => {
                        println!(
                            "seems like its one sided conversation. You can only receive messages."
                        );
                    }
                }
            });
            thread_listen.join().unwrap();
            thread_sender.join().unwrap();
        }
        &_ => {}
    }
}
