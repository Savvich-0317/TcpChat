use std::{
    io::{self, BufRead, BufReader, Write},
    net::TcpListener,
    thread::{self, JoinHandle},
};

use crate::{
    listen::{GetHandshake, PrintStream},
    sender::TcpSender,
};

mod listen;
mod sender;
fn main() {
    println!("TcpChat");

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
            println!("who is we chatting with? Leave blank if we want use handshake");
            std::io::stdin().read_line(&mut addr_to).unwrap();
            println!("who are we?");
            std::io::stdin().read_line(&mut addr_us).unwrap();

            if addr_to.trim().is_empty() {
                let handshake = start_listening_handshake(addr_us.clone()).unwrap();
                let addr_to = &handshake.as_str()[11..];
                println!("Got fellow listener! {addr_to}");

                let thread_listen = start_thread_listener(addr_us.clone());
                let thread_sender = start_thread_sender(addr_to.to_string());

                thread_listen.join().unwrap();
                thread_sender.join().unwrap();
                
            } else {
                //let thread_sender = start_thread_sender(addr_to);
                println!("Sending handshake");
                let thread_listen = start_thread_listener(addr_us.clone());
                send_handshake(addr_to.clone(), addr_us.clone()).unwrap();
                println!("Sended waiting for response with connection");

                let thread_sender = start_thread_sender(addr_to);

                thread_listen.join().unwrap();
                thread_sender.join().unwrap();
            }
        }

        &_ => {}
    }
}
fn send_handshake(addr_to: String, addr_us: String) -> Result<(), String> {
    let mut sender = TcpSender::new(addr_to.trim().to_string(), 60);
    match sender {
        Ok(mut stream) => {
            stream
                .reply(format!("!Handshake!{addr_us}").to_string())
                .unwrap();
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn start_listening_handshake(addr_us: String) -> Result<String, String> {
    let listener = TcpListener::bind(addr_us.trim());
    match listener {
        Ok(_) => {
            println!("Waiting for handshake");
            for stream in listener.unwrap().incoming() {
                println!("Got stream connection for handshake");

                return stream.unwrap().get_handshake();
            }
            Err("No handshake connection even started".to_string())
        }
        Err(_) => Err("No handshake started".to_string()),
    }
}
fn start_thread_listener(addr_us: String) -> JoinHandle<()> {
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
            Err(_) => {
                if addr_us.trim().is_empty() {
                    println!(
                        "This is one sided conversation. You cant receive messages, only send."
                    )
                } else {
                    println!(
                        "Theres a problem setting up listener, check for address availability."
                    )
                }
            }
        }
    });
    thread_listen
}

fn start_thread_sender(addr_to: String) -> JoinHandle<()> {
    let thread_sender = thread::spawn(move || {
        let mut sender = TcpSender::new(addr_to.trim().to_string(), 60); //drops stream if goes out of scope
        match sender {
            Ok(_) => loop {
                let mut message = "".to_string();
                io::stdin().read_line(&mut message).unwrap();
                match sender.as_mut().unwrap().reply(message.to_string()) {
                    Ok(_) => {}
                    Err(e) => println!("{e}"),
                };
            },
            Err(_) => {
                println!("seems like its one sided conversation. You can only receive messages.");
            }
        }
    });
    thread_sender
}
