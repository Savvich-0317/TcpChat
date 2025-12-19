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
        "3" => {                                                                           //2121
            let thread_listen = thread::spawn(||{let listener = TcpListener::bind("localhost:1212").unwrap();

            for mut stream in listener.incoming() {
                println!("Got stream connection");
                stream.unwrap().print_stream();
                println!("connection closed");
            }});
                                                                                          //1212
            let thread_sender = thread::spawn(||{let mut sender = TcpSender::new("localhost:2121".to_string(), 5).unwrap(); //drops stream if goes out of scope

            loop {
                let mut message = "".to_string();
                io::stdin().read_line(&mut message).unwrap();
                sender.reply(message.to_string()).unwrap();
            }});
            thread_listen.join().unwrap();
            thread_sender.join().unwrap();
        }
        &_ => {}
    }
}
