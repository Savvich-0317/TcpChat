use std::{
    io::{self, BufRead, BufReader},
    net::TcpListener,
};

use crate::{listen::PrintStream, sender::TcpSender};

mod listen;
mod sender;
fn main() {
    println!("choose operation mode 2-sender 1-listener");
    let mut choose = "".to_string();
    io::stdin().read_line(&mut choose).unwrap();

    match choose.trim() {
        "1" => {
            let listener = TcpListener::bind("localhost:1212").unwrap();

            for stream in listener.incoming() {
                println!("Got stream connection");
                stream.unwrap().print_stream();
            }
        }
        "2" => {
            println!("choosed sender");
            let mut sender = TcpSender::new("localhost:1212".to_string(), 5).unwrap(); //drops stream if goes out of scope

            loop {
                let mut message = "".to_string();
                io::stdin().read_line(&mut message).unwrap();
                sender.reply(message.to_string()).unwrap();
            }
        }
        &_ => {}
    }
}
