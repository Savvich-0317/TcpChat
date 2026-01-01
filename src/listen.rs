use std::{
    io::{BufRead, BufReader},
    net::TcpStream,
};
use term_size;

use crate::decrypt_message;
pub trait PrintStream {
    fn print_stream(&self, private_us: String);
}
pub trait GetHandshake {
    fn get_handshake(&self) -> Result<String, String>;
}
impl PrintStream for TcpStream {
    fn print_stream(&self, private_us: String) {
        let mut status = "//from conversator";
        let buf_reader = BufReader::new(self);
        let private = private_us.clone();
        for line in buf_reader.lines() {
            match line {
                Ok(mut msg) => {
                    if !private.clone().is_empty() {
                        msg = decrypt_message(msg.clone(), private.clone())
                            .trim()
                            .to_string();
                        status = "//decrypted / from convensator";
                    }
                    let width = term_size::dimensions().unwrap().0;
                    if msg.len() % width < width - status.len() {
                        println!(
                            "{}",
                            msg.to_string()
                                + " "
                                    .repeat(width - msg.len() % width - status.len())
                                    .as_str()
                                + status
                        )
                    } else {
                        println!("{msg}\n{}{status}", " ".repeat(width - status.len()));
                    }
                }
                Err(_) => break,
            }
        }
    }
}
impl GetHandshake for TcpStream {
    fn get_handshake(&self) -> Result<String, String> {
        let mut buf_reader = BufReader::new(self);
        let mut handshake = "".to_string();
        buf_reader.read_line(&mut handshake).unwrap();
        if handshake.contains("!Handshake!") {
            //println!("GETHANDSHAKE DEBUG {handshake}");
            Ok(handshake)
        } else {
            Err("no greet".to_string())
        }
    }
}
