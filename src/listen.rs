use std::{
    io::{BufRead, BufReader},
    net::TcpStream,
};
use term_size;
pub trait PrintStream {
    fn print_stream(&self);
}
pub trait GetHandshake {
    fn get_handshake(&self) -> Result<String, String>;
}
impl PrintStream for TcpStream {
    fn print_stream(&self) {
        let status = "//from conversator";
        let buf_reader = BufReader::new(self);

        for line in buf_reader.lines() {
            match line {
                Ok(msg) => println!(
                    "{}",
                    msg.to_string()
                        + " "
                            .repeat(term_size::dimensions().unwrap().0 - msg.len() - status.len())
                            .as_str()
                        + status
                ),
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
            Ok(handshake)
        } else {
            Err("no greet".to_string())
        }
    }
}
