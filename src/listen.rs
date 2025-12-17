use std::{
    io::{BufRead, BufReader},
    net::TcpStream,
};

pub trait print_stream{
    fn print_stream(&self);
}

impl print_stream for TcpStream {
    fn print_stream(&self) {
        let buf_reader = BufReader::new(self);
    
        for line in buf_reader.lines() {
            match line {
                Ok(msg) => println!("{}", msg.to_string()),
                Err(_) => break,
            }
        }
    }
}

