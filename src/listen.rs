use std::{
    io::{BufRead, BufReader},
    net::TcpStream,
};

pub trait PrintStream{
    fn print_stream(&self);
}

impl PrintStream for TcpStream {
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

