use std::{fmt::Debug, io::Write, net::TcpStream, thread, time::Duration};
pub enum SenderErrors {
    SenderConnectionError,
}
pub struct TcpSender {
    addr: String,
    Stream: Box<dyn InternalSends>,
}
impl TcpSender {
    pub fn new(addr: String, times: u32) -> TcpSender {
        let mut sender = TcpSender {
            addr: "addr".to_string(),
            Stream: Box::new(Nothing {}),
        };
        sender.try_to_establish_sender(addr, times).unwrap();
        sender
    }

    pub fn reply(&mut self, message: String) -> Result<(), &str> {
        self.Stream.reply(message)
    }
}
struct Nothing {}

trait sends {
    fn try_to_establish_sender(&mut self, addr: String, times: u32) -> Result<(), &str>;
}

impl sends for TcpSender {
    fn try_to_establish_sender(&mut self, addr: String, times: u32) -> Result<(), &str> {
        for i in 0..times {
            let mut sender = TcpStream::connect(&addr);
            match sender {
                Ok(sender) => {
                    self.Stream = Box::new(sender);
                    return Ok(());
                }
                Err(_) => {
                    println!("retrying..{}", i);
                }
            }
            thread::sleep(Duration::from_secs(1));
        }
        Err("Cannot create connection to listener.")
    }
}

trait InternalSends {
    fn reply(&mut self, message: String) -> Result<(), &str>;
}
impl InternalSends for TcpStream {
    fn reply(&mut self, message: String) -> Result<(), &str> {
        match self.write_all(message.as_bytes()) {
            Ok(_) => Ok(()),
            Err(_) => Err("Failed to write a message, probably connection is closed"),
        }
    }
}
impl InternalSends for Nothing {
    fn reply(&mut self, message: String) -> Result<(), &str> {
        Err("There was never connection established")
    }
}
