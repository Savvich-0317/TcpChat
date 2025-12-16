use std::{fmt::Debug, io::Write, net::TcpStream, thread, time::Duration};
pub enum SenderErrors {
    SenderConnectionError,
}
pub struct TcpSender {
    addr: String,
    Stream: Option<TcpStream>,
}
impl TcpSender {
    pub fn new(addr: String, times: u32) -> Result<TcpSender, String> {
        let mut sender = TcpSender {
            addr: addr.clone(),
            Stream: None,
        };
        sender.connect(addr, times)
    }

    pub fn connect(mut self, addr: String, times: u32) -> Result<TcpSender, String> {
        for i in 0..times {
            match TcpStream::connect(&addr) {
                Ok(stream) => {
                    self.Stream = Some(stream);
                    return Ok(self);
                }
                Err(_) => {}
            }
            thread::sleep(Duration::from_secs(1));
        }
        Err(format!("Failed after {} connects", times).to_string())
    }

    pub fn reply(&mut self, message: String) -> Result<(), String> {
        match self.Stream.as_mut() {
            Some(stream) => match stream.write_all(format!("{message}\n\n").as_bytes()) {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            },
            None => Err("Error while sending a message".to_string()),
        }
    }
}
