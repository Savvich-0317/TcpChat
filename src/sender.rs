use std::{ io::Write, net::TcpStream, thread, time::Duration};

pub struct TcpSender {
    addr: String,
    pub stream: Option<TcpStream>,
}
impl TcpSender {
    pub fn new(addr: String, times: u32) -> Result<TcpSender, String> {
        let mut sender = TcpSender {
            addr: addr.clone(),
            stream: None,
        };
        sender.connect(addr, times)
    }

    pub fn connect(mut self, addr: String, times: u32) -> Result<TcpSender, String> {
        for _ in 0..times {
            match TcpStream::connect(&addr) {
                Ok(stream) => {
                    self.stream = Some(stream);
                    return Ok(self);
                }
                Err(_) => {}
            }
            thread::sleep(Duration::from_secs(1));
        }
        Err(format!("Failed after {} connects", times).to_string())
    }

    pub fn reply(&mut self, message: String) -> Result<(), String> {
        if self.stream.is_some() {
            let stream = self.stream.as_mut().unwrap();

            match stream.write_all(message.as_bytes()) {
                Ok(_) => {
                    stream.flush().expect("Error with flush unexpected");
                    //println!("{:?}", stream.take_error().unwrap());
                    match stream.take_error().unwrap() {
                        Some(_) => Err("Connection seems to be dropped".to_string()),
                        None => Ok(()),
                    }
                }
                Err(_) => Err("there was error sending a message".to_string()),
            }
        } else {
            Err("there was no connection".to_string())
        }
    }
}
