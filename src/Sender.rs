use std::{fmt::Debug, net::TcpStream, thread, time::Duration};
pub enum SenderErrors {
    SenderConnectionError,
}

pub fn try_to_establish_sender(addr: String, times: u32) -> Result<TcpStream, String> {
    for i in 0..times {
        let mut sender = TcpStream::connect(&addr);
        match sender {
            Ok(sender) => return Ok(sender),
            Err(_) => {
                println!("retrying..{}", i)
            }
        }
        thread::sleep(Duration::from_secs(1));
    }
    Err("SenderErrors::SenderConnectionError".to_string())
}
