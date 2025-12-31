use base64::{Engine as _, engine::general_purpose};
use std::{
    clone, fs,
    io::{self, BufRead, BufReader, Write},
    net::TcpListener,
    thread::{self, JoinHandle},
};

use rsa::{
    Oaep, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    rand_core::OsRng,
};
use sha2::Sha256;

use crate::{
    listen::{GetHandshake, PrintStream},
    sender::TcpSender,
};

mod listen;
mod sender;
fn main() {
    println!("TcpChat");

    //ssh-keygen -t rsa -b 4096 -m PKCS8 -f rsa_key -N ""
    let mut private = "".to_string();
    match fs::read_to_string("rsa_key") {
        Ok(text) => private = text.to_string(),
        Err(_) => {
            println!("There is no RSA private key in running dir, there will be no decryption.")
        }
    }

    let mut public = "".to_string();
    match fs::read_to_string("rsa_key_public.pem") {
        Ok(text) => public = text,
        Err(_) => {
            println!("There is no RSA public key in running dir, there will be no encryption.")
        }
    }

    let message = "lol aboba";
    let encrypt = encrypt_message(message.to_string(), public.clone());
    println!("{}", encrypt);
    println!("{}", decrypt_message(encrypt, private.clone()));

    println!("choose operation mode 2-sender 1-listener 3 - client + server");

    let mut choose = "".to_string();
    io::stdin().read_line(&mut choose).unwrap();

    match choose.trim() {
        "1" => {
            let listener = TcpListener::bind("localhost:1212").unwrap();

            for mut stream in listener.incoming() {
                println!("Got stream connection");
                stream.unwrap().print_stream(private.clone());
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

        "3" => {
            let mut addr_us = "".to_string(); //localhost:2121
            let mut addr_to = "".to_string(); //localhost:1212
            println!("who is we chatting with? Leave blank if we want use handshake");
            std::io::stdin().read_line(&mut addr_to).unwrap();
            println!("who are we?");
            std::io::stdin().read_line(&mut addr_us).unwrap();
            addr_to = addr_to.trim().to_string();
            addr_us = addr_us.trim().to_string();

            if addr_to.trim().is_empty() {
                let handshake = start_listening_handshake(addr_us.as_str()).unwrap();
                let begin_public = handshake.find("public:").unwrap();
                let addr_to = &handshake.as_str()[14..begin_public];
                let public_conv = &handshake.as_str()[begin_public + 8..&handshake.len() - 1]
                    .replace("\\n", "\n");
                println!(
                    "gotted handshake! from {addr_to}\nand public {}",
                    public_conv
                );
                println!("{}", public_conv);
                send_handshake(addr_to.to_string(), addr_us.clone(), public.clone()).unwrap();
                println!("sended handshake");

                let thread_listen = start_thread_listener(addr_us.clone(),private.clone());
                let thread_sender = start_thread_sender(addr_to.to_string(), public_conv.clone());

                thread_listen.join().unwrap();
                thread_sender.join().unwrap();
            } else {
                //let thread_sender = start_thread_sender(addr_to);
                println!("Sending handshake");
                let addr_us_clone = addr_us.clone();

                let handshake_thread = thread::spawn(move || {
                    start_listening_handshake(addr_us_clone.as_str()).unwrap()
                });
                send_handshake(addr_to.clone(), addr_us.clone(), public.clone()).unwrap();
                println!("sended handshake");

                let handshake = handshake_thread.join().unwrap();
                let begin_public = handshake.find("public:").unwrap();
                let addr_to = &handshake.as_str()[14..begin_public];
                let public_conv = &handshake.as_str()[begin_public + 8..&handshake.len() - 1]
                    .replace("\\n", "\n");
                println!(
                    "gotted handshake! from {addr_to}\nand public {}",
                    public_conv
                );

                println!("to {addr_to} us {addr_us}");

                let thread_listen = start_thread_listener(addr_us.clone(),private.clone());
                let thread_sender =
                    start_thread_sender(addr_to.to_string(), public_conv.to_string());

                thread_listen.join().unwrap();
                thread_sender.join().unwrap();
            }
        }

        &_ => {}
    }
}
fn encrypt_message(message: String, public_to: String) -> String {
    let pub_key =
        RsaPublicKey::from_public_key_pem(public_to.as_str()).expect("unable to read pub_key");
    let mut rng = OsRng;
    let encrypted = pub_key
        .encrypt(&mut rng, Oaep::new::<Sha256>(), message.as_bytes())
        .unwrap();
    let encrypted_b64 = general_purpose::STANDARD.encode(&encrypted);
    encrypted_b64
}
fn decrypt_message(message: String, private_us: String) -> String {
    let decrypted_b64 = general_purpose::STANDARD
        .decode(&message)
        .expect("Failed to decode base64");
    let priv_key =
        RsaPrivateKey::from_pkcs8_pem(private_us.as_str()).expect("unable to read priv_key");
    let decrypted = priv_key
        .decrypt(Oaep::new::<Sha256>(), &decrypted_b64)
        .unwrap();
    String::from_utf8(decrypted).unwrap()
}

fn send_handshake(addr_to: String, addr_us: String, public_key: String) -> Result<(), String> {
    let mut sender = TcpSender::new(addr_to.to_string(), 60);
    let handshake = format!("!Handshake!ip:{}public:{:?}", addr_us, public_key.trim()).to_string();
    match sender {
        Ok(mut stream) => {
            stream.reply(handshake).unwrap();
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn start_listening_handshake(addr_us: &str) -> Result<String, String> {
    let listener = TcpListener::bind(addr_us);
    match listener {
        Ok(_) => {
            println!("Waiting for handshake");
            for stream in listener.unwrap().incoming() {
                println!("Got stream connection for handshake");

                return stream.unwrap().get_handshake();
            }
            Err("No handshake connection even started".to_string())
        }
        Err(_) => Err("No handshake started".to_string()),
    }
}
fn start_thread_listener(addr_us: String, private_us: String) -> JoinHandle<()> {
    let thread_listen = thread::spawn(move || {
        let listener = TcpListener::bind(addr_us.clone());
        match listener {
            Ok(_) => {
                for stream in listener.unwrap().incoming() {
                    println!("Got stream connection");
                    stream.unwrap().print_stream(private_us.clone());
                    println!("connection closed");
                }
            }
            Err(_) => {
                if addr_us.clone().is_empty() {
                    println!(
                        "This is one sided conversation. You cant receive messages, only send."
                    )
                } else {
                    println!(
                        "Theres a problem setting up listener, check for address availability."
                    )
                }
            }
        }
    });
    thread_listen
}

fn start_thread_sender(addr_to: String, public_to: String) -> JoinHandle<()> {
    let thread_sender = thread::spawn(move || {
        let mut sender = TcpSender::new(addr_to.trim().to_string(), 60); //drops stream if goes out of scope
        match sender {
            Ok(_) => loop {
                let mut message = "".to_string();
                io::stdin().read_line(&mut message).unwrap();
                match sender
                    .as_mut()
                    .unwrap()
                    .reply(encrypt_message(message, public_to.clone()) + "\n")
                {
                    Ok(_) => {}
                    Err(e) => println!("{e}"),
                };
            },
            Err(_) => {
                println!("seems like its one sided conversation. You can only receive messages.");
            }
        }
    });
    thread_sender
}
