use base64::{Engine as _, engine::general_purpose};
use cursive::{
    CbSink, Cursive, CursiveExt, View, backend,
    event::{Event, Key},
    reexports::enumset::__internal::EnumSetTypeRepr,
    utils::lines::simple::Span,
    view::{self, Nameable, Resizable, Scrollable, Selector},
    views::{
        Button, Dialog, DummyView, Layer, LinearLayout, OnEventView, ScrollView, StackView,
        TextArea, TextView,
    },
};
use gag::Gag;
use rand::RngCore;
use rodio::Decoder;

use std::{
    cell::RefCell,
    fs::{self, File, ReadDir},
    io::{self, BufRead, BufReader, Read, Write},
    net::TcpListener,
    path::Display,
    sync::{Arc, LazyLock, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use rsa::{
    Oaep, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    rand_core::OsRng,
};
use sha2::Sha256;

use crate::{
    listen::{GetHandshake, PrintStream},
    logging::{LogMessage, PrintMessage, print_log},
    sender::TcpSender,
};

mod listen;
mod logging;
mod sender;
#[derive(serde::Deserialize, serde::Serialize)]
struct Config {
    addr_us: String,
    encryption: bool,
    save_history: bool,
    tui_interface: bool,
}

struct ReadedData {
    addr_us: String,
    addr_to: String,
}
fn main() {
    println!("TcpChat");

    let content = fs::read_to_string("config.toml").unwrap();
    let mut saved_config: Config = toml::from_str(content.as_str()).unwrap();

    let mut private = "".to_string();
    match fs::read_to_string("rsa_key") {
        Ok(text) => private = text.to_string(),
        Err(_) => {
            println!("There is no RSA private key in running dir.")
        }
    }

    let mut public = "".to_string();
    static CONNECTED: LazyLock<Mutex<String>> = LazyLock::new(|| Mutex::new(String::new()));
    match fs::read_to_string("rsa_key_public.pem") {
        Ok(text) => public = text,
        Err(_) => {
            println!("There is no RSA public key in running dir.")
        }
    }

    if !public.is_empty() && !private.is_empty() {
        println!("There is rsa keys!");
    } else {
        println!(
            "There is no encryption keys! You can generate pair with generate_my_keys.sh in directory!"
        );
    }

    if !saved_config.encryption {
        private = "".to_string();
        public = "".to_string();
        println!("Encryption disabled via config.");
    }
    if !saved_config.save_history {
        println!("History saving disabled via config.");
    }
    /*
            let message = "lol aboba";
            let encrypt = encrypt_message(message.to_string(), public.clone());
            println!("{}", encrypt);
            println!("{}", decrypt_message(encrypt, private.clone()));
    */
    let mut addr_us = "".to_string(); //localhost:2121
    let mut addr_to = "".to_string(); //localhost:1212
    let saved_addr_us = Arc::new(saved_config.addr_us.clone());

    let mut choose = "3".to_string();
    if saved_config.tui_interface {
        let mut siv = Cursive::default();
        siv.set_fps(60);
        let mut files = "".to_string();
        siv.add_fullscreen_layer(TextView::new("TcpChat"));

        let mut layout = LinearLayout::vertical();
        let saved_addr_us = Arc::clone(&saved_addr_us);
        for file in fs::read_dir("history").unwrap() {
            let file_name = file.unwrap().file_name().into_string().unwrap();
            files += format!("{}\n", &file_name).as_str();
            let saved = Arc::clone(&saved_addr_us);
            layout.add_child(Button::new(
                file_name.clone()[..file_name.clone().len() - 4].to_string(),
                move |s| {

                    s.set_user_data(ReadedData {
                        addr_to: file_name.clone()[..file_name.len() - 4].to_string(),
                        addr_us: "".to_string(),
                    });
                    let mut layout = LinearLayout::vertical();
                    if saved.is_empty(){
                        layout.add_child(TextView::new("Adress us?"));
                    }else {
                        layout.add_child(TextView::new(format!("Adress us? Leave empty for {}",saved)));
                    }

                    layout.add_child(TextArea::new().with_name("adress_us_e"));
                    let value = saved.clone();
                    s.add_layer(
                        LinearLayout::horizontal().child(
                        Dialog::new()
                            .title("Are you sure?")
                            .content(layout)
                            .button("Yes", move |s| {
                                let mut addr_us = s.call_on_name("adress_us_e", |v: &mut TextArea| {
                                    v.get_content().to_string()
                                });
                                if addr_us.clone().unwrap().is_empty(){
                                    addr_us = Some(value.to_string());
                                }
                                let data = ReadedData {
                                    addr_to: s.user_data::<ReadedData>().unwrap().addr_to.clone(),
                                    addr_us: addr_us.clone().unwrap(),
                                };
                                s.set_user_data(data);

                                match TcpListener::bind(addr_us.clone().unwrap()) {
                                    Ok(_) => {
                                        s.quit();
                                    }
                                    Err(_) => {
                                        s.pop_layer();
                                        s.add_layer(
                                            Dialog::new()
                                                .title("Error")
                                                .content(TextView::new(format!("The {} adress is cant be binded \nCheck the port availability",addr_us.clone().unwrap())

                                                ))
                                                .button("Okay.", |s| {
                                                    s.pop_layer();
                                                }),
                                        );
                                    }
                                }


                            })
                            .button("Cancel", |s| {
                                s.pop_layer();
                            }),).child(Dialog::new().title(format!("From previous convs with {}",file_name.clone()[..file_name.len() - 4].to_string())).content(TextArea::new().disabled().content(fs::read_to_string(format!("history/{}",file_name.clone())).unwrap_or_default())).scrollable())
                    );

                },
            ).with_name("adress_select"));
        }
        let saved_addr_us = saved_addr_us.clone();
        layout.add_child(Button::new("New...", move |s| {
            let captured_addr_to = TextArea::new().with_name("adress_to");
            let captured_addr_us = TextArea::new().with_name("adress_us");
            let mut add_layout = LinearLayout::vertical();
            add_layout.add_child(TextView::new("Adress to?"));
            add_layout.add_child(captured_addr_to);
            if saved_addr_us.is_empty(){
                add_layout.add_child(TextView::new("Adress us?"));
            }else {
                add_layout.add_child(TextView::new(format!("Adress us? Leave empty for {}",saved_addr_us)));
            }

            add_layout.add_child(captured_addr_us);
           let saved = saved_addr_us.clone();

            s.add_layer(
                Dialog::new()
                    .content(add_layout)
                    .title("Start new conversation")
                    .button("Start", move |s| {
                        let addr_to = s.call_on_name("adress_to", |v: &mut TextArea| {
                            v.get_content().to_string()
                        });
                        let mut addr_us = s.call_on_name("adress_us", |v: &mut TextArea| {
                            v.get_content().to_string()
                        });

                        if addr_us.to_owned().unwrap().trim().is_empty(){
                            addr_us = Some(saved.to_string());
                        }

                        s.set_user_data(ReadedData {
                            addr_to: addr_to.clone().unwrap(),
                            addr_us: addr_us.clone().unwrap(),
                        });
                        match TcpListener::bind(addr_us.clone().unwrap()) {
                            Ok(_) => {
                                s.quit();
                            }
                            Err(_) => {
                                s.pop_layer();
                                s.add_layer(
                                    Dialog::new()
                                        .title("Error")
                                        .content(TextView::new(format!("The {} adress is cant be binded \nCheck the port availability",addr_us.clone().unwrap())

                                        ))
                                        .button("Okay.", |s| {
                                            s.pop_layer();
                                        }),
                                );
                            }
                        }
                    })
                    .button("Cancel", |s| {
                        s.pop_layer();
                    }),
            );
        }));

        let mut main = LinearLayout::horizontal();

        main.add_child(Dialog::around(layout).title("Continue conversation with..."));
        main.add_child(
            Dialog::new()
                .title("Menu")
                .content(LinearLayout::vertical().child(Button::new("Delete history", |siv|{siv.add_layer(Dialog::new().title("Warning").content(TextView::new("This action will delete all history")).button("Ok", |siv|{
                    for entry in fs::read_dir("history").unwrap() {
                        fs::remove_file(entry.unwrap().path()).unwrap();
                    }
                    siv.pop_layer();
                }).button("No", |siv|{siv.pop_layer();}));})).child(Button::new("Change longterm address us", |siv| {
                    siv.add_layer(
                        Dialog::new()
                            .content(TextArea::new().with_name("longterm_addr_us"))
                            .title("Setting longterm adress")
                            .button("Cancel", |siv| {
                                siv.pop_layer();
                            }).button("Ok", |siv| {
                                let content = fs::read_to_string("config.toml").unwrap();
                                let mut saved_config: Config = toml::from_str(content.as_str()).unwrap();
                                saved_config.addr_us = siv
                                    .call_on_name("longterm_addr_us", |h: &mut TextArea| {
                                        h.get_content().to_string()
                                    })
                                    .unwrap()
                                    .to_string();
                                match TcpListener::bind(&saved_config.addr_us) {
                                    Ok(_) => {siv.pop_layer();},
                                    Err(_) => {siv.add_layer(Dialog::new().title("Warning").content(TextView::new(format!("The {} adress is cant be binded \nCheck the port availability",&saved_config.addr_us))).button("Okay", |siv|{siv.pop_layer();}));}
                                }
                                let toml_content = toml::to_string(&saved_config).unwrap();
                                fs::write("config.toml", toml_content.as_bytes()).unwrap();

                            })
                    );

                })))
        );
        siv.add_layer(main);
        play_random_sound();
        siv.run();
        let user_data = siv.take_user_data::<ReadedData>().unwrap();
        println!("{} aboba {}", user_data.addr_to, user_data.addr_us);
        addr_to = user_data.addr_to.clone();
        addr_us = user_data.addr_us.clone();

        siv.quit();
    } else {
        println!(
            "choose operation mode 2-sender 1-listener 3 - client + server 4 - choose long term adress and port 5 delete conversation history"
        );
        choose = "".to_string();
        io::stdin().read_line(&mut choose).unwrap();
    }

    match choose.trim() {
        "5" => {
            println!("Sure? y/n");
            let mut choose = "".to_string();
            io::stdin().read_line(&mut choose).unwrap();
            if choose.trim().to_ascii_lowercase() == "y" {
                for entry in fs::read_dir("history").unwrap() {
                    fs::remove_file(entry.unwrap().path()).unwrap();
                }
                println!("History deleted");
            }
        }
        "4" => {
            println!("Type your adress");
            let mut choose = "".to_string();
            io::stdin().read_line(&mut choose).unwrap();
            saved_config.addr_us = choose.trim().to_string();
            let toml_content = toml::to_string(&saved_config).unwrap();
            fs::write("config.toml", toml_content.as_bytes()).unwrap();
        }
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
            let print_gag = Gag::stdout().unwrap();

            if saved_config.tui_interface {
                thread::spawn(|| {
                    let mut siv = Cursive::default();
                    siv.add_layer(TextView::new(" ").with_name("stick"));
                    //борровит, клонит, отпускает
                    let cb_sink = { siv.cb_sink().clone() };
                    thread::spawn(move || {
                        let mut n = 0;
                        unsafe {
                            while CONNECTED.lock().unwrap().as_str() != "connected" {
                                thread::sleep(Duration::from_millis(100));
                                n += 1;
                                cb_sink
                                    .send(Box::new(move |s| {
                                        s.call_on_name("stick", |h: &mut TextView| {
                                            h.set_content(format!(
                                                "{}\n{}",
                                                CONNECTED.lock().unwrap().as_str(),
                                                "-\\|/".chars().nth(n % 4).unwrap()
                                            ))
                                        });
                                    }))
                                    .unwrap();
                            }
                        }

                        cb_sink
                            .send(Box::new(|s| {
                                s.quit();
                            }))
                            .unwrap();
                        unsafe {
                            CONNECTED.lock().unwrap().clear();
                            CONNECTED.lock().unwrap().push_str("finished");
                        };
                    });
                    siv.run();
                });
            } else {
                drop(print_gag);
            }

            if addr_to.is_empty() && addr_us.is_empty() {
                println!("who is we chatting with? Leave blank if we want use handshake");
                std::io::stdin().read_line(&mut addr_to).unwrap();
                if !saved_config.addr_us.is_empty() {
                    println!("who are we? Leave empty for {}", saved_config.addr_us);
                    std::io::stdin().read_line(&mut addr_us).unwrap();
                    if addr_us.trim().is_empty() {
                        println!("using {} for us", saved_config.addr_us);
                        addr_us = saved_config.addr_us;
                    }
                } else {
                    println!("who are we?");
                    std::io::stdin().read_line(&mut addr_us).unwrap();
                }
            }

            addr_to = addr_to.trim().to_string();
            addr_us = addr_us.trim().to_string();

            /*
                        let mut text = TextView::new("").with_name("loading_text");
                        cursive_flexi_logger_view::show_flexi_logger_debug_console(&mut siv);
                        siv.run();
            */
            /*
            let mut connected = Arc::new(Mutex::new(false));
            let connected_clone = connected.clone();
            thread::spawn(move || {
                let mut siv = Cursive::new();
                siv.add_layer(TextView::new("Trying to connect..."));
                siv.run();

            });
            */

            //let thread_sender = start_thread_sender(addr_to);
            println!("Sending handshake");
            CONNECTED.lock().unwrap().clear();
            CONNECTED.lock().unwrap().push_str("Sending handshake");
            let addr_us_clone = addr_us.clone();

            let handshake_thread =
                thread::spawn(move || start_listening_handshake(addr_us_clone.as_str()).unwrap());

            let mut handshake = String::new();
            let mut ping = u128::default();
            if !addr_to.is_empty() {
                send_handshake(addr_to, addr_us.clone(), public.clone());
                CONNECTED.lock().unwrap().clear();
                CONNECTED.lock().unwrap().push_str("sended handshake");
                let timer = Instant::now();
                handshake = handshake_thread.join().unwrap();
                CONNECTED.lock().unwrap().clear();
                CONNECTED.lock().unwrap().push_str("got handshake");
                ping = timer.elapsed().as_millis();
            } else {
                CONNECTED.lock().unwrap().clear();
                CONNECTED.lock().unwrap().push_str("waiting for handshake");
                handshake = handshake_thread.join().unwrap();
                CONNECTED.lock().unwrap().clear();
                CONNECTED.lock().unwrap().push_str("got handshake");
                let timer = Instant::now();
                println!("{handshake}");
                let begin_public = handshake.find("public:").unwrap();
                let addr_to = &handshake.as_str()[14..begin_public];
                let public_conv = &handshake.as_str()[begin_public + 8..&handshake.len() - 1]
                    .replace("\\n", "\n");
                println!(
                    "gotted handshake! from {addr_to}\nand public {}",
                    public_conv
                );
                ping = timer.elapsed().as_millis();
                send_handshake(addr_to.to_string(), addr_us.clone(), public.clone()).unwrap();
                CONNECTED.lock().unwrap().clear();
                CONNECTED.lock().unwrap().push_str("sended handshake");
            }

            println!("{handshake}");
            let begin_public = handshake.find("public:").unwrap();
            let addr_to = &handshake.as_str()[14..begin_public];
            let public_conv =
                &handshake.as_str()[begin_public + 8..&handshake.len() - 1].replace("\\n", "\n");
            println!(
                "gotted handshake! from {addr_to}\nand public {}",
                public_conv
            );
            CONNECTED.lock().unwrap().clear();
            unsafe {
                CONNECTED.lock().unwrap().push_str("connected");
                while CONNECTED.lock().unwrap().as_str() != "finished" {
                    thread::sleep(Duration::from_secs(1));
                }
            }

            println!("to {addr_to} us {addr_us}");

            if saved_config.tui_interface {
                let mut siv = Cursive::default();

                let mut conv = LinearLayout::vertical();

                let thread_listen = start_thread_listener(
                    addr_us.clone(),
                    private.clone(),
                    addr_to.to_string(),
                    saved_config.save_history,
                    Some(siv.cb_sink().clone()),
                );

                let send_stream =
                    Arc::from(Mutex::from(create_sender_tui(addr_to.to_string()).unwrap()));
                conv.add_child(
                    TextView::new(format!(
                        "from {} to {} conversation. Encryption: our: {} their: {} approx ping: {}",
                        addr_us,
                        addr_to,
                        !public.is_empty(),
                        !public_conv.is_empty(),
                        ping
                    ))
                    .full_width(),
                );

                conv.add_child(
                    (TextArea::new().content("").disabled().with_name("Chat"))
                        .scrollable()
                        .scroll_strategy(view::ScrollStrategy::StickToBottom)
                        .full_width(),
                );
                conv.add_child(DummyView.fixed_height(1));
                let mut answer = LinearLayout::horizontal();
                answer.add_child(TextArea::new().with_name("message"));
                let public_to: Arc<String> = Arc::from(public_conv.to_string().clone());
                answer.add_child(Button::new("reply", move |s| {
                    s.focus_name("message").unwrap();
                    let message = s.call_on_name("message", |h: &mut TextArea| {
                        let content = h.get_content().to_string();
                        h.set_content("");

                        content
                    });

                    if public_to.clone().is_empty() {
                        let chat = s.call_on_name("Chat", |h: &mut TextArea| {
                            h.set_content(
                                h.get_content().to_string()
                                    + message.clone().unwrap().as_str()
                                    + "    [our]\n",
                            );
                        });
                        send_stream
                            .clone()
                            .lock()
                            .unwrap()
                            .reply(message.unwrap() + "\n")
                            .unwrap();
                    } else {
                        let chat = s.call_on_name("Chat", |h: &mut TextArea| {
                            h.set_content(
                                h.get_content().to_string()
                                    + message.clone().unwrap().as_str()
                                    + "    [our secured]\n",
                            );
                        });
                        send_stream
                            .clone()
                            .lock()
                            .unwrap()
                            .reply(
                                encrypt_message(message.unwrap(), public_to.clone().to_string())
                                    + "\n",
                            )
                            .unwrap();
                    }
                }));
                conv.add_child(answer);
                siv.pop_layer();
                siv.pop_layer();
                siv.add_fullscreen_layer(conv);

                siv.run();
            } else {
                let thread_listen = start_thread_listener(
                    addr_us.clone(),
                    private.clone(),
                    addr_to.to_string(),
                    saved_config.save_history,
                    None,
                );
                let thread_sender =
                    start_thread_sender(addr_to.to_string(), public_conv.to_string());
                println!("time spended for connect idk lol sec");

                thread_sender.join().unwrap();
            }
        }

        &_ => {}
    }
}
fn encrypt_message(message: String, public_to: String) -> String {
    if public_to.is_empty() {
        return message.trim().to_string();
    }
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
    if private_us.is_empty() {
        message
    } else {
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
}

fn send_handshake(addr_to: String, addr_us: String, public_key: String) -> Result<(), String> {
    let mut sender = TcpSender::new(addr_to.to_string(), 60);
    let handshake = format!("!Handshake!ip:{}public:{:?}", addr_us, public_key.trim()).to_string();
    match sender {
        Ok(mut stream) => {
            stream.reply(handshake).unwrap();
            Ok(())
        }
        Err(e) => Err(
            "There may be problem with connection, or given ip and received ip dont match. "
                .to_string()
                + e.as_str(),
        ),
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
fn start_thread_listener(
    addr_us: String,
    private_us: String,
    addr_to: String,
    save_history: bool,
    sink: Option<CbSink>,
) -> JoinHandle<()> {
    let thread_listen = thread::spawn(move || {
        let listener = TcpListener::bind(addr_us.clone());
        match listener {
            Ok(_) => {
                for stream in listener.unwrap().incoming() {
                    let cb_sink = sink.clone();
                    println!("Got stream connection");
                    if let Err(err) = print_log(addr_to.as_str()) {
                        println!("{err}");
                    } else {
                        println!("from previous conversation with this adress");
                    }
                    let buf_reader_stream = BufReader::new(stream.unwrap());

                    for message in buf_reader_stream.lines() {
                        let cb_sink = sink.clone();
                        match message {
                            Ok(message) => {
                                play_random_sound();
                                if cb_sink.is_some() {
                                    let mes = message.clone();
                                    let private_us = private_us.clone();
                                    cb_sink
                                        .unwrap()
                                        .send(Box::new(move |s| {
                                            s.call_on_name("Chat", |view: &mut TextArea| {
                                                let content = view.get_content();
                                                if private_us.is_empty() {
                                                    view.set_content(
                                                        content.to_string()
                                                            + decrypt_message(mes, private_us)
                                                                .as_str()
                                                            + "    [conversator]\n",
                                                    );
                                                } else {
                                                    view.set_content(
                                                        content.to_string()
                                                            + decrypt_message(mes, private_us)
                                                                .as_str()
                                                            + "    [conversator secured]\n",
                                                    );
                                                }
                                            });
                                        }))
                                        .unwrap();
                                } else {
                                    message.print_message(private_us.clone());
                                }
                                if save_history {
                                    message.log_message(addr_to.as_str(), private_us.as_str());
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    if cb_sink.is_some() {
                        cb_sink
                            .unwrap()
                            .send(Box::new(move |s| {
                                s.add_layer(
                                    Dialog::new()
                                        .title("Disconection")
                                        .content(TextView::new(
                                            "Conversator has dropped connection.",
                                        ))
                                        .button("exit", |s| s.quit()),
                                );
                            }))
                            .unwrap();
                    }
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
fn create_sender_tui(addr_to: String) -> Result<TcpSender, String> {
    let mut sender = TcpSender::new(addr_to.trim().to_string(), 60); //drops stream if goes out of scope
    sender
}
fn play_sound(path: &str) {
    let print_gag = Gag::stderr().unwrap();
    let stream_handle =
        rodio::OutputStreamBuilder::open_default_stream().expect("open default audio stream");
    let sink = rodio::Sink::connect_new(&stream_handle.mixer());
    let file = File::open(path).unwrap();
    let source = Decoder::try_from(file).unwrap();
    sink.append(source);
    sink.sleep_until_end();
}
fn play_random_sound() {
    thread::spawn(|| {
        let print_gag = Gag::stderr().unwrap();
        let stream_handle =
            rodio::OutputStreamBuilder::open_default_stream().expect("open default audio stream");
        let sink = rodio::Sink::connect_new(&stream_handle.mixer());
        let mut sounds = Vec::new();
        for entry in fs::read_dir("sounds").unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();

            if path.is_file() {
                sounds.push(format!("{}", path.to_str().unwrap()).to_string());
            }
        }

        let source = Decoder::try_from(
            File::open(sounds[rand::rng().next_u32().to_usize() % sounds.len()].clone()).unwrap(),
        )
        .unwrap();
        sink.append(source);
        sink.sleep_until_end();
    });
}
