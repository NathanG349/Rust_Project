mod crypto;

use clap::{Parser, Subcommand};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::process;
use crypto::{Lcg, pow_mod, generate_private_key, P, G};
use chrono::Local; // Imoport de lhorloge

#[derive(Parser)]
#[command(version, about = "Secure Chat")]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Server { port: u16 },
    Client { address: String },
}

fn main() {
    let args = Args::parse();
    match args.command {
        Commands::Server { port } => {
            let address = format!("0.0.0.0:{}", port);
            println!("[SERVER] Listening on {}", address);
            let listener = TcpListener::bind(&address).expect("Failed to bind");
            println!("Waiting for connection...");
            if let Ok((stream, _)) = listener.accept() {
                handle_connection(stream, true);
            }
        }
        Commands::Client { address } => {
            println!("[CLIENT] Connecting to {}...", address);
            if let Ok(stream) = TcpStream::connect(&address) {
                println!("Connected!");
                handle_connection(stream, false);
            } else {
                println!("Failed to connect.");
            }
        }
    }
}

fn handle_connection(mut stream: TcpStream, _is_server: bool) {
    //  KEY EXCHANGE 
    println!("Starting Key Exchange...");
    let private_key = generate_private_key();
    let public_key = pow_mod(G, private_key, P);
    stream.write_all(&public_key.to_be_bytes()).unwrap();
    
    let mut buffer = [0u8; 8];
    stream.read_exact(&mut buffer).unwrap();
    let remote_public_key = u64::from_be_bytes(buffer);
    let shared_secret = pow_mod(remote_public_key, private_key, P);
    println!("Secure Channel Established. Secret: {:X}", shared_secret);

    let seed = shared_secret;
    let mut encrypt_lcg = Lcg::new(seed);
    let mut decrypt_lcg = Lcg::new(seed);

    let mut read_stream = stream.try_clone().unwrap();
    
    // Thread Reception
    thread::spawn(move || {
        let mut buffer = [0u8; 1024];
        loop {
            match read_stream.read(&mut buffer) {
                Ok(0) => { process::exit(0); }
                Ok(n) => {
                    let received = &buffer[0..n];
                    // Decrypt
                    let mut plain = Vec::new();
                    for &b in received {
                        plain.push(b ^ decrypt_lcg.next_byte());
                    }
                    
                    // AJOUT DE LA GESTION DE L'HEURE ICI
                    let now = Local::now();
                    let timestamp = now.format("%H:%M:%S"); // Format HH:MM:SS
                    
                    // On change l'affichage pour inclure le timestamp
                    println!("\n[{}] Received: {}", timestamp, String::from_utf8_lossy(&plain));
                    
                    print!("> ");
                    io::stdout().flush().unwrap();
                }
                Err(_) => break,
            }
        }
    });

    // Envoi
    print!("> ");
    io::stdout().flush().unwrap();
    let stdin = io::stdin();
    let mut input = String::new();
    loop {
        input.clear();
        stdin.read_line(&mut input).unwrap();
        let clean = input.trim();
        if clean == "/quit" { break; }
        
        // Encrypt
        let mut encrypted = Vec::new();
        for &b in clean.as_bytes() {
            encrypted.push(b ^ encrypt_lcg.next_byte());
        }
        stream.write_all(&encrypted).unwrap();
        print!("> ");
        io::stdout().flush().unwrap();
    }
}