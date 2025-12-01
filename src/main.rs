mod crypto; // On importe le fichier crypto.rs

use clap::{Parser, Subcommand};
use colored::*; // Import des couleurs
use chrono::Local; // Import de l'heure
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::process;
use crypto::{Lcg, pow_mod, generate_private_key, P, G};

#[derive(Parser)]
#[command(version, about = "Secure Stream Cipher Chat")]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Mode Serveur
    Server { port: u16 },
    /// Mode Client
    Client { address: String },
}

fn main() {
    let args = Args::parse();

    match args.command {
        Commands::Server { port } => {
            let address = format!("0.0.0.0:{}", port);
            println!("{}", format!("[SERVER] Listening on {}", address).blue().bold());
            let listener = TcpListener::bind(&address).expect("Failed to bind");
            
            println!("{}", "Waiting for secure connection...".yellow());

            if let Ok((stream, addr)) = listener.accept() {
                println!("{}", format!("[CONNECTION] Client connected from {}", addr).green().bold());
                handle_connection(stream, true); // true = ici le serveur
            }
        }
        Commands::Client { address } => {
            println!("{}", format!("[CLIENT] Connecting to {}...", address).blue());
            match TcpStream::connect(&address) {
                Ok(stream) => {
                    println!("{}", "Connected! Initiating handshake...".green().bold());
                    handle_connection(stream, false); // false = ici le client
                }
                Err(e) => eprintln!("{}", format!("Failed to connect: {}", e).red()),
            }
        }
    }
}

fn handle_connection(mut stream: TcpStream, is_server: bool) {
    // --- 1. Échange Diffie-Hellman ---
    println!("\n{}", " KEY EXCHANGE START ---".purple());
    
    let private_key = generate_private_key();
    let public_key = pow_mod(G, private_key, P);

    // Envoyer ma clé
    let pub_bytes = public_key.to_be_bytes();
    stream.write_all(&pub_bytes).unwrap();
    
    // Recevoir sa clé
    let mut buffer = [0u8; 8];
    stream.read_exact(&mut buffer).unwrap();
    let remote_public_key = u64::from_be_bytes(buffer);

    // Calculer le secret
    let shared_secret = pow_mod(remote_public_key, private_key, P);
    
    println!("Shared Secret established: {:X}", shared_secret);
    println!("{}", " SECURE CHANNEL READY ---".purple());

    //  Initialisation Crypto 
    let seed = shared_secret;
    let mut encrypt_lcg = Lcg::new(seed);
    let mut decrypt_lcg = Lcg::new(seed);

    //  Chat Loop 
    let mut read_stream = stream.try_clone().expect("Failed to clone stream");
    
    // Thread RÉCEPTION
    thread::spawn(move || {
        let mut buffer = [0u8; 1024];
        loop {
            match read_stream.read(&mut buffer) {
                Ok(0) => { 
                    println!("\n{}", " Connection closed by peer.".red()); 
                    process::exit(0); 
                }
                Ok(n) => {
                    let received_bytes = &buffer[0..n];
                    
                    // Déchiffrement
                    let mut plain_bytes = Vec::new();
                    for &cipher_byte in received_bytes {
                        let key_byte = decrypt_lcg.next_byte();
                        plain_bytes.push(cipher_byte ^ key_byte);
                    }

                    let msg_str = String::from_utf8_lossy(&plain_bytes);
                    
                    // GESTION HEURE
                    let time = Local::now().format("%H:%M:%S");

                    // GESTION COULEURS
                    // Si je suis serveur, l'autre est Client (et inversement)
                    let remote_name = if is_server { "CLIENT" } else { "SERVER" };
                    let color_name = if is_server { remote_name.cyan() } else { remote_name.yellow() };

                    // Affichage Joli : [19:42:01] [CLIENT] Salut
                    print!("\r"); // Efface la ligne de prompt actuelle
                    println!("{} [{}] {}", 
                        format!("[{}]", time).dimmed(),
                        color_name, 
                        msg_str.bold()
                    );
                    
                    // Réafficher le prompt
                    print!("{}", "> ".blue());
                    io::stdout().flush().unwrap();
                }
                Err(_) => { break; }
            }
        }
    });

    // Boucle ENVOI
    print!("{}", "> ".blue());
    io::stdout().flush().unwrap();
    
    let stdin = io::stdin();
    let mut input = String::new();
    
    loop {
        input.clear();
        stdin.read_line(&mut input).unwrap();
        let clean_input = input.trim();
        
        if clean_input.is_empty() { 
            print!("{}", "> ".blue());
            io::stdout().flush().unwrap();
            continue; 
        }

        // Commande pour quitter
        if clean_input == "/quit" {
            println!("{}", "Exiting...".red());
            break;
        }

        // Chiffrement
        let mut encrypted_bytes = Vec::new();
        for &byte in clean_input.as_bytes() {
            let key_byte = encrypt_lcg.next_byte();
            encrypted_bytes.push(byte ^ key_byte);
        }

        // Envoi
        if stream.write_all(&encrypted_bytes).is_err() {
            break;
        }
        
        // Remettre le prompt
        print!("{}", "> ".blue());
        io::stdout().flush().unwrap();
    }
}
