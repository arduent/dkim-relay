/*

    Copyright (C) 2025 Waitman Gobble

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, see <https://www.gnu.org/licenses/>.

   Contact by email: <waitman@quantificant.com>
   <https://quantificant.com/contact>

*/

#![allow(future_incompatible)]

use clap::{Arg, Command};
use daemonize::Daemonize;
use simplelog::*;
use nix::unistd::{setgid, setuid, Gid, Uid};
use tokio::net::TcpListener;
use tokio::io::{AsyncBufReadExt, BufReader, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_native_tls;
use native_tls;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_rustls::{rustls, TlsAcceptor};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::{self, File};
use std::io;
use serde::Deserialize;
use std::process;
use time::macros::format_description;
use rsa::sha2::{Digest, Sha256};
use openssl::rsa::Rsa;
use openssl::rsa::Padding;
use openssl::pkey::PKey;
use openssl::error::ErrorStack;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::engine::Engine as _;
use base64::engine::general_purpose;
use std::collections::HashMap;
use std::sync::Arc;
use std::error::Error as StdError;
use std::time::{SystemTime, UNIX_EPOCH};

// TCP stream
pub trait SrAsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> SrAsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type BoxedStream = Box<dyn SrAsyncStream>;

// Server configuration structure
#[derive(Debug, Deserialize)]
struct ServerConfig {
    listen_host: String,
    listen_port: u16,
    tls_enabled: bool,
    cert_path: String,
    key_path: String,
    auth_username: String,
    auth_password: String,
    drop_user: String,
}

// Domain configuration structure
#[derive(Debug, Deserialize)]
struct DomainConfig {
    name: String,
    selector: String,
    private_key: String,
    helo_host: String,
    relay: String,
    relay_port: u16,
    relay_auth_user: String,
    relay_auth_password: String,
}

// Main configuration structure
#[derive(Debug, Deserialize)]
struct Config {
    server: ServerConfig,
    domain: Vec<DomainConfig>,
}

// Queued email structure
// Store the queue in memory
#[derive(Debug)]
struct QueuedEmail {
    timestamp: std::time::Instant,
    email: String,
    helo_host: String,
    mail_from: String,
    rcpt_to: Vec<String>,
    relay_username: String,
    relay_password: String,
    relay_host: String,
    relay_port: u16,
}

// logging macro
macro_rules! log_expect {
    ($result:expr, $msg:expr) => {
         match $result {
             Ok(val) => val,
             Err(err) => {
                 log::error!("{}: {}", $msg, err);
                 panic!("{}: {}", $msg, err);
             }
         }
    };
}

// software version
fn get_version() -> &'static str {
  "0.1a"
}

//DEBUG 
/*
fn hex_dump(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(" ")
}
*/

// drop from root to unprivileged user specified in config
fn drop_privileges(unprivileged_user: &str) -> Result<(), Box<dyn std::error::Error>> {
    let user = users::get_user_by_name(unprivileged_user)
        .ok_or_else(|| format!("User {} not found", unprivileged_user))?;
    setgid(Gid::from_raw(user.primary_group_id()))?;
    setuid(Uid::from_raw(user.uid()))?;
    Ok(())
}

// determine local unix epoch time for DKIM Signature
fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

// load the tls configuration
async fn load_tls_config(server_config: &ServerConfig) -> io::Result<TlsAcceptor> {    
    let certs = CertificateDer::pem_file_iter(&server_config.cert_path)
        .expect("cannot open certificate file")
        .map(|cert| cert.unwrap())
        .collect::<Vec<_>>();
    let key =
        PrivateKeyDer::from_pem_file(&server_config.key_path).expect("cannot open private key file");

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
    .expect("bad certificate/key");

     
    Ok(TlsAcceptor::from(Arc::new(config)))
}

// initialize file logger
fn init_file_logger(log_file: &str) {
    let file = File::options()
        .append(true)
        .create(true)
        .open(log_file)
        .expect("Failed to create/open log file");

    // Create a custom format closure if you want to include timestamps.
    let config = ConfigBuilder::new()
        .set_time_format_custom(format_description!("[year]-[month]-[day] [hour]:[minute]:[second]"))
        .build();

    WriteLogger::init(LevelFilter::Info, config, file)
        .expect("Failed to initialize file logger");
}

// base64 encoder helper function
fn to_base64(text: Vec<u8>) -> String {
        BASE64.encode(text)
}

// forward email from queue to relay server, use STARTTLS if specified
async fn forward_email(queued: QueuedEmail) -> Result<(), Box<dyn StdError>> {
    let use_tls = queued.relay_host.starts_with("tls://");
    let host = if use_tls {
    log::info!("Using TLS");
        queued.relay_host.trim_start_matches("tls://")
    } else {
        queued.relay_host.as_str()
    };

    let addr = format!("{}:{}", host, queued.relay_port);
    log::info!("Connecting to relay at {}", addr);
    let mut tcp_stream = tokio::net::TcpStream::connect(&addr).await?;

    // Create a BufReader for pre-TLS communication.
    let mut reader = tokio::io::BufReader::new(&mut tcp_stream);
    let mut line = String::new();

    // Read the relay's initial greeting.
    reader.read_line(&mut line).await?;
    log::info!("Relay greeting: {}", line.trim_end());
    line.clear();

    // send EHLO command.
    let ehlo_cmd = format!("EHLO {}\r\n", queued.helo_host);
    reader.get_mut().write_all(ehlo_cmd.as_bytes()).await?;
    reader.get_mut().flush().await?;
    let ehlo_response = read_smtp_response(&mut reader).await?;
    log::info!("EHLO full response: {}", ehlo_response);

    if use_tls {

        // send STARTTLS.
        reader.get_mut().write_all(b"STARTTLS\r\n").await?;
        reader.get_mut().flush().await?;
        let starttls_response = read_smtp_response(&mut reader).await?;
        log::info!("STARTTLS response: {}", starttls_response);

        // upgrade the plain TCP stream to TLS.
        let native_connector = native_tls::TlsConnector::builder()
            .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
//enable these if you are relaying through a server that needs it
//            .danger_accept_invalid_certs(true)
//            .danger_accept_invalid_hostnames(true)
            .build()?;
        let connector = tokio_native_tls::TlsConnector::from(native_connector);
        let tls_stream = connector.connect(host, tcp_stream).await?;
        
        // unified_stream is the TLS stream.
        let unified_stream: BoxedStream = Box::new(tls_stream);
        // Proceed to split the unified stream.
        process_smtp_commands(unified_stream, queued).await?;

    } else {

        // box the plain TCP stream if not using TLS
        let unified_stream: BoxedStream = Box::new(tcp_stream);
        process_smtp_commands(unified_stream, queued).await?;

    }

    Ok(())
}

// handle SMTP responses
async fn read_smtp_response<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut response = String::new();
    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line).await?;
        if bytes == 0 {
            break;
        }
        response.push_str(&line);
        // Check if this is the last line: it should have a space after the code (e.g. "250 ")
        if line.len() >= 4 && &line[3..4] == " " {
            break;
        }
    }
    Ok(response)
}

// process SMTP commands to forward queued email
async fn process_smtp_commands(
    stream: BoxedStream,
    queued: QueuedEmail
) -> Result<(), Box<dyn std::error::Error>> {


    //DEBUG - queued email
    //log::info!("Queued email: \r\n{}-end-",queued.email);
    //log::info!("Hex Dump: {}",hex_dump(&queued.email.clone().into_bytes()));
    log::info!("Queued email - {} bytes",queued.email.len());
    
    // split the unified stream into a reader and writer
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = tokio::io::BufReader::new(read_half);
    let mut line = String::new();

    // perform AUTH LOGIN if credentials are provided
    if !queued.relay_username.is_empty() && !queued.relay_password.is_empty() {
        write_half.write_all(b"AUTH LOGIN\r\n").await?;
        write_half.flush().await?;
        reader.read_line(&mut line).await?;
        log::info!("AUTH prompt: {}", line.trim_end());
        line.clear();
        let username_enc = general_purpose::STANDARD.encode(&queued.relay_username);
        write_half.write_all(format!("{}\r\n", username_enc).as_bytes()).await?;
        write_half.flush().await?;
        reader.read_line(&mut line).await?;
        log::info!("Username response: {}", line.trim_end());
        line.clear();
        let password_enc = general_purpose::STANDARD.encode(&queued.relay_password);
        write_half.write_all(format!("{}\r\n", password_enc).as_bytes()).await?;
        write_half.flush().await?;
        reader.read_line(&mut line).await?;
        log::info!("AUTH success response: {}", line.trim_end());
        line.clear();
    }

    // send MAIL FROM command
    let mail_from_cmd = format!("MAIL FROM:<{}>\r\n", queued.mail_from);
    write_half.write_all(mail_from_cmd.as_bytes()).await?;
    write_half.flush().await?;
    reader.read_line(&mut line).await?;
    log::info!("MAIL FROM:<{}> response: {}", queued.mail_from, line.trim_end());
    line.clear();

    // send RCPT TO command
    for recipient in queued.rcpt_to.iter() {
        let rcpt_cmd = format!("RCPT TO:<{}>\r\n", recipient);
        write_half.write_all(rcpt_cmd.as_bytes()).await?;
        write_half.flush().await?;
        reader.read_line(&mut line).await?;
        log::info!("RCPT TO:<{}> response: {}", recipient, line.trim_end());
        line.clear();
    }

    // send DATA command
    write_half.write_all(b"DATA\r\n").await?;
    write_half.flush().await?;
    reader.read_line(&mut line).await?;
    log::info!("DATA response: {}", line.trim_end());
    line.clear();

    // send the signed email data
    let email_data = format!("{}\r\n.\r\n", queued.email);
    write_half.write_all(email_data.as_bytes()).await?;
    write_half.flush().await?;
    reader.read_line(&mut line).await?;
    log::info!("Final response: {}", line.trim_end());
    line.clear();

    // send QUIT command
    write_half.write_all(b"QUIT\r\n").await?;
    write_half.flush().await?;
    reader.read_line(&mut line).await?;
    log::info!("QUIT response: {}", line.trim_end());

    Ok(())
}

// load a pkcs8 private key
fn load_rsa_from_pkcs8(pem: &str) -> Result<Rsa<openssl::pkey::Private>, ErrorStack> {
    // load using PKey in PKCS#8 PEM format
    let pkey = PKey::private_key_from_pem(pem.as_bytes())?;
    // extract an RSA key from the PKey and return
    pkey.rsa()
}


// sign a precomputed SHA-256 digest (32 bytes) using PKCS#1 v1.5
fn sign_digest_openssl(private_key_pem: &str, prehash: &[u8]) -> Result<String, ErrorStack> {
    // ensure the digest is correct SHA-256 size
    assert_eq!(prehash.len(), 32, "Prehash must be 32 bytes for SHA-256");

    // load the RSA private key from PEM
    let rsa = load_rsa_from_pkcs8(private_key_pem)?;

    // build the DigestInfo structure prepending DER prefix
    let der_prefix = hex::decode("3031300d060960864801650304020105000420")
        .expect("Invalid DER prefix");

    let mut digest_info = der_prefix;
    digest_info.extend_from_slice(prehash); // Now digest_info is 51 bytes.

    // buffer for the signature
    let mut signature = vec![0u8; rsa.size() as usize];

    // sign (encrypt) the DigestInfo with the private key using PKCS#1 v1.5 padding
    let sig_len = rsa.private_encrypt(&digest_info, &mut signature, Padding::PKCS1)?;
    signature.truncate(sig_len);

    // base64-encode the signature.
    Ok(general_purpose::STANDARD.encode(signature))
}

// parse the email headers and return headers, header_names, body structures
// header_names has the original names mapped to the lowercase header names
// many DKIM signers specify the original header names, some use lowercase
fn parse_headers(data_lines: Vec<String>) -> (HashMap<String, String>, HashMap<String, String>, Vec<String>) {
    let mut headers = HashMap::new();
    let mut header_names = HashMap::new();
    let mut body = Vec::new();
    let mut in_headers = true;
    let mut current_header = String::new();
    let mut current_value = String::new();
    let mut current_header_name = String::new();

    for line in data_lines {
        if in_headers {
            if line.is_empty() {
                // End of headers.
                in_headers = false;
                if !current_header.is_empty() {
                    headers.insert(current_header.clone(), current_value.trim().to_string());
                    header_names.insert(current_header.clone(), current_header_name.clone());
                }
                continue;
            }
            // check for folded header lines (continuation)
            if line.starts_with(' ') || line.starts_with('\t') {
                current_value.push(' ');
                current_value.push_str(line.trim());
            } else {
                if !current_header.is_empty() {
                    headers.insert(current_header.clone(), current_value.trim().to_string());
                    header_names.insert(current_header.clone(), current_header_name.clone());
                }
                // new header line
                if let Some((name, value)) = line.split_once(':') {
                    current_header_name = name.trim().to_string();
                    current_header = name.trim().to_lowercase(); // header names are lowercase for relaxed
                    current_value = value.trim().to_string();
                }
            }
        } else {
            body.push(line.clone());
        }
    }

    let size = headers.keys().len();
    log::info!("Number of headers: {}", size);

    (headers, header_names, body)
}

// return the relaxed header
fn canonicalize_header_relaxed(header: &str, value: &str) -> String {
    // lowercase header name and compress whitespace in the value
    let canonical_name = header.to_lowercase();
    let canonical_value = value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    format!("{}:{}", canonical_name, canonical_value)
}

// return the relaxed body
fn canonicalize_body_relaxed(body_lines: &[String]) -> String {
    // remove trailing white space from each line
    let mut canonical_lines: Vec<String> = body_lines
        .iter()
        .map(|line| line.trim_end().to_string())
        .collect();

    // remove all trailing empty lines
    while let Some(last) = canonical_lines.last() {
        if last.is_empty() {
            canonical_lines.pop();
        } else {
            break;
        }
    }

    // if no lines remain, canonicalize to an empty string.
    // otherwise, join the lines with CRLF and add a trailing CRLF
    let canonical_body = if canonical_lines.is_empty() {
        String::new()
    } else {
        format!("{}\r\n", canonical_lines.join("\r\n"))
    };

    //DEBUG
    //log::info!("Canonicalized body: {}", canonical_body);
    canonical_body
}

// calculate the signature
fn generate_dkim_signature(
    headers: &HashMap<String, String>,
    header_names: &HashMap<String, String>,
    body: &str,
    private_key_pem: &str,
    domain: &str,
    selector: &str,
    headers_to_sign: &[&str],
) -> String {

    //build list of signed headers
    let mut actual_headers: Vec<String> = Vec::new();
    // canonicalize the headers to be signed
    let mut header_data = String::new();

    for &h in headers_to_sign {
        if let Some(value) = headers.get(h) {
            let canonical = canonicalize_header_relaxed(h, value);
            header_data.push_str(&canonical);
            header_data.push_str("\r\n");
            // keep a list of the actual non-null headers to include
            actual_headers.push(header_names.get(h).unwrap().to_string());
        }
    }

    //DEBUG
    //log::info!("Header Data: {}",header_data);

    // body is already canonicalized
    let canonical_body = body;

    // compute the body hash
    let mut hasher = Sha256::new();
    hasher.update(canonical_body.as_bytes());
    let body_hash = hasher.finalize();
    let bh = to_base64(body_hash.to_vec());
    log::info!("Body Hash: {}",bh);

    let timestamp = current_unix_timestamp();
    // signature expires in 7 days
    let expires = timestamp + 604800;

    // build the DKIM header for signing (with an empty b= value)
    let dkim_header = format!(
        "v=1; a=rsa-sha256; c=relaxed/relaxed; d={}; s={}; t={}; x={}; h={}; bh={}; b=",
        domain,
        selector,
        timestamp, expires,
        actual_headers.join(":"),
        bh
    );

    log::info!("Headers present: {}",actual_headers.join(","));
    // append the DKIM header to the header_data for signing
    let signing_data = format!("{}{}", header_data, canonicalize_header_relaxed("dkim-signature", &dkim_header));

    //DEBUG
    //log::info!("Signing Data: {}",signing_data);

    //DEBUG
    //let hex_output = hex_dump(signing_data.as_bytes());
    //log::info!("Hex dump: {}", hex_output);

    // hash the signing data
    let mut xhasher = Sha256::new();
    xhasher.update(signing_data.as_bytes());
    let xhashed = xhasher.finalize();

    // log hash for debug
    let xhashed_b64 = to_base64(xhashed.to_vec());
    log::info!("Hashed Header: {}",xhashed_b64);

	// sign the header
    let sig_b64 = sign_digest_openssl(private_key_pem, &xhashed)
        .expect("Failed to sign data");

    // return the complete DKIM-Signature header with signature 
    // appended to b=
    format!("DKIM-Signature: {}{}", dkim_header, sig_b64)
}

/* FOR FUTURE USE
fn split_into_chunks(input: &str, chunk_size: usize) -> Vec<String> {
    input
        .as_bytes()
        .chunks(chunk_size)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect()
}

fn fold_header(header: &str, max_width: usize) -> String {
    // accumulate words and try to wrap them
    let mut result = String::new();
    let mut current_line = String::new();

    // split header on whitespace
    for word in header.split_whitespace() {
        // determine the length if we add the word
        // if current_line is empty, no extra space is needed
        let additional_len = if current_line.is_empty() {
            word.len()
        } else {
            1 + word.len() // plus one for the space before the word
        };

        if current_line.len() + additional_len > max_width && !current_line.is_empty() {
            // append the current_line to result with a CRLF and a continuation space
            result.push_str(&current_line);
            result.push_str("\r\n ");
            current_line.clear();
            // start the next line with the current word
            
            // for the signature break into chunks
            if word.len()>64 {
                let chunky = split_into_chunks(word,64);
                for chunk in chunky {
                    result.push_str("    ");
                    result.push_str(&chunk);
                    result.push_str("\r\n ");
                }
            } else {
                 current_line.push_str(word);
            }
        } else {
            // otherwise add a space if needed, then the word
            if !current_line.is_empty() {
                current_line.push(' ');
            }
            current_line.push_str(word);
        }
    }

    // append any remaining text
    if !current_line.is_empty() {
        result.push_str(&current_line);
    }

    result
}
*/

// add the signed header to the top of the header block
fn tmp_insert_header(dkimhdr: String, mut data_lines: Vec<String>) -> String {

    //fold in the future
    //let folded_dkimhdr = fold_header(&dkimhdr,72);

    data_lines.insert(0, dkimhdr);
    format!("{}", data_lines.join("\r\n"))
}

// top level function to sign the message 
fn sign_email_message(data_lines: Vec<String>, private_key_pem: &str, 
    domain: &str, selector: &str) -> String {

    // parse headers and body
    let (headers, header_names, body_lines) = parse_headers(data_lines);
    let body_canonical = canonicalize_body_relaxed(&body_lines);

    // define headers to sign - sets the order
    let headers_to_sign = [
        "from", "reply-to", "mail-reply-to", "subject", "date", "to", "cc", "organization",
        "resent-date", "resent-from", "resent-sender", "resent-to",
        "resent-cc", "in-reply-to", "references", "list-id", "list-help",
        "list-unsubscribe", "list-subscribe", "list-post", "list-owner", "list-archive",
    ];

    // generate DKIM signature.
    generate_dkim_signature(&headers, &header_names, &body_canonical, private_key_pem, domain, selector, &headers_to_sign)
}

// extract domain from header value
fn extract_domain(s: &str) -> Option<&str> {
    // First, try to find the '<' and '>' characters
    let start = s.find('<')?;
    let end = s.find('>')?;
    // Extract the email address between the angle brackets.
    let email = &s[start + 1..end];
    log::info!("Found Email Address: {}",email);
    // Now, find the '@' symbol in the email address.
    let at_index = email.find('@')?;
    // Return everything after the '@'.
    Some(&email[at_index + 1..])
}

// service the connected client
async fn handle_client(
    mut stream: BoxedStream,
    config: Arc<Config>,
    email_tx: mpsc::Sender<QueuedEmail>) {

    let mut match_domain: Option<String> = None;
    let mut mail_from = String::new();
    let mut recipients = Vec::new();
    let mut authenticated = false;

    log::info!("Sending greeting to new client");

    // Send initial SMTP greeting.
    if stream.write_all(b"220 localhost SMTP Service Ready\r\n").await.is_err() {
        log::error!("Failed to write greeting");
    return;
    }
    if stream.flush().await.is_err() {
        log::error!("Failed to flush greeting");
        return;
    }

    // pin the boxed stream
    let mut stream = Box::pin(stream);
    // use tokio::io::split on a mutable reference to the pinned stream
    let (reader, mut writer) = tokio::io::split(&mut *stream);

    let reader = BufReader::new(reader);
    let mut lines = reader.lines();

    // process commands in a loop
    while let Ok(Some(line)) = lines.next_line().await {
        log::info!("Received: {}", line);

        // extract the SMTP command
        let mut parts = line.split_whitespace();
        let command = parts.next().unwrap_or("").to_uppercase();

        match command.as_str() {
            "EHLO" | "HELO" => {
                log::info!("Responding to EHLO/HELO");
                writer.write_all(b"250 AUTH LOGIN\r\n").await.ok();
                writer.flush().await.ok();
            },
            "AUTH" => {
	            // expecting: AUTH LOGIN
                if let Some(mech) = parts.next() {
                    if mech.to_uppercase() == "LOGIN" {
                        // prompt for username ("Username:" in base64).
                        writer.write_all(b"334 VXNlcm5hbWU6\r\n").await.ok();
                        writer.flush().await.ok();

                        let Ok(Some(username_b64)) = lines.next_line().await else { break; };
                        if username_b64.trim().is_empty() {
                            writer.write_all(b"535 Authentication failed\r\n").await.ok();
                            writer.flush().await.ok();
                            // abrupt disconnect we don't like fakers anyway 
                            break;
                        };

                        let username = match base64::engine::general_purpose::STANDARD.decode(username_b64.trim()) {
                            Ok(u) => String::from_utf8_lossy(&u).to_string(),
                            Err(_) => {
                                writer.write_all(b"535 Authentication failed\r\n").await.ok();
                                writer.flush().await.ok();
                                continue;
                            }
                        };

                        // prompt for password ("Password:" in base64).
                        writer.write_all(b"334 UGFzc3dvcmQ6\r\n").await.ok();
                        writer.flush().await.ok();

                        let Ok(Some(password_b64)) = lines.next_line().await else { break; };
                        if password_b64.trim().is_empty() {
						    writer.write_all(b"535 Authentication failed\r\n").await.ok();
                            writer.flush().await.ok();
                            // abrupt disconnect 
                            break;
                        };

                        let password = match base64::engine::general_purpose::STANDARD.decode(password_b64.trim()) {
                            Ok(p) => String::from_utf8_lossy(&p).to_string(),
                            Err(_) => {
                                writer.write_all(b"535 Authentication failed\r\n").await.ok();
                                writer.flush().await.ok();
                                continue;
                            }
                        };

                        // compare with credentials from the configuration.
                        if username == config.server.auth_username && password == config.server.auth_password {
                            // ok
                            authenticated = true;
                            writer.write_all(b"235 Authentication successful\r\n").await.ok();
                        } else {
                            // if you want it behave as a normal SMTP server then use the 535 line
                            // and comment out the loop routine following
                            //writer.write_all(b"535 Authentication failed\r\n").await.ok();

                            // but more fun to mess with script kiddies instead
                            log::error!("Failed auth, sending them into the black hole");
                            // messing with the script kiddies
                            writer.write_all(b"235 Authentication successful\r\n").await.ok();
                            writer.flush().await.ok();
                            // go in a loop until they get bored, or until the end of time
                            while let Ok(Some(_)) = lines.next_line().await {
                                writer.write_all(b"235 Authentication successful\r\n").await.ok();
                                writer.flush().await.ok();
                            }
                            break;
                        }
                        writer.flush().await.ok();
                    } else {
                        writer.write_all(b"504 Unrecognized authentication mechanism\r\n").await.ok();
                        writer.flush().await.ok();
                    }
                } else {
                    writer.write_all(b"501 Syntax: AUTH <mechanism>\r\n").await.ok();
                    writer.flush().await.ok();
                }
            },
            "MAIL" => {
			    // the client has to authenticate before using the MAIL command
                if !authenticated {
                    writer.write_all(b"530 Authentication required\r\n").await.ok();
                    writer.flush().await.ok();
                    // send them away, they have no business trying to send mail
                    break;
                }  
                // has to be MAIL FROM:<address>
                if line.to_uppercase().starts_with("MAIL FROM:") {
                    if writer.write_all(b"250 OK\r\n").await.is_err() {
                        break;
                    }
                    if writer.flush().await.is_err() {
                        break;
                    }
                    if let Some(start) = line.find('<') {
                        if let Some(end) = line.find('>') {
                            mail_from = line[start+1..end].to_string();
                        }
                    }
                    if let Some(tmp_domain) = extract_domain(&line) {
                        match_domain = Some(tmp_domain.to_string());
                    } else {
                        log::error!("Failed to extract domain");
                    }
                } else {
                    let _ = writer.write_all(b"500 Syntax error in parameters or arguments\r\n").await;
                    let _ = writer.flush().await;
                }
            },
            "RCPT" => {
			    // need to be authenticated before adding recipients
                if !authenticated {
                    writer.write_all(b"530 Authentication required\r\n").await.ok();
                    writer.flush().await.ok();
                    break;
                } 
                // Expecting: RCPT TO:<address>
                if line.to_uppercase().starts_with("RCPT TO:") {
                    if writer.write_all(b"250 OK\r\n").await.is_err() {
                        break;
                    }
                    if let Some(start) = line.find('<') {
                        if let Some(end) = line.find('>') {
                            let rcpt = line[start+1..end].to_string();
                            recipients.push(rcpt);
                        }
                    }
                } else {
                    let _ = writer.write_all(b"500 Syntax error in parameters or arguments\r\n").await;
                    writer.flush().await.ok();
                    break;
                }
            },
            "RSET" => {
                // some clients send a reset command when they are finished
                // clear any transaction-specific state
                mail_from.clear();
                recipients.clear();
                match_domain = None;
                authenticated = false;
                // Respond with 250 OK.
                let _ = writer.write_all(b"250 OK\r\n").await;
                let _ = writer.flush().await;
            },
            "DATA" => {
                // has to be authenticated to send DATA
                if !authenticated {
                    writer.write_all(b"530 Authentication required\r\n").await.ok();
                    writer.flush().await.ok();
                    break;
                }
                // this dkim-relay server doesn't handle unsigned mail
                // make sure you have a domain config for each domain you use
                if match_domain.is_none() {
                    let _ = writer.write_all(b"503 Bad sequence of commands\r\n").await;
                    let _ = writer.flush().await;
                    log::error!("No match_domain on DATA!");
                    continue;
                }
                // Signal the start of message data.
                if writer.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n").await.is_err() {
                    break;
                }
                if writer.flush().await.is_err() {
                    break;
                }
                let mut data_lines = Vec::new();
                // read lines until a line containing only a dot
                while let Ok(Some(data_line)) = lines.next_line().await {
                    if data_line.trim() == "." {
                        break;
                    }
                    data_lines.push(data_line);
                }

                //DEBUG
                //log::info!("Message data:\n{:?}", data_lines);
                
                // we have the DATA let's sign and queue the message 

                //find matching key and selector for this message
                let mut selector = "";
                let mut private_key_pem = "";
                let sign_domain = match_domain.as_deref().unwrap();

                for (_, domain) in config.domain.iter().enumerate() {
                    if domain.name == sign_domain
                    {
                        private_key_pem = &domain.private_key;
                        selector = &domain.selector;
                    }
                }

                log::info!("Sign Domain: {}",sign_domain);

                if private_key_pem!=""
                {
                    log::info!("Matched selector: {}",selector);

                    //get DKIM-Signature
                    let signed = sign_email_message(data_lines.clone(), 
                        private_key_pem, 
                        &sign_domain, &selector);

                    //insert DKIM-Signature into headers
                    let inserted = tmp_insert_header(signed,data_lines);

                    let domain_conf = config.domain.iter()
                        .find(|d| d.name.eq_ignore_ascii_case(sign_domain));

                    if let Some(domain_conf) = domain_conf {
                        let queued_email = QueuedEmail {
                            timestamp: std::time::Instant::now(),
                            email: inserted,
                            helo_host: domain_conf.helo_host.clone(),
                            mail_from: mail_from.clone(),
                            rcpt_to: recipients.clone(),
                            relay_username: domain_conf.relay_auth_user.clone(),
                            relay_password: domain_conf.relay_auth_password.clone(),
                            relay_host: domain_conf.relay.clone(),
                            relay_port: domain_conf.relay_port,
                        };

                        // Insert the email into the queue.
                        if let Err(e) = email_tx.send(queued_email).await {
                            log::error!("Failed to queue email: {}", e);
                        } else {
                            log::info!("Email queued successfully.");
                        }
                    } else {
                        log::error!("No matching domain configuration found for {}", sign_domain);
                    }

                    let _ = writer.write_all(b"250 OK: Message accepted for delivery\r\n").await;
                    if writer.flush().await.is_err() {
                        break;
                    }
                } else {
                    // if the client receives this message it means it couldn't sign the message
                    // check your config and your client setup
                    let _ = writer.write_all(b"523 Encryption needed.\r\n").await;
                    let _ = writer.flush().await;
                }
            },
            "QUIT" => {
                // all done see you later
                let _ = writer.write_all(b"221 Bye\r\n").await;
                let _ = writer.flush().await;
                break;
            },
            // not sure what they are attempting but we don't support it
            _ => {
                // For unsupported commands.
                let _ = writer.write_all(b"502 Command not implemented\r\n").await;
                let _ = writer.flush().await;
            }
        }
    }
}

// run the SMTP server
async fn run_server(config: Config) -> std::io::Result<()> {
    //list the configured domains in the log
    for (i, domain) in config.domain.iter().enumerate() {
        log::info!("Domain {} : {:?} selector: {:?}", i + 1, domain.name, domain.selector);
    }
    let config = Arc::new(config);

    let address = format!("{}:{}", config.server.listen_host, config.server.listen_port);
    let listener = TcpListener::bind(&address).await?;
    log::info!("Server is listening on {}", address);

    // prepare the TLS acceptor if needed
    let tls_acceptor = if config.server.tls_enabled {
    log::info!("TLS enabled");
        Some(load_tls_config(&config.server).await?)
    } else {
        None
    };

    // create MPSC channel for mail queue
    // messages are stored in memory and processed in a separate thread
    // NOTE: if you are trying to mass-send marketing or transactional
    // emails you probablyl want to bump up the 100 message limit
    let (email_tx, mut email_rx) = mpsc::channel::<QueuedEmail>(100);

    // start the queue processing thread
    tokio::spawn(async move {
        while let Some(queued) = email_rx.recv().await {
            // wait 30 seconds before sending
            // it's an arbitrary duration that attempts
            // to prevent a possible race condition
            // for example a large email getting stuffed 
            // into the queue when the queue is trying to 
            // process it. maybe this 30 seconds can be adjusted
            let elapsed = queued.timestamp.elapsed();
            if elapsed < Duration::from_secs(30) {
                sleep(Duration::from_secs(30) - elapsed).await;
            }
            // attempt to forward the email
            if let Err(e) = forward_email(queued).await {
                log::error!("Error forwarding email: {}", e);
                // here we lose the message if relay fails
                // TODO: re-requeue and try again later, maybe 
                // network or remote server issue?
                // we are spoiled and everything always works, right?
                // otherwise it just vanishes into dust
            } else {
                log::info!("Email forwarded successfully.");
            }
        }
    });

    //drop to unprivileged user
    if config.server.drop_user!="" {
        let _ = drop_privileges(&config.server.drop_user);
        log::info!("Dropped to user: {}",config.server.drop_user);
    }

    // here is the main listener loop that accepts client connections
    // and sends them out for processing
    loop {
        let (stream, addr) = listener.accept().await?;
        log::info!("Accepted connection from {}", addr);
        let config = Arc::clone(&config);
        let email_tx_clone = email_tx.clone();

        // wrap the accepted stream with TLS if enabled
        let stream = if let Some(ref acceptor) = tls_acceptor {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    // box the TLS stream
                    Box::new(tls_stream) as BoxedStream
                }
                Err(e) => {
                    // we only support TLSv1.2 and 1.3 here
                    log::error!("TLS handshake failed: {}", e);
                    continue;
                }
            }
        } else {
            // TLS not configured just use the plain TCP stream
            Box::new(stream) as BoxedStream
        };

        tokio::spawn(async move {
            // send the client to the handler
            handle_client(stream, config, email_tx_clone).await;
        });
    }
}

fn main() -> std::io::Result<()> {

    // version set at the top of the file
    let version  = get_version();

    // parse command-line arguments
    let matches = Command::new("DKIM Relay Server")
        .version(version)
        .author("Waitman Gobble <waitman@quantificant.com>")
        .about("A simple SMTP relay server with DKIM signing.")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Sets a custom config file")
                .num_args(1),
        )
        .arg(
            Arg::new("pid")
                .short('p')
                .long("pid")
                .value_name("FILE")
                .help("PID file path")
                .num_args(1),
        )
        .arg(
            Arg::new("daemon")
                .short('d')
                .long("daemon")
                .help("Run as a daemon")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("log")
                .short('l')
                .long("log")
                .value_name("FILE")
                .help("Sets the log file path")
                // default the log file to "/var/log/dkim-relay.log"
                .default_value("/var/log/dkim-relay.log")
                .num_args(1),
        )
        .get_matches();

    // get config file path; default to "config.toml" if not specified
    let config_path = matches.get_one::<String>("config").map(String::as_str).unwrap_or("config.toml");

    let pid_file = matches.get_one::<String>("pid").map(String::as_str);
    let run_daemon = *matches.get_one::<bool>("daemon").unwrap_or(&false);
    let log_file = matches.get_one::<String>("log").unwrap();

    // start logging
    init_file_logger(log_file);

    // log our PID
    let pid = process::id();
    log::info!("+++ dkim-relay version {:?} started with PID {}",version,pid);
    log::info!("Using configuration file: {}", config_path);

    // if specified daemonize before binding the network listener
    if run_daemon {
        // open log file for daemon and redirect stdout / stderr
        let stdout = File::options()
            .append(true)
            .create(true)
            .open(log_file)
            .expect("Failed to create/open log file");
        let stderr = stdout.try_clone().expect("Failed to clone log file handle");

        let mut daemonize = Daemonize::new()
            .stdout(stdout)
            .stderr(stderr);

        // create PID file if specified
        // can use with rc script
        if let Some(pid_path) = pid_file {
            daemonize = daemonize.pid_file(pid_path);
        }

        match daemonize.start() {
            Ok(_) => log::info!("Daemonized successfully"),
            Err(e) => {
                // oops we gotta bail
                log::error!("Error during daemonization: {}", e);
                process::exit(1);
            }
        }
    }

    // load the configuration
    let config_content = log_expect!(fs::read_to_string(config_path),
        "Failed to read configuration file");
    let config: Config = log_expect!(toml::from_str(&config_content),
        "Failed to parse configuration");

    log::info!("Loaded Config {}",config_path);
    log::info!("Logging to {}",log_file);

    // build and run the Tokio runtime
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_server(config))
}
//the end

