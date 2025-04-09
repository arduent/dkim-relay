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

use clap::{Arg, Command};
use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use pkcs8::{EncodePrivateKey, EncodePublicKey};
use pem::parse;
use base64::{engine::general_purpose, Engine as _};

// software version
fn get_version() -> &'static str {
  "0.1a"
}

fn main() -> Result<(), Box<dyn std::error::Error>> {

    // version set at the top of the file
    let version  = get_version();

    // parse command-line arguments
    let m = Command::new("DKIM Key Generator")
        .version(version)
        .author("Waitman Gobble <waitman@quantificant.com>")
        .about("Create pki DKIM keys for signing.")
        .arg(
            Arg::new("bits")
                .short('b')
                .long("bits")
                .help("Key bitlength should be 1024 or 2048")
        .default_value("1024")
        .value_parser(["512", "1024", "2048"])
        )
        .arg(
            Arg::new("selector")
                .short('s')
                .long("selector")
                .help("DNS selector name for this key")
                .default_value("selector")
        )
        .arg(
            Arg::new("domain")
                .short('d')
                .long("domain")
                .help("DNS domain name for this key")
                .default_value("example.com")
        )
        .get_matches();
        
    let sbits = m.get_one::<String>("bits")
        .expect("Default value is set");
    let bits: usize = sbits.parse().expect("Invalid number");

    let selector: &String = m.get_one("selector")
        .expect("selector");

    let domain: &String = m.get_one("domain")
        .expect("example.com");

    // create a secure random number generator
    let mut rng = OsRng;

    // generate a 1024-bit RSA private key
    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .expect("failed to generate a key");

    // derive the associated public key
    let public_key = RsaPublicKey::from(&private_key);

    // export the private key in PKCS#8 PEM format
    let private_key_pem = private_key.to_pkcs8_pem(Default::default())?;
    println!("\n{}\n", private_key_pem.as_str());

    // export the public key in PKCS#1 PEM format
    let public_key_pem = public_key.to_public_key_pem(Default::default())?;

    let parsed_pem = parse(public_key_pem.as_bytes())?;
    
    // re-encode that raw binary data as Base64 (single-line, no headers)
    let base64_pubkey = general_purpose::STANDARD.encode(parsed_pem.contents());

    // build the DKIM TXT record string
    let dkim_txt_record = format!("{}._domainkey.{}. IN TXT \"v=DKIM1; k=rsa; p={}\"", 
        selector, domain, base64_pubkey);

    // print for DNS zone
    println!("\nDKIM DNS record ({} bits):\n\n{}\n\n", bits, dkim_txt_record);

    Ok(())
}
//the end

