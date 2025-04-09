# dkim-relay

Welcome to **dkim-relay**

This program runs as an SMTP server which creates a `DKIM-Signature` header for incoming emails, then relays the email to another SMTP server as configured. The user may use the included program `dkim-gen-keys` to create the RSA private key and BIND zone file entry for the corresponding public key. Keys are RSA (up to 2048 bits, though 1024-bit keys may be more practical on some systems due to DNS fragmentation issues).

**Note:**  
It is highly recommended that the configuration file is owned by root and has restrictive permissions (e.g. mode 400 or 600) so that private keys and credentials remain secure.

## Configuration

The configuration is stored in `config.toml`. You can customize the listen host, port, TLS, and authentication settings, as well as configure each domain you wish to sign.

### Example Config

```toml
[server]
listen_host = "127.0.0.1"
listen_port = 12050
drop_user = "dkim"
tls_enabled = true
cert_path = "/path/to/fullchain.pem"
key_path = "/path/to/privkey.pem"
auth_username = "user"
auth_password = "password"

[[domain]]
name = "example.com"
selector = "selector"
private_key = """
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
"""
relay = "tls://smtp.example.com"
relay_port = 587
helo_host = "this.host.name"
relay_auth_user = "user"
relay_auth_password = "password"
```

After setting up your domains, ensure the config file is secure (owned by root, `chmod 400` or `600`) to prevent unauthorized access to keys and credentials.

## Starting the Server

### Command-Line Options

- `-p` &mdash; PID file path  
- `-c` &mdash; Configuration file path  
- `-l` &mdash; Log file path  
- `-d` &mdash; Daemonize

### Example Command

```bash
./target/release/dkim-relay -p /var/run/dkim.pid \
    -c /root/dkim-relay/config.toml -l /var/dkim/dkim.log -d
```

*(For debugging, use the `debug` build instead of `release`.)*

## Installation

To build in release mode:

```bash
cargo build --release
```

For a development (debug) build with symbols:

```bash
cargo build
```

## How It Works

1. **SMTP Connection & Parsing:**  
   When a client connects and sends SMTP commands to deliver an email, the server parses the header and body into separate structures. The email is not altered except for the insertion of the `DKIM-Signature` header.

2. **Canonicalization:**  
   The server uses **relaxed/relaxed canonicalization**:
   - It compresses whitespace and converts header field names to lowercase.
   - Blank or missing headers can be included to "lock in" their absence, which prevents a third party from later inserting unauthorized headers without breaking the signature.

3. **Hashing and Signing:**  
   - A 32-byte SHA-256 hash is computed on the canonicalized body.
   - The canonicalized header data (which now includes a temporary `DKIM-Signature` header with an empty `b=` tag and a proper `bh=` value) is hashed.
   - The header hash is then combined with a fixed DER prefix (19 bytes for SHA-256) to form a 51-byte DigestInfo.
   - This DigestInfo is signed using the RSA private key with PKCS#1 v1.5 padding (using the OpenSSL crate to mimic the legacy RSA_sign/RSA_verify functions).
   - The resulting signature is base64‑encoded and inserted into the `b=` tag of the final `DKIM-Signature` header.

4. **DKIM-Signature Header Placement:**  
   The generated `DKIM-Signature` header (with the now–populated `b=` field) is added at the top of the header block. In cases where multiple DKIM-Signature headers exist, the topmost one is used for verification.

## Security Considerations

- **Config File & Privilege Dropping:**  
  The server starts as root (to bind privileged ports and read secure files) and then drops privileges to an unprivileged user (as specified in `drop_user`) once setup is complete.
  
- **TLS Support:**  
  TLS is optional for incoming and outgoing connections. Currently, the server supports STARTTLS on outgoing connections but not (yet) on incoming connections. The incoming connection supports SSL (typically SSL SMTP runs on port 465, but can be configured to your preference).

## How to Use

1. **Configure** your `config.toml` with your server and domain settings.
2. **Build** the server using Cargo.
3. **Secure** the configuration file (make sure only root can read it).
4. **Start** the server with the appropriate command-line options.
5. The server will parse incoming emails, create a DKIM-Signature, and relay the message to the configured relay server.

## License
```
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
```

