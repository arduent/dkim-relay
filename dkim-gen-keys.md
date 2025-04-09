# dkim-gen-keys

`dkim-gen-keys` is a command-line tool for creating PKI DKIM keys for signing email. Use this utility to generate the RSA private key and the corresponding public key information for DNS (BIND) zone file entries.

## Options

- `-b, --bits <bits>`  
  Key bitlength should be 1024 or 2048.  
  **Default:** `1024`  
  **Possible values:** `512`, `1024`, `2048`

- `-s, --selector <selector>`  
  DNS selector name for this key.  
  **Default:** `selector`

- `-d, --domain <domain>`  
  DNS domain name for this key.  
  **Default:** `example.com`

- `-h, --help`  
  Print help information.

- `-V, --version`  
  Print version information.

## Example

To generate a new DKIM key with 1024 bits for the domain `example.com` with the DNS selector `selector`:

```bash
dkim-gen-keys -b 1024 -s selector -d example.com
```

## License
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


