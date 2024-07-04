# SSL Certificate Information Extractor

This program connects to multiple servers over SSL/TLS, retrieves their certificates, extracts specific information, and stores it in a JSON array.

## Prerequisites

Before you can compile and run the program, you need to have the following libraries installed:

- OpenSSL library
- JSON-C library
- POSIX Threads (pthread) library

## Installation

To install the necessary libraries on a Debian-based system, you can use the `make install` command:

```sh
make install
```
## Compilation
To compile the program using the provided Makefile, run:

```sh
make
```

## Usage

```sh
./ssl <input_file> <cafile>
```

`<input_file>`: A file containing IP pairs, one per line.
`<cafile>`: The CA file (CA.pem) to verify the server certificates.

### Input File Format
The input file should contain IP pairs, one per line. If the port is not specified, the default port 443 will be used. Example:

```sh
192.168.1.1:443
example.com:8443
8.8.8.8
another.example.com
```

### Creating Your Own CA.pem File

```sh 
openssl genpkey -algorithm RSA -out ca.key -aes256
```
You will be prompted to set a passphrase for the private key.

Create a Self-Signed CA Certificate:

```sh
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt
```

During this process, you will be asked to fill in details such as country, state, organization, etc. This information will be embedded in the certificate.

Combine the Private Key and Certificate to Create CA.pem:

```sh
cat ca.crt ca.key > CA.pem
```

## Example

```sh
./ssl input.txt CA.pem
```
## Output
The program will create an output.json file containing the extracted certificate information in a pretty-printed JSON format.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing
Please feel free to submit pull requests and issues. Any contributions, large or small, major features, bug fixes, or documentation improvements are welcomed.



