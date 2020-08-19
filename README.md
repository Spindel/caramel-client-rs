# Caramel Client Rust

Rust Caramel client and Library

## What is it

Caramel is a simple Certificate Authority that lets users set up their own root
CA, sign clients & servers, and thereby identify machines to machinse using TLS
Client Certificate Authentication.

This is a _client_ that communicates against a [Caramel Server](https://github.com/ModioAB/caramel/).

It is responsible for:

1. Generating private keys
2. Creating CSR (Certificate Sign Requests)
3. Posting said CSR to the Caramel Server
4. Fetching and the signed certificates from the Caramel Server


## Why use it

We use it for machine-to-machine authentication. By adding a systemd service or
a cron-job to create and maintain a Private Key and Certificate for machines to
authenticate against other machines, we eliminate the need for
computer-accounts and/or service passwords.

Common use-cases for us are:

- Log upload from servers to other servers
- Authenticating client-apps to database-servers
- Deploying Keys & Certificates for Monitoring services (Zabbix)
- Web-application to API authentication


## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
