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


## User stories

For developers, these are some of the basic scenarios that this crate should be
able to fulfill, either as a stand-alone application, or as a library embedded
in other software.

### Log client certificate & Key handling

In our infrastructure we want to authenticate uploading log-files to the
log-server using TLS with client certificates.

For this reason we have set up a separate CA for the log infrastructure, and
want to deploy a tool to all machines that submit logs.

The tool is launched by a systemd service and timer to keep the certificates
up-to-date.

    [Unit]
    Description=Refresh Caramel Certificate for %i
    After=network.target
    Wants=network-online.target

    [Service]
    Type=oneshot
    Environment=CARAMEL_CA=ca.example.com
    Environment=CARAMEL_CN=service.example.com
    Environment=CARAMEL_CERT_DIR=/var/lib/example/tls/
    WorkingDirectory=/var/lib/example/tls/
    ExecStart=/usr/local/bin/caramel-client $CARAMEL_CA $CARAMEL_CN


This service is then triggered with a timer, and/or depended upon by other
services using a simple drop-in file.

The above unit will then make sure that in /var/lib/example/tls/  there are a
files for CA certificate, Private Key, and a signed Certificate file for other
applications to use.

In this use-case, the caramel-client generates a Private Key, Certificate Sign
Request, and then continues to poll the server for a signed certificate, only
finally exiting with success once the CA has _signed_ the request.

This is because following services will require a certificate to continue
succesfully, thus they are supposed to wait until a certificate has been
received.  Therefore, the simplest mode of the client is to loop forever as it
waits for the server to sign the request, something that requires manual work
by an administrator.

As the servers have administrators watching over them, there is no need to
automatically attempt to recover from error situations, and it's important to
fail with a good error message for administrators to be able to track the
status of the application.
