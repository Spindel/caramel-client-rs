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


### Embedded client application

On embedded firmware, we do not want to ship a large amount of public CA
certificates, and want to protect us against MITM and other interesting
problems, so we embed the CA certificate with the hardware.

For this use-case, the client is called by other applications, thus signifying
the status of the key with an return-code, and never blocking or looping.

In these cases, there is no administrator to access or debug, thus the client
needs to be able to automatically recover, usually by starting over "from
scratch" in case of certain error-codes from the Caramel server.

Here, the application uses a "well known" serial number from hardware, or
the MAC address of the device, as their client-id.

Unlike the command-line client above, the CA-certificate should be able to use
one specified elsewhere, and the Private Key and Certificate are stored in a
single well-known file with specific ownership and permissions.

To avoid concurrent invocations causing trouble, the _key_ file is `flock`-ed
(Exclusive, returning an unspecified error-code if another process is in
progress) while it is working with Keys and/or CSR-requests, thus causing an
error-code exit if the program is started concurrently, which it can be, as
multiple different tools will each attempt to start the well-known "Make sure
we have keys" application if a key does not exist.

To facilitate debugging and monitoring, the Client ID is part of the user-agent
in this mode of operation.

And to further grant identification, if the client deems that it has a useable
certificate, it defaults to passing a client certificate to the server.

This client also compares the time-stamp of the server-side and our local
certificate, and doesn't fetch the file new in case it hasn't been updated, in
order to save bandwidth on metered connections.

Status codes in use:

- Succesful request: 0
- Unchanged file: 0
- Pending signature: 69
- Misc error: 127

Error handling:

- Rejected: Wipe key, CSR and start over


### Embedded library application

On mobile devices (smartphones) the library is used in the background to
facilitate API connectivity. The first time the application is started it
generates a new UUID and Key, and posts that to a Caramel Server in the
background.

The caramel server is configured to automatically sign all previously unseen
UUID-based requests, thus the client can almost instantly get a certificate.

At this step, an anonymous user has a _distinct_ and trusted identity to the
server, while still being able to be anonymous.

If the service then requires it, a proper _user authentication_ step can
happen, using fex. OAuth or email call-back to tie a user identity to this
device's account.

For thise use-case, it is important to never attempt to store a file directly
to disk, and only return file-like objects that can be stored in system
key-chains or per-application databases.
