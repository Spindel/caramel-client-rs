# Caramel Client Rust

Rust Caramel client and Library

## What is it

Caramel is a simple Certificate Authority (CA) that lets users set up their own
root CA, sign clients & servers, and thereby identify machines to machines
using TLS (Transport Layer Security) with Client Certificate Authentication.

This is a _client_ that communicates against a [Caramel Server](https://github.com/ModioAB/caramel/).

It is responsible for:

1. Generating Private Keys
2. Creating CSR (Certificate Sign Requests)
3. Posting said CSR to the Caramel Server
4. Fetching signed certificates from the Caramel Server

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

## Getting Started

### Installation

To run Caramel Client Rust project you need to have the following packages installed:

 - rustup
 - rustc
 - cargo
 - pkg-config
 - clippy
 - fmt

Information on how to install rust and cargo can be found on [rust-lang.org](https://www.rust-lang.org/learn/get-started).
Follow thereafter [rust-lang/rust-clippy](https://github.com/rust-lang/rust-clippy) and
[rust-lang/rustfmt](https://github.com/rust-lang/rustfmt) to install clippy and fmt.

### Build and test project

Here comes a list of useful cargo commands which will help you when contributing to the Caramel Client Rust project.

| Command | Description |
|---------|-------------|
| cargo build  | Build all binary and library targets (crates). The resulting crate can be found in `caramel-client-rs/target/debug/` under the name `caramel-client-rs`. |
| cargo run  | Build and run all crates. |
| cargo check  | Compiles the code without generating crates. This makes it faster than `cargo build`. |
| <nobr>cargo test -- --nocapture </nobr>| Run all unit tests and get output from stdout and stderr during execution. |
| <nobr> cargo test \<FILE\>::test::\<FUNCTION\> </nobr> | Run a single unit tests. `<FILE>` is the file name and `<FUNCTION>` is the name of the test function. |
| <nobr>cargo clippy</nobr> | A collection of lints which helps you correct logical mistakes in your code.  |
| cargo fmt  | Formats the code so that it follows Rust's [style guide](https://github.com/rust-dev-tools/fmt-rfcs/blob/master/guide/guide.md). |
<br>

A step by step guide on how to use cargo can be found in the [cargo book](https://doc.rust-lang.org/cargo/index.html).

### Checks run in CI pipeline

The following checks are run by the CI pipeline:

 - cargo test
 - cargo check
 - cargo clippy --tests -- -D clippy::pedantic -D clippy::cargo
 - cargo fmt

You can use the alias below to rebase your changes ontop remote master.
The alias is similar to what is used by the CI pipeline.

    # git config alias.every "rebase -x 'git --no-pager log --oneline --max-count=1' --rebase-merges --autosquash origin/master"

The alias can be used as:

    # git checkout <COMMIT>
    # git every -x 'cargo check'

where `<COMMIT>` is the commit with your changes.

Check the [.gitlab-ci.yml](https://gitlab.com/ModioAB/caramel-client-rs/-/blob/master/.gitlab-ci.yml) file for more details.

### Visual Studio Code setup

To developers that are using Visual Studio Code we recommend the following plugins:

 - [Rust](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust):
  Adds language support for rust. Includes code completion, jumping between sections, formating, etc.
 - [Docker](https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-docker):
  Simplifies woring with Docker containers. Allows creating, managing and debugging
  containers inside Visual Studio Code.

If you want to use Visual Studio Code on WSL we also recommend that you install the
[Remote - WSL](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-wsl) plugin
which enables you to access files in the Linux environment in VS Code.

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

The above unit will then make sure that in /var/lib/example/tls/ there are a
files for CA certificate, Private Key, and a signed Certificate file for other
applications to use.

In this use-case, the caramel-client generates a Private Key, Certificate Sign
Request, and then continues to poll the server for a signed certificate, only
finally exiting with success once the CA has _signed_ the request.

This is because following services will require a certificate to continue
succesfully, thus they are supposed to wait until a certificate has been
received. Therefore, the simplest mode of the client is to loop forever as it
waits for the server to sign the request, something that requires manual work
by an administrator.

As the servers have administrators watching over them, there is no need to
automatically attempt to recover from error situations, and it's important to
fail with a good error message for administrators to be able to track the
status of the application.


### Embedded client application

On embedded firmware, we do not want to ship a large amount of public CA
certificates, and want to protect us against MITM/Man In The Middle) and other interesting
problems, so we embed the CA certificate with the hardware.

For this use-case, the client is called by other applications, thus signifying
the status of the key with an return-code, and never blocking or looping.

In these cases, there is no administrator to access or debug, thus the client
needs to be able to automatically recover, usually by starting over "from
scratch" in case of certain error-codes from the Caramel server.

Here, the application uses a "well known" serial number from hardware, or
the MAC address of the device, as their client-id.

Unlike the command-line client above, the CA certificate should be able to use
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
CA certificate, it defaults to passing a client certificate to the server.

This client also compares the time-stamp of the server-side and our local
certificate, and doesn't fetch the file new in case it hasn't been updated, in
order to save bandwidth on metered connections.

Status codes in use:

- Succesful request: 0
- Unchanged file: 0
- Locked file: 1
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


## Using the container

    # podman pull registry.gitlab.com/modioab/caramel-client-rs/client:master
    # podman run -ti --rm=true -v $(pwd):/data:rw registry.gitlab.com/modioab/caramel-client-rs/client:master CA.EXAMPLE.COM  TEST-CERTIFICATE-PLEASE-IGNORE
