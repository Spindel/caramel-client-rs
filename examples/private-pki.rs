use caramel_client;
use std::io::Write;

// Note, this example almost 1:1 implements how the "normal"  Caramel File Request type works.
// Perhaps this example should instead open an SQLite-database and use that?
//
// I.e. Should the example be a simple adaptor on the other logic?

// We pin a CA-certificate here. If you run the client on a machine that does not have a
// certificate store, this is important.
//
// Most deployments however can just use a letsencrypt certificate for `ca.example.com` and the lib
// will do the rest.
const CA_CERT: &str = "-----BEGIN CERTIFICATE-----
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
Yegr7LgJOyQdp1MtVENfRFL5Ag==
-----END CERTIFICATE-----
";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    panic!("Not implemented");
    // use example `hostname` or `cat /etc/machine-id`  to identify a single machine.

    let client_id = "test-request-please-ignore";
    let csr_path = Path::new("test-request-please-ignore.csr");
    let key_path = Path::new("test-request-please-ignore.key");

    /// A CA (Certificate Authority) has a host-name to reach them at, and a CA Certificate (root
    /// cert) that will sign requests for this CA.
    ///
    /// Here, we assume that the server is using public certificates signed by the built-in CA
    /// certificate. This means we get Certificate Pinning as well.
    /// Suitable for embedded areas where you do not ship a bundle of CA certificates.
    let mut CA = caramel_client::Authority::new_with_cert("ca.sommar.modio.se", CA_CERT)
        .expect("Error parsing CA cert");

    /// Verify can fail, it performs network requests to make sure we can connect, as well as
    /// validates that the CA certificate seems `ok` for our use-case.
    /// If this fails in your application code, you should either re-use a cached certificate
    /// (offline, otherwise)  or prompt user to upgrade or try again.
    CA.verify().expect("Error connecting to CA server");

    /// A new Request. A request always binds to a CA (whom will sign it) and an `client_id` that
    /// identifies us.
    let mut caramel_request = caramel_client::CertificateRequest::new_with_ca(client_id, CA);

    /// This code is extra verbose, and you should really try to use a keychain for the private
    /// key. If you want a file-backed API, there's a specific helper for that which you can use
    /// instead. (See `examples/minimal.rs`)
    if !key_path.exists() {
        /// Generate a new Private Key File.
        caramel_request
            .new_key()
            .expect("Crypto error generating key");

        /// Read out the key file, so we can write it to our secure storage.
        let key_file_content = caramel_request.key_file();
        println!("Save this somewhere safe, in a keychain or so.");
        println!("This example saves it to disk without caring about security.");
        println!("\n{}", key_file_content);
        let mut file =
            std::fs::File::create(&key_path).expect("Error opening key file for writing");
        file.write_all(&key_file_contents)
            .expect("Error writing key file to disk");
    }
    let key_data = std::fs::read(key_path).expect("Error reading private key from disk");
    /// Load the private key into the Request first.
    caramel_request.load_key(key_data).expect("Invalid key?");

    /// We now have a key. First, new CSR if need be.
    if !csr_path.exists() {
        /// Generate a new Certificate Request file.
        caramel_request
            .new_csr()
            .expect("Crypto error generating CSR");
        /// Read out the CSR data, so we can write it to disk.
        let csr_file_content = caramel_request.csr_file();
        println!("This file can be re-generated or loaded from disk again, and contains nothing secret: \n{}", csr_file_content);
        let mut file =
            std::fs::File::create(&csr_path).expect("Error opening CSR file for writing");
        file.write_all(&csr_file_content)
            .expect("Error writing CSR file to disk");
    }
    /// CSR already existed, now we load it instead.
    /// We load the CSR (Certificate Sign Request) here, this data is public, but needs to match
    /// the PRIVATE KEY from above.
    let csr_data = std::fs::read(csr_file).expect("Error reading CSR file from disk");
    /// Load the CSR into the request (Certificate Sign Request)
    caramel_request.load_csr(csr_data).expect("Invalid CSR?");

    /// Attempt to download the Certificate that matches our Request from the server.
    /// This part of the request should be called regularly.
    /// How often depends on how long life-time your certificates have.
    /// I recommend calling it at least every 1/4 of the life-time of your certificates. So if a
    /// certificate is valid for 4 hours, I recommend performing it every hour.
    ///
    /// After the download, it's usually a good idea to write it to disk, keychain or register it
    /// with your TLS libraries. Since that may cause a reconnection, users might want to take care
    /// to only update if the certificate has changed.
    match caramel_request.fetch_certificate() {
        /// Happy path.
        /// We got the certificate and can now continue
        Ok(CaramelClient::Status::Downloaded(certificate)) => {
            println!(
                "Fresh certificate. Place in appropriate place for later use:\n",
                certificate
            );
        }
        /// Less happy path.
        /// We have a pending request, maybe the server isn't signing requests automatically.
        /// Perhaps we are waiting for a human to press a button or verify a request manually.
        Ok(CaramelClient::Status::Pending) => {
            println!("Certificate was posted, but has not been signed yet.");
        }
        /// Sad path.
        /// We had a valid request, but it has been rejected by the server.
        /// Our only recourse is to delete both the CSR and the Private Key and start over from
        /// scratch.
        Err(CaramelClient::Status::Rejected) => {
            panic!("This key is rejected. Delete key and CSR and start over.");
        }
        /// Sad or Happy path.
        /// For some reason our request wasn't found on the server, so we need to POST it again.
        /// Maybe we have never done that before? Maybe the server forgot about us?
        /// Maybe the CSR and the Server do not match each-other?
        Err(CaramelClient::Error::Notfound) => {
            caramel_request
                .post_request()
                .expect("Error posting request to server");
        }
        /// Other errors, typoed DNS, internal server error, offline, etc.
        /// Usually, "try again later" or ask an operator.
        Err(_) => {
            panic!("Some other error happened. See documentation for possible errors.");
        }
    }
}
