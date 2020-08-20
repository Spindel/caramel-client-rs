use caramel_client;

const CA_SERVER: &str = "ca.sommar.modio.se";

// This example attempts to show how to use the Caramel Client library where we do not store data
// as files on disk, but in some kind of external storage.
// In this explicit case, we use an environment variable for the Private Key, and always
// re-generate the CSR (Certificate Sign Request).
//
//
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // use example `hostname` or `cat /etc/machine-id`  to identify a single machine.
    let client_id = "test-certificate-please-ignore";
    /// The CaramelRequest is the basic interface, that is most likely to be useful and adaptible
    /// by others.
    ///
    ///
    /// This API exposes the following functions that are useful:
    ///     get_cacert              - Download a CA Certificate from server
    ///     load_cacert             - Load a CA Certificate from a buffer
    ///     new_key / load_key      - Makes a Private Key available
    ///     new_csr / load_csr      - Makes a CSR available
    ///     post_csr                - Post the CSR to the Certificate Authority
    ///     get_crt                 - Fetch a certificate from the Certificate Authority
    ///
    /// Note that it does NOT implement any file IO, but it does implement Network IO.
    let mut caramel_request = caramel_client::CaramelRequest::new(CA_SERVER, client_id);
    caramel_request
        .get_cacert()
        .expect("Error fetching CA Cert from server");

    // We try to load the private key from somewhere else.
    // In this case, an environment variable.
    // Do note that it's not recommended to store sensitive data as private keys in environment
    // variables, even if Kubernetes and Docker recommends it.
    // However, it is a convenient way to show the API.
    let env_privkey = std::env::var_os("PRIVATE_KEY");
    if let Some(val) = env_privkey {
        let key_data = val
            .into_string()
            .expect("Environment variable could not be parsed to string.");
        caramel_request
            .load_key(&key_data)
            .expect("Error loading Private Key Pair from external source.");
    } else {
        caramel_request
            .new_key()
            .expect("Error generating Private Key Pair");
    }
    println!("This is your private key. Save it somewhere safe.");
    println!("{}", caramel_request.key_data);
    /// Due to caramel design choices, it is safe to always re-generate the CSR data.
    /// As long as the CA Certificate, Client ID and Private Key are the same, the Request should
    /// always be bit-by-bit identical.
    caramel_request
        .new_csr()
        .expect("Error generating Certificate Sign Request");
    println!("{}", caramel_request.csr_data);
    caramel_request
        .post_csr()
        .expect("Error posting Certificate Sign Request");
    caramel_request
        .get_crt()
        .expect("Error downloading certificate from server");
    println!("This is our signed certificate. Store it or use it.");
    println!("{}", caramel_request.crt_data);
}
