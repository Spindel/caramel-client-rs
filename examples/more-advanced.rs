use caramel_client;

const CA_SERVER: &str = "ca.sommar.modio.se";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // use example `hostname` or `cat /etc/machine-id`  to identify a single machine.
    let client_id = "test-certificate-please-ignore";
    /// The CaramelRequest is the basic interface, that is most likely to be useful and adaptible
    /// by others.
    ///
    ///
    /// This API exposes the following functions that are useful:
    ///     get_cacert              - Download a CA certificate from server
    ///     load_cacert             - Load a CA certificate from a buffer
    ///     new_key / load_key      - Makes a Private Key available
    ///     new_csr / load_csr      - Makes a CSR available
    ///     post_csr                - Post the CSR to the Certificate Authority
    ///     get_crt                 - Fetch a certificate from the Certificate Authority
    ///
    /// Note that it does NOT implement any file IO, but it does implement Network IO.
    let mut CR = caramel_client::CaramelRequest::new(CA_SERVER, client_id);
    CR.get_cacert().expect("Error fetching CA Cert from server");
    CR.new_key().expect("Error generating Private Key Pair");
    println!("{}", CR.key_data);
    CR.new_csr()
        .expect("Error generating Certificate Sign Request");
    println!("{}", CR.csr_data);
    CR.post_csr()
        .expect("Error posting Certificate Sign Request");
    CR.get_crt()
        .expect("Error downloading certificate from server");
    println!("{}", CR.crt_data);
}
