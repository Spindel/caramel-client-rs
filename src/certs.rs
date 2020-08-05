use openssl::pkey::PKey;
use openssl::rsa::Rsa;

/// Load and verify that the private key is okay. not too short, can be parsed, etc.
/// should probably take a path or similar rather than a string.
/// placeholder
pub fn verify_private_key(filename: &String) -> Result<(), String> {
    Err("No can do".into())
}

/// Create a new private key and save it to filename
/// Should definitely take a path...
/// placeholder
pub fn create_private_key(filename: &String) -> Result<(), String> {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    Err("Not implemented".into())
}

/// Create a subject from a CAcert + our expected clientid
/// placeholder
fn make_subject(cacert_filename: &String, clientid: &String) -> Result<String, String> {
    Err("Not implemented".into())
}

/// Make a CSR. Indata is so generic, but I don't know the openssl/rust datatypes well enough
/// placeholder
pub fn make_csr_request(indata: &String) -> Result<String, String> {
    Err("Not implemented".into())
}
