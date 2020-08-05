use openssl::pkey::PKey;
use openssl::rsa::Rsa;

pub fn verify_private_key(filename: &String) -> Result<(), String> {
    Err("No can do".into())
}

pub fn create_private_key(filename: &String) -> Result<(), String> {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    Err("Not implemented".into())
}

fn make_subject(cacert_filename: &String, clientid: &String) -> Result<String, String> {
    Err("Not implemented".into())
}

/// Make a CSR
pub fn make_csr_request(indata: &String) -> Result<String, String> {
    Err("Not implemented".into())
}
