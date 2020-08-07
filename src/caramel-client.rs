mod certs;
mod network;
use std::path::Path;

//-----------------------------     Certificate crunch     ---------------------------------------------
struct CertificateRequest {
    server: String,
    client_id: String,
    key_file_name: String,
    csr_file_name: String,
    crt_temp_file_name: String,
    crt_file_name: String,
    ca_cert_file_name: String,
}

impl CertificateRequest {
    pub fn new(server: String, client_id: String) -> CertificateRequest {
        CertificateRequest {
            server: format!("{}", &server),
            client_id: format!("{}", &client_id),
            key_file_name: format!("{}{}", &client_id, ".key"),
            csr_file_name: format!("{}{}", &client_id, ".csr"),
            crt_temp_file_name: format!("{}{}", &client_id, ".temp"),
            crt_file_name: format!("{}{}", &client_id, ".crt"),
            ca_cert_file_name: format!("{}{}", &server, ".cacert"),
        }
    }

    pub fn ensure_cacert(&self) -> Result<(), String> {
        // should perform:
        // 1. Test for cacert
        // 2. Download root.crt and save to cacert if not.
        // 3. Verify cacert can be loaded
        if !Path::new(&self.ca_cert_file_name).exists() {
            println!(
                "Ca cert: '{}' does not exist, fetching.",
                self.ca_cert_file_name
            );
            network::fetch_root_cert(&self.server, &self.ca_cert_file_name)?;
        }
        certs::verify_cacert(&self.ca_cert_file_name)?;
        Ok(())
    }

    pub fn ensure_key(&self) -> Result<(), String> {
        // should perform:
        // 1. If no private key exists, create a new one and save it.
        // 2. Verify existing key files can be loaded and have a proper size / validation
        if !Path::new(&self.key_file_name).exists() {
            certs::create_private_key(&self.key_file_name)?;
        }
        certs::verify_private_key(&self.key_file_name)?;
        Ok(())
    }
    pub fn ensure_csr(&self) -> Result<(), String> {
        // should perform:
        // 1. If no CSR exist create a new one, building subject from "clientid" and "cacert"
        //    subjects
        // 2. Load the CSR and ensure that it's public key matches our private key

        if !Path::new(&self.csr_file_name).exists() {
            certs::create_csr_request(
                &self.csr_file_name,
                &self.ca_cert_file_name,
                &self.client_id,
                &self.key_file_name,
            )?;
        }
        certs::verify_csr(&self.csr_file_name, &self.key_file_name, &self.client_id)?;
        Ok(())
    }

    pub fn ensure_crt(&self) -> Result<(), String> {
        // Should perform:
        // 1. sha256sum of the CSR file
        // 2. try to GET the crt from the server  https://ca/{sha256(csr)}
        // 2a. Default to trusting the public PKI
        // 2b. If TLS error, add the cacert to the list of verifying certs for this connection
        // 3. If we get 404, Post the CSR to the server
        // 4. If we get 202 or 304,  wait?
        // 5. If we get 200, save the cert to a temp place
        // 6. If we get a cert, verify that it's valid
        //      ( openssl verify, and make sure it matches our pub keypair)
        // 7. Replace existing cert with the new temp one.
        //    Only if the two differ, to avoid updating ctime/mtime on files unnecessarily.
        //
        if Path::new(&self.crt_file_name).exists() {
            certs::verify_cert(
                &self.crt_file_name,
                &self.ca_cert_file_name,
                &self.key_file_name,
                &self.client_id,
            )?;
        }

        let temp_crt = network::get_crt(&self.server, &self.csr_file_name)?;
        certs::verify_cert(
            &temp_crt,
            &self.ca_cert_file_name,
            &self.key_file_name,
            &self.client_id,
        )?;
        println!(
            "moving {} to {}",
            &self.crt_temp_file_name, &self.crt_file_name
        );
        Err("Not implemented, ensure_crt".to_string())
    }
}

fn certificate_request(
    server: String,
    client_id: String,
) -> Result<String, Box<dyn std::error::Error>> {
    println!("Server: {} client_id: {}", server, client_id);

    // Create request info
    let request_info = CertificateRequest::new(server, client_id);

    request_info.ensure_key()?;
    request_info.ensure_cacert()?;
    request_info.ensure_csr()?;
    request_info.ensure_crt()?;
    Ok("Received Certificate".into())
}

/// Parse the commandline, returning server and client_id
/// Alternatively, an error message in an Err
///
fn read_cmd_input() -> Result<(String, String), String> {
    let mut args: Vec<String> = std::env::args().collect();

    println!("{:?}", args); // DEBUG PRINT

    let length = args.len();
    match length {
        3 => {
            let client_id = args.pop().unwrap();
            let server = args.pop().unwrap();
            Ok((server, client_id))
        }

        _ => {
            let program = args.first().unwrap();
            let err_msg = format!("Usage: {} <SERVER> <CLIENTID>", program);
            Err(err_msg)
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (server, client_id) = read_cmd_input()?;
    let res = certificate_request(server, client_id);

    if res.is_err() {
        eprintln!("{}", res.unwrap_err().to_string());
        std::process::exit(1);
    } else {
        println!("Certificate Success");
        Ok(())
    }
}
