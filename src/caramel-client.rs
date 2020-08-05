mod certs;

// pseudo code from Python of current application flow of caramel-clint
/*
def __init__(self, *, server, client_id):
    self.server = server
    self.client_id = client_id
    self.key_file_name = client_id + '.key'
    self.csr_file_name = client_id + '.csr'
    self.crt_temp_file_name = client_id + '.tmp'
    self.crt_file_name = client_id + '.crt'
    self.ca_cert_file_name = server + '.cacert'

def perform(self):
    self.assert_openssl_available()
    self.ensure_ca_cert_available()
    self.assert_ca_cert_available()
    self.assert_ca_cert_verifies()
    subject = self.get_subject()
    self.ensure_valid_key_file()
    self.ensure_valid_csr_file(subject)
    self.request_cert_from_server()
    self.assert_temp_cert_verifies()
    self.rename_temp_cert()
*/

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
            ca_cert_file_name: format!("{}{}", &client_id, ".cacert"),
        }
    }

    pub fn ensure_cacert(&self) -> Result<(), String> {
        let url = format!("https://{}/root.crt", self.server);
        if !Path::new(&self.ca_cert_file_name).exists() {
            println!("Attempting to fetch CA cert from {}", url); // TODO change to logging
                                                                  //Setup session with url
        }
        Ok(())
    }

    pub fn ensure_key(&self) -> Result<(), String> {
        if Path::new(&self.key_file_name).exists() {
            certs::verify_private_key(&self.key_file_name)?;
            Ok(())
        } else {
            certs::create_private_key(&self.key_file_name)?;
            Err("No can do".to_string())
        }
    }
    pub fn ensure_csr(&self) -> Result<(), String> {
        Err("Not implemented, ensure_csr".to_string())
    }
    pub fn ensure_crt(&self) -> Result<(), String> {
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

use std::path::Path;
fn ensure_ca_cert_available(req: &CertificateRequest) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("https://{}/root.crt", req.server);

    if !Path::new(&req.ca_cert_file_name).exists() {
        println!("Attempting to fetch CA cert"); // TODO change to logging
                                                 //Setup session with url
    }
    Ok(())
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
