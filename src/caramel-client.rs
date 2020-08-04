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
    server:String,
    client_id:String,
    key_file_name:String,
    csr_file_name:String,
    crt_temp_file_name:String,
    crt_file_name:String,
    ca_cert_file_name:String,
}

fn certificate_request(server:String, client_id:String) -> Result<String, Box<dyn std::error::Error>> {
    println!("Server: {} client_id: {}", server, client_id);

    // Create request info
    let request_info = CertificateRequest{  server:server.clone(), 
                                            client_id:client_id.clone(),
                                            key_file_name:format!("{}{}",client_id,".key"),
                                            csr_file_name:format!("{}{}",client_id,".csr"),
                                            crt_temp_file_name:format!("{}{}",client_id,".temp"),
                                            crt_file_name:format!("{}{}",client_id,".crt"),
                                            ca_cert_file_name:format!("{}{}",client_id,".cacert"),
                                            };

    ensure_ca_cert_available(&request_info)?;

    Ok("Received Certificate".into())
}

use std::path::Path;
fn ensure_ca_cert_available(req:&CertificateRequest) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("https://{}/root.crt", req.server);

    if !Path::new(&req.ca_cert_file_name).exists() {
        println!("Attempting to fetch CA cert"); // TODO change to logging
        //Setup session with url
    }
    Ok(())
}

// ---------------------------   Main process and input   ------------------------------------------
#[derive(Debug)]
struct InputError {
    program: String,
}

fn read_cmd_input() -> Result<(String, String), InputError>{
    let args: Vec<String> = std::env::args().collect();
    let server:String;
    let client_id:String;

    println!("{:?}", args); // DEBUG PRINT

    if args.len() == 3 {
        server = args[1].clone();
        client_id = args[2].clone();

        println!("Server: {} client_id: {}", server, client_id); // DEBUG PRINT

        return Ok((server, client_id));
    }
    else if args.len() == 1 {
        return Err(InputError{program: args[0].clone()})
    }
    else{
        panic!("Unknown Input Error!");
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>>{

    let (server, client_id) = match read_cmd_input() {
        Ok((s,c)) => (s, c),
        Err(e) => {
            eprintln!("Usage: {} <SERVER> <CLIENT-ID>", e.program);
            std::process::exit(1);
        }
    };

    println!("Server: {} client_id: {}", server, client_id);

    let res = certificate_request(server, client_id);

    if res.is_err() {
        eprintln!("{}", res.unwrap_err().to_string());
        std::process::exit(1);
    }
    else {
        println!("Certificate Success");
        Ok(())
    }

}
