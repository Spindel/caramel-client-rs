use caramel_client;

const CA_SERVER: &str = "ca.sommar.modio.se";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // use example `hostname` or `cat /etc/machine-id`  to identify a single machine.
    let client_id = "test-certificate-please-ignore";
    /// The FileRequest will always back the stored data to disk in the current directory.
    /// This is the simplest action and makes for the smallest example, but also has very limited
    /// API and control.
    /// The API is only really suitable if you want files to exist in the current directory and
    /// trying to automate as much as possible.
    ///
    /// Note that the FileRequest will invariably _delete_ local data (key, csr, crt)  and
    /// re-create them if it gets errors from the server.
    let mut CR = caramel_client::FileRequest::new(CA_SERVER, client_id);
    let attempts = 1;
    /// Try once, does not necessarily wait for the server to sign a request
    CR.try_loop(attempts)
        .expect("Something went wrong in the first attempt");
    /// Try forever. Does what it says on the tin, will retry all steps until we get a working
    /// certificate, or a hard failure that we cannot deal with.
    CR.try_forever()
        .expect("Waiting forever for the server went wrong");
}
