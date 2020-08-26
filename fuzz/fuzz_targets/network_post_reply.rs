#![no_main]
use libfuzzer_sys::fuzz_target;


use caramel_client::network::{
    inner_get_crt,CurlReply, inner_post_csr}
    ;


use arbitrary::Arbitrary;

// This implements the validation using random data as CA cert & name
#[derive(Arbitrary, Debug)]
struct CurlDataReply {
    pub url: String,
    pub status_code: u32,
    pub data: Vec<u8>,
}



fuzz_target!(|data: CurlDataReply| {
    let cr = CurlReply{
        status_code: data.status_code,
        data: data.data 
    };
    let _  = inner_post_csr(&data.url, &cr);
    let _  = inner_get_crt(&data.url, cr);
});
