// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2020 Modio AB

use sha2::{Digest, Sha256};

/// Take a string buffer and calculate it's hex-ified sha256sum
#[allow(dead_code)]
pub fn sha256hex(indata: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&indata);
    let result = hasher.finalize();
    format!("{:x}", result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum() {
        const CSR_DATA: &str = "-----BEGIN CERTIFICATE REQUEST-----
MIICpDCCAYwCAQAwXzELMAkGA1UEBhMCU0UxEDAOBgNVBAoMB01vZGlvQUIxDzAN
BgNVBAsMBlNvbW1hcjEtMCsGA1UEAwwkMGI3YzY3YmItYzBhNS00ZmEwLTg5YzQt
YWNlNTE1NTk3NjdiMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApxh7
G/E4eUHGPdEyDVa4gGp/UQPz+SP3T5JNPB3R0vmE46xLRZ3JdDuOIrTVy/gLXfDb
h10q+sYbeGaQeTf5orj14F6KeV9EkujM8t5e1niRzxG1crURGEReqkAAyODacjBn
2WWxQ5kEtkddp6kVIpXMKPI+fzmgtwuUlWpNrIPe1f6H1C55sffLWXnP6g84fNJC
g/U0T2lVklnf6WxwkUyHxRfnfEtjBHLi8Psaz4VFUKcBrh4juGOU5wHlOMWaHavr
FZiSdtc96nKG+5JeKbTGVxHRfqk6uVcME2LRL9HXp1oTYG5yK8Q+tLTOOIuIxa34
jQ2UaQqrmP7SibrH3wIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAFy6iJJ/0CZn
KIwoNUiXJQPSnf+11k3eM84ujzHDB7ZSxsiFldnydL0PKlL5JOafwHt1no9P2o20
//kMmViwKpMMBR1z/e27J1ty0cJp4TSunzdvUXdikoeUjhxKEAoQUYl/i44NEIXI
ubn2UgVYsxNquQVSlyFG2PgKobi3edZQKxUqQr+9COMGZxzHmrbbZqwSzAShy29y
6tV+0QZcOk7FqKt9GO/baxwhbwJt57lDLZSeDFO5toKKnCLTmYsQsE0+5bkxW3vn
TdnsVmkvlgUQop1CsdXfhcEtt5AzfuvgNBrpUPgRs6IVyHF6N9o90d/7YwLxlvEX
kVDsWYTe/wk=
-----END CERTIFICATE REQUEST-----
";
        let out = sha256hex(&CSR_DATA.to_string());
        assert_eq!(
            out,
            "3f6edb2595850495f9f15214018aee629af959c68f72b331f15d40e8daaa81ed"
        );
    }
}
