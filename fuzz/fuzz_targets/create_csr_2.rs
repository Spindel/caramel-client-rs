#![no_main]
use libfuzzer_sys::fuzz_target;
use caramel_client::certs::create_csr;

const VALID_KEY_DATA1: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtHkqLKRbMYyyQ0diUtuLW/kpZdxIAji9fjdOK1RJXZz8GKiz
w2EF3vT0IQ3fdF4CW1eF6WFfdu8bpCAQBbkTHvMsqR9xuPiSlIw2RN3NOVxknTon
RS7VO+FSxfQSdSCPYpFITVCCrRpa7IK1Mp8C+RygM/rbC6aKxKREq8Kkw2PFkC74
s+Q+TL9VpnHWppUfDLf5n6e5Yu0l8hChz98btnbsMZw1PwtZn86oe5QFw6TjkepY
X7IXt3JUlvqVAMlI++6M7HRaS1qcigumvz+uK/yxpKQ3vLJnjfbdnilHDYJo+Atp
ziGt16NUJgv7GJb+nMzUBegMNqRqAH7uoZy9kQIDAQABAoIBAGP4+rPgF+RK3DUI
xh7AH2LDk3spm3oflFjmqha2ii2hWMUQLwR8KpRnfRUSakY8DXIr+bJejlOEAPva
BwYkj8MFUigdkxG0IP7I7QcZFyY/WD0AieB5IQYau4+MtOzNLKCdej/Z6Yman+OE
RHvWOf9lLBmfTNgXWae0l5XOLRdOr0N59a9BfNeyODt4CfrBJ7QaM0F/H2s0pFzL
Yce7zUtGHKLDLiD6AsiV8JpeG1Ab+MMKsU3RRShvww8AsP0OyDfJclUCi+9v3tNJ
6SnEad0qzWJ7PMEJwGTXhlYYDMXv7xgpdus9AOV+9HsuZGqOgsDu7VRoClxL1hy7
kfIhDUECgYEA3y64NfwpYokOcDVYNy8q9Ny55htClUH3P05JTwijNderQqrDvAeh
RKEGRR8wqt3TzQ1iPiq92ShUHQArw3UpIcXfc78rPO9ptOBU7aiF1ggAvk4MTjOf
I/uAP0b0COSqreajcCIHoQwiqqcJsuYzmc30LebrIttqPbad4xlkGxcCgYEAzwK9
GU1l7cBs+eEiKME8kO8ay3PLBAN8DY3kcTgTeJsTlrw2kDQVxnNh4NH1/NBxAuSi
XCZEx8x1zRdKBgZhf4HAufak1bOF2KKLT3VnOxO0WFX37oao+QEzomtNXf2Khd7M
2Ot7VRkgk+AEp3iLdzPQFiH/EFz9HiACVnbTNZcCgYBDJSYsr7mvuHZMkfABYkJ1
Orb/ILJuf1Moi6AIlBuuRj1zKDcNKep94EgnoZOdxHFFXsJw26EUZUqxEu0Xt/bw
/zwT8a7LfWf7EAbdHXduhifbGVYgbO1zAOZ7oxgmWM101k/Tm5lZ/XGsj+aeGR3r
JwhQiwmxCfwzpu5ndaslbwKBgQDF7FRokLvX6ZdIApzqYndKC5KO25NLrxk4zGWS
ao8TTRIZmLKChYocR81ZauXKZnDm1zr06BHzBeXLxWyc/hTSGHjwVIWdXRun2SFh
Q1sD/P79RpTalh2QljmMHRPHvdZn0HIDJIKzBmdDe3h3tqWBvyRBRRfdyUqpNumF
Se7+2QKBgAVYMQadBE2WSyzjOpzgIz/7xGA8y+DkYPcQelc7kSJvTEZFVDfMBktd
n2+g4Al8cu6674THUVHzzr5bmZJ/XQFT6KQhG1KRlCiikOFhgoaEUU2Sy6myon3K
2S5luFEBVaDbYLvPa4Jp1tjiIT4QggCtJnq9OV0yzI6SYvJZjslC
-----END RSA PRIVATE KEY-----
";


use arbitrary::Arbitrary;

// This implements the validation using random data as CA cert & name
#[derive(Arbitrary, Debug)]
pub struct Certmake {
    cacert: Vec<u8>,
    name: String,
}

fuzz_target!(|data: Certmake| {
    let valid_key = VALID_KEY_DATA1.as_bytes().to_vec();
    let _ = create_csr(&data.cacert, &valid_key, &data.name);
});
