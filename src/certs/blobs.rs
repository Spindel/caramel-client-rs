// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2020 Modio AB

//! This module should only be used in the test configuration.
#[cfg(test)]
pub mod testdata {
    #[must_use]
    pub fn convert_string_to_vec8(text: &str) -> Vec<u8> {
        text.as_bytes().to_vec()
    }

    pub const OTHER_CLIENT_ID1: &str = "080d8e74-e6d3-11ea-9c0e-00155d2d5bbd";
    pub const VALID_CLIENT_ID1: &str = "06bc4ab2-dbaf-11ea-9abc-00155dcdee8d";

    // ca.sommar.modio.se.cacert
    pub const VALID_CACERT_DATA1: &str = "-----BEGIN CERTIFICATE-----
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
Yegr7LgJOyQdp1MtVENfRFL5Ag==
-----END CERTIFICATE-----
";

    // ca.modio.se.cacert has some `interesting` misfeatures.
    // Including an subject in the "wrong order" and a suspicious version number
    pub const WORKAROUND_CACERT: &str = "-----BEGIN CERTIFICATE-----
MIIGhjCCBG6gAwIBAwIBADANBgkqhkiG9w0BAQ0FADCBhjELMAkGA1UEBhMCU0Ux
EDAOBgNVBAsMB0NhcmFtZWwxEzARBgNVBAcMCkxpbmvDtnBpbmcxETAPBgNVBAoM
CE1vZGlvIEFCMRcwFQYDVQQIDA7DlnN0ZXJnw7Z0bGFuZDEkMCIGA1UEAwwbQ2Fy
YW1lbCBTaWduaW5nIENlcnRpZmljYXRlMB4XDTE0MDYwOTE3MjY1NVoXDTM0MDYw
OTE3MjY1NVowgYYxCzAJBgNVBAYTAlNFMRAwDgYDVQQLDAdDYXJhbWVsMRMwEQYD
VQQHDApMaW5rw7ZwaW5nMREwDwYDVQQKDAhNb2RpbyBBQjEXMBUGA1UECAwOw5Zz
dGVyZ8O2dGxhbmQxJDAiBgNVBAMMG0NhcmFtZWwgU2lnbmluZyBDZXJ0aWZpY2F0
ZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALb+k4N44USm+Ukdptiu
wfNADSibfSZp3ACV9o+FJmpeq/bsEo4I8BCyfFQhU/QHZFZHd7yqqNOD0CvZcxeg
obHH2FK6S2WN3QHpNyy0RUuQ8x8+57j3vxk0Hx9GWoXYQuzib2eCLbhYTQq+E+5+
Y12NJxT3j1r76mzL9Ngztme3tVE5/VunGGU0t2m/AWNf1IKMysVVcn6ZM2GUIj8O
M9ip2nvXK9A5xuTvBij+FLDt8Lna+V+BiLGtRe3S0HUy/otGUGXTdVgCzQYWidxW
NLnFslQtiOgU79QfVAiINg9C+JQl9h0avtEhjS/B/dzJlo0WpQ/3LmunkJG/nlwd
f6KCdC3DNVHElngKETHCfusiHK3duMwl/JCUn5MgFzPTBslHWVUGJeSmUhU83sPR
VDLpKqYN+aNkp6+e1FzSseTaZI34zPyMZ+hlfUwVtDfRHZnSuwbkBuRMoSbSTR4j
bAMnnVQvvKzejbVfKBzZbZnqEG1lTERkj4a5fyC7gj+lgladgWpxFI2xd6P6JZDc
54YIFYyxGipUYUsSH+2JcLMxs3r7ZfRTzHaaXZaaik9iu/GhcstwO61LZlsd0vEX
sVO0u1Szj00VRcRAeiwhOEdRS8OrwDy9EsWobkd3VCOq+Qzfg3Q5xDL1XPCwU42k
K1cyeTGsCjoyIdf7Y0alP5o3AgMBAAGjgfwwgfkwEgYDVR0TAQH/BAgwBgEB/wIB
ADAOBgNVHQ8BAf8EBAMCAgQwHQYDVR0OBBYEFDtO6b/+3wjtjomvYyfJU8Y9sr0O
MIGzBgNVHSMEgaswgaiAFDtO6b/+3wjtjomvYyfJU8Y9sr0OoYGMpIGJMIGGMQsw
CQYDVQQGEwJTRTEQMA4GA1UECwwHQ2FyYW1lbDETMBEGA1UEBwwKTGlua8O2cGlu
ZzERMA8GA1UECgwITW9kaW8gQUIxFzAVBgNVBAgMDsOWc3RlcmfDtnRsYW5kMSQw
IgYDVQQDDBtDYXJhbWVsIFNpZ25pbmcgQ2VydGlmaWNhdGWCAQAwDQYJKoZIhvcN
AQENBQADggIBAE3Mqsya09FrFlf90ZkXH+7KyIBskTBTQggKPCsuHNfOSCW5akcQ
aFUZrjcFO4M4ZNcBpgBMng8IsU073+9aRlnbphpN28AFtGhc1nph1MaDpwuwsNBz
aBuHFwR+K1V/gtP7sQDnRUsPBLgT5Gg4dFAKyUTbyJdoGVbdX51TA2cm1fFkZJlm
vhaRgcby62Qm1dqMCW9r3XGobCkiINk6pHxdcWpZXX/sGlXwJnLdkn54AZ4aTH50
W4X3R08sRtP+hJUMJLw6u828VzT5t3CAWTIxZ3pQvUn1ePJcUiCCIViv1e4rlo2V
RUY9vvPTJhRmF/xbXD4xtGVTv8nrM0XSOFcENwn9ZXHZDKSt73jqxBqdmppwrTDT
f5lrEuuZrj26unnjSbnmAFz7BaS6rh6ZEBcaT7YgCPpd12FaJcr+7lNAUkFmkOvf
yj79XkWIgXnBOjtYve5aBRC46FcMkQkNhVfCU/e3uCp2l/Rc36hEm57OANtJbgLV
LDiYaWm3h7oVIRoG4WoBSBMLSQUgleQpX3IEiwO97vxjWkAdHA8IMI3HDUE9nnTi
mn1gxVw4FJ5FW9Jv0sBlS7RJHjGQnMb1eD2Whr+Dad1VBLNoAVdIKZZ1OT+mHYas
AW5slDlhh7vbggdS77Ocmq1FiaIT6xPF+CE4BmrO4GvLYDpi55FlUBOB
-----END CERTIFICATE-----
";

    // 06bc4ab2-dbaf-11ea-9abc-00155dcdee8d.crt
    pub const VALID_CRT_DATA1: &str = "-----BEGIN CERTIFICATE-----
MIIFWDCCA0CgAwIBAgIRALBtIYDbrxHqsV5+EcyPSKkwDQYJKoZIhvcNAQELBQAw
VjELMAkGA1UEBhMCU0UxEDAOBgNVBAoMB01vZGlvQUIxDzANBgNVBAsMBlNvbW1h
cjEkMCIGA1UEAwwbQ2FyYW1lbCBTaWduaW5nIENlcnRpZmljYXRlMB4XDTIwMDgx
MTA4NTAyMVoXDTIwMDgxMTExNTAyMVowXzELMAkGA1UEBhMCU0UxEDAOBgNVBAoM
B01vZGlvQUIxDzANBgNVBAsMBlNvbW1hcjEtMCsGA1UEAwwkMDZiYzRhYjItZGJh
Zi0xMWVhLTlhYmMtMDAxNTVkY2RlZThkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAtHkqLKRbMYyyQ0diUtuLW/kpZdxIAji9fjdOK1RJXZz8GKizw2EF
3vT0IQ3fdF4CW1eF6WFfdu8bpCAQBbkTHvMsqR9xuPiSlIw2RN3NOVxknTonRS7V
O+FSxfQSdSCPYpFITVCCrRpa7IK1Mp8C+RygM/rbC6aKxKREq8Kkw2PFkC74s+Q+
TL9VpnHWppUfDLf5n6e5Yu0l8hChz98btnbsMZw1PwtZn86oe5QFw6TjkepYX7IX
t3JUlvqVAMlI++6M7HRaS1qcigumvz+uK/yxpKQ3vLJnjfbdnilHDYJo+AtpziGt
16NUJgv7GJb+nMzUBegMNqRqAH7uoZy9kQIDAQABo4IBFjCCARIwDAYDVR0TAQH/
BAIwADAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwLwYDVR0RBCgw
JoIkMDZiYzRhYjItZGJhZi0xMWVhLTlhYmMtMDAxNTVkY2RlZThkMB0GA1UdDgQW
BBTU5gum61amsaUbcJmylRFvkRK/cDCBjwYDVR0jBIGHMIGEgBRj5vOZQ0mGYOFn
sXR0HD9Vp7lt9KFapFgwVjELMAkGA1UEBhMCU0UxEDAOBgNVBAoMB01vZGlvQUIx
DzANBgNVBAsMBlNvbW1hcjEkMCIGA1UEAwwbQ2FyYW1lbCBTaWduaW5nIENlcnRp
ZmljYXRlghBYB3RCpwsR6pK4fhHMj0ipMA0GCSqGSIb3DQEBCwUAA4ICAQB07k2d
RHD1pOMBN+aR28+cXiVEhid++DoYZlTyvKd+WQJC8fuOkwLXrgxwxAHzKQtsZusw
kPiOOXy3/ErgW/H472dD/pL8m0UbpouoDSwq7JWUDJeCSg3urthxsk5hzdKZz99p
uq1khkb9cTgOfO9zj4ma8ViEOUusuDPuCgeA8BW6Og4LoK6Whh4JQRn46843nI6Z
SrV8SL0eBRxF/USIVL44Kj1ViS3kB3Z5k/jTMJfkiUpe0Uy2EDqueeWe0js/iXKc
K7x/qzeG7tuaG9cZ9CGRel+H/vYEs8wrqV24gfjD7JCh7CZD7kHJysziHaPZhbpb
aVb1b7FGOuxdXxlYz5UKBHsV7NJv6/FSFoIdtL5Eap7leQDN1vaF6xMQ7N99Ad/O
jCECWW9kXVC/pjkApDW33NZFP1w0+n70ImOhWeMCi73JvnKoFzBxIee4vyg9G8He
lAYL4HJyEAJ79YjU0oUQ6WQtgWCGeSovD/vwx3AYCtIkl6MK8LV7HkRT/NVZSFbT
FKnIekTZZJCmjeUtZpMAr1r5/PEujjZrzHcoJtMFyUK27sG7FoeRzMgANEJvxduf
C4VHIzwLWa2yuegl76iORIuPuUeUtZrWAk5Sv+LuydNYbxyVxJ3CIspU8x+RI1Bb
P2ymBLrZQdX4YRW97Jm2Ot61moaA+ySS1qSEoQ==
-----END CERTIFICATE-----
";

    pub const SHA256_CSR_DATA1: &str =
        "144a55597a59202ddba07ff65a1d24ea32916e64f1e9b7befaee353e2bb41669";

    // 06bc4ab2-dbaf-11ea-9abc-00155dcdee8d.csr
    pub const VALID_CSR_DATA1: &str = "-----BEGIN CERTIFICATE REQUEST-----
MIICpDCCAYwCAQAwXzELMAkGA1UEBhMCU0UxEDAOBgNVBAoMB01vZGlvQUIxDzAN
BgNVBAsMBlNvbW1hcjEtMCsGA1UEAwwkMDZiYzRhYjItZGJhZi0xMWVhLTlhYmMt
MDAxNTVkY2RlZThkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtHkq
LKRbMYyyQ0diUtuLW/kpZdxIAji9fjdOK1RJXZz8GKizw2EF3vT0IQ3fdF4CW1eF
6WFfdu8bpCAQBbkTHvMsqR9xuPiSlIw2RN3NOVxknTonRS7VO+FSxfQSdSCPYpFI
TVCCrRpa7IK1Mp8C+RygM/rbC6aKxKREq8Kkw2PFkC74s+Q+TL9VpnHWppUfDLf5
n6e5Yu0l8hChz98btnbsMZw1PwtZn86oe5QFw6TjkepYX7IXt3JUlvqVAMlI++6M
7HRaS1qcigumvz+uK/yxpKQ3vLJnjfbdnilHDYJo+AtpziGt16NUJgv7GJb+nMzU
BegMNqRqAH7uoZy9kQIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAC2eWiWo1dLF
W0nDhMUYcs+WV0RkRkGXPMWT2VTsX/4Qr6u1zoigb45qEmJZVWifslAT6YHYuYbT
vyZHWSfcu+ka+3QEO+zZw0qhyyS/zJqCOXy/octV2a6HeRCJFDyukMwmYButFJf7
OJ8gE+qbV1IJU6kJ3Ug91iPL7NMi+EAdX2UiGpuxLZ/LEsWVZwGwbAOfM4LqZYoj
FLCklObK943kBSCN8C40xPaF+tqE22kRv+NHy2EQw53k5eP0P4R9ihBVUg7kSb1E
gDqnhtySwVDIEfRfdlrsvoVcKN45f4K63NNbeiwiGktTfxza/UGjniCpoBBRImo9
5Xls/X2U0Z8=
-----END CERTIFICATE REQUEST-----
";

    // 06bc4ab2-dbaf-11ea-9abc-00155dcdee8d.key
    pub const VALID_KEY_DATA1: &str = "-----BEGIN RSA PRIVATE KEY-----
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

    // to small key
    pub const TOO_SMALL_KEY_DATA1: &str = "-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQClt5G9F0OJIk4TzrmeTwXOnaXPH0L37yiVk9JUcWBbnQY5Esxj
rEe9hLK8U8+HT2C1F9/lHxxRbk4adz//UNCM9JvXTaamoK+Ty+6+MFGrZDtrD0Ys
KhRgdxZLjHkd3kF3fnZSa9CMB3HEni4GL6N0ukZoA4XOZoqF1XSwGup4aQIDAQAB
AoGAZgJH7hQh+IprcXnxfOe79WHJrWPa/2/ylZC3Ck/4NqzEJeHSexCT4K+Mrq0Q
tIRCTXdy1UF/VwkFfvklJe8DUKOltRiAVPE4BfD72gAVXu0yS4yoIN1LNWfTA2Dj
wHF21kATpDaKrAWeoFcpweiPkv6/ncOz9xqXDTaydQba1GECQQDSsF0l1rI2clUD
x2dtKU1Wwu4ov3HS3RwY+sOT8+sUaN/vpq7Xmx9WhGMl0dPoPlkn1esr7Ips0O47
fqfmuhidAkEAyVs/E0f4D3Aud4alT3QQ0kHSJ+b1Md1HrGyPA+J8LPVdjU0ubDMS
tOVFaR32lruT32JO2kC//kE9dJLzi+aXPQJAXWjT43LMkFcgWgyOTleBcnX6IRa/
4D0nt+t1yqLaFrJollfQLMcZncIUMzBUQyNhY8fz/AVjWdtHxBjjV+gqAQJAEB1i
Xeurmaizv1MiVcqHMhycch8UzonUG6OQipIMuBhnBVEA/x3TSHD07iW8v3GBsyYO
A3+dHf8gqPy9yxuITQJAArl6cfAw5L5o1tGm9lz4OeVbiGY1purYTy7bMpqYDgYv
wZxKcLyO4BjEsK7m7iVhhtBsHWp8/3+dSCb3eAIORw==
-----END RSA PRIVATE KEY-----
";

    pub const RANDOM_DATA_KEY_DATA1: &str = "-----BEGIN RSA PRIVATE KEY-----
Hems\u{f6}borna \u{e4}r en roman fr\u{e5}n 1887 av August Strindberg.
Den utgavs ett \u{e5}r efter Tj\u{e4}nstekvinnans son.
Strindberg gjorde \u{e4}ven en dramaversion av ber\u{e4}ttelsen 1889.
Romanen skrevs under Strindbergs vistelse i Schweiz och s\u{f6}dra Tyskland.

De inledande raderna \u{e4}r en s\u{e5} kallad in medias res-fras:
*Han kom som ett yrv\u{e4}der en aprilafton och hade ett h\u{f6}gan\u{e4}skrus i en sv\u{e5}ngrem om halsen.*
-----END RSA PRIVATE KEY-----
";

    // Uses CA_MODIO_SE_CACERT + VALID_KEY_DATA1, with Work-around logic.
    pub const WORKAROUND_CSR_DATA1: &str = "-----BEGIN CERTIFICATE REQUEST-----
MIIC1TCCAb0CAQAwgY8xCzAJBgNVBAYTAlNFMRcwFQYDVQQIDA7DlnN0ZXJnw7Z0
bGFuZDETMBEGA1UEBwwKTGlua8O2cGluZzERMA8GA1UECgwITW9kaW8gQUIxEDAO
BgNVBAsMB0NhcmFtZWwxLTArBgNVBAMMJDA2YmM0YWIyLWRiYWYtMTFlYS05YWJj
LTAwMTU1ZGNkZWU4ZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALR5
KiykWzGMskNHYlLbi1v5KWXcSAI4vX43TitUSV2c/Bios8NhBd709CEN33ReAltX
helhX3bvG6QgEAW5Ex7zLKkfcbj4kpSMNkTdzTlcZJ06J0Uu1TvhUsX0EnUgj2KR
SE1Qgq0aWuyCtTKfAvkcoDP62wumisSkRKvCpMNjxZAu+LPkPky/VaZx1qaVHwy3
+Z+nuWLtJfIQoc/fG7Z27DGcNT8LWZ/OqHuUBcOk45HqWF+yF7dyVJb6lQDJSPvu
jOx0WktanIoLpr8/riv8saSkN7yyZ4323Z4pRw2CaPgLac4hrdejVCYL+xiW/pzM
1AXoDDakagB+7qGcvZECAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQBKOZqH/Qhh
ucXEwuGdNOMtql/5ejluQsx60Pr+ILvWlHAwYiWGHeV7Qyp7v83uXo78tDl8kwLV
rJNovrXC08wY2WNpl2lt3u1tU7P3B5PajBkXrY1Tl/dyA8hAWVmi4eAUoPDTr6i3
X+uw8ZnBXx8cB6AyBdGa/Ggu8ntmW8hWLMWoe4NpxFpAnlqhuWZrJEbqxnYITBU4
imPopMEynqYdsZCGtw4LXO0jqKjD4mZHIsltV5JNNh8AzOnlZWhflqmEUB7UtuVE
2g/1ZJ2ru2VmHiD7uPcTAJzLjnnZjZRC7l4oxEaw+UqMTDsRLd7ipWMwGn9NdB9J
JLMstYxO4R/g
-----END CERTIFICATE REQUEST-----
";

    // 88f53b4b-1f86-4d8c-8cf0-f49576678b60.key
    pub const VALID_KEY_DATA2: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2CLGKLQxMK9YNtEmJ3O/H6p/6m0gGxbqrpC/KSk+2tseleVP
dw8f3bcMdJUfi3KaxhopxdMq3nCjIGnMZ2Iw43kFUPd+fkrcY3O/5e/NbaR3V/0H
orRrS2mmsV3cBdVoQTMjA3+VcrQ7bgr86qksyEIfc5sHQuDcwBShErpjKP5XJ1Bn
SO95JHVfI637xUPZhHTBmDi/pLkG3jR/9/fGXdMn+oA+RkBXptaovbno0U2E0QGP
z4TeVNzwbta8AIm2vYiNSy2MKd54U3Wvaonzw5r/3MhSBDfZ8xp8U/9A/xHTML68
XR8oaiphlBujqmesgPcK/DkgidYXMQcSP4mUEQIDAQABAoIBAQDD5YDFk8yh28uQ
o7B5QaeRA/A8gfv/kZ3T6s3YeNHHe6MVKWoE92hihG59nEujEJTHyR7jdqn8QwsX
bc0eRxkYk7AF2syDm0Z1vYvI1LjVD6Q709L/3ZcCGxhC2ld50htUPQ0XNqQ1+rWC
3+Ksrfkw6P2ownKqYzSxxADaAKWvmGx1BcFBgSWL1m6AhJ2CnxohOLaBifLn9MnJ
X3d2BiMtkGAHZzCduFiM1NLwEg9+YtyYxFFJoSyBsEd8rncgJZW9zfDynC1SZBoX
HMIGBd5s2w8mWGW0xQRCsO4bFZ2130R4QJ86EByZUXaGv058actFZtOxeT+ImrGv
LuDUI4WhAoGBAPaanQlZY8DJCfX1W37dct9jmuZZQUYXjcKeg3fhBgGlqhabaQXj
Zt+UMq7niapYAVN3Bf2B1lcZLhbJVS/0N5kMq6/XPOc00bxqdAx4DWUAWUi5dSUD
QU93lWPrh0aGqmNDlSY4WT5c/bRPUr6cD/oPMvbMD1SyrbDZzzx2FalDAoGBAOBe
+R+jEB7FJZUlIzoXGbSVpo3eC/hajnPe+Zq8YXjrp8kJjcpYZgJgbzm0Gj+2jhoh
0FyPl+JYsWWAugpQHnFAT3DyqNOlklFBaco9guq9FCcMQtDSTWveAGK5wIRVUX/B
Ai4lZYTrxglBYXjqqBEf8LkqJI0d5bWQNT/LS74bAoGBAOrH+ziadWFnRed4qJqZ
RTOvhhtG4OFVrW6cMfihMXHCArSxU4T6ose8NaDV6fhW/zQyvm5D/ghAfePN3R/h
uEkrig3Is0BAxmpHQ6NXbRE7CsY1Y3VQqw54gK933vvjXDdTcZ3IyhaYvCa92r6E
oKVncRMM5o+x6bHVPPuIRUk3AoGAFjOvqR7EmJbfiiubmcLxazonugAP5Spo0DRv
NI2Rg5qmBrGoUy5+IZwTRX1533YcB5/y80XOPLqUCzw6rIyTBpfbhIyuggrvOJUl
d7qwerPtC5QeBHXa7WKRXTOORkn+/4pEwfY3XnjKJt5OW920dcVYV6pA5angsh+r
9T0TqKMCgYBhcIkJ2LcLFzFTuo0Y6XUdrymH3wqEEvNNELjiB4FOuO1VSPklZK1W
cUYQwlnafJBdgkHjUq8vKqkr44iPlhZCVbr3c+RKld9hyUMs3b7i5/Uqb9vlCgFW
5wDtzr8uhurgUespkeu2l/UGtozAGkld+hJ2njqB5KGa8v5ATeIIsg==
-----END RSA PRIVATE KEY-----
";

    // 88f53b4b-1f86-4d8c-8cf0-f49576678b60.crt
    pub const _VALID_CRT_DATA2: &str = "-----BEGIN CERTIFICATE-----
MIIFWDCCA0CgAwIBAgIRAMf+3LbX+hHqu/x+EcyPSKkwDQYJKoZIhvcNAQELBQAw
VjELMAkGA1UEBhMCU0UxEDAOBgNVBAoMB01vZGlvQUIxDzANBgNVBAsMBlNvbW1h
cjEkMCIGA1UEAwwbQ2FyYW1lbCBTaWduaW5nIENlcnRpZmljYXRlMB4XDTIwMDgw
NjE1Mzc0OFoXDTIwMDgwNjE4Mzc0OFowXzELMAkGA1UEBhMCU0UxEDAOBgNVBAoM
B01vZGlvQUIxDzANBgNVBAsMBlNvbW1hcjEtMCsGA1UEAwwkODhmNTNiNGItMWY4
Ni00ZDhjLThjZjAtZjQ5NTc2Njc4YjYwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA2CLGKLQxMK9YNtEmJ3O/H6p/6m0gGxbqrpC/KSk+2tseleVPdw8f
3bcMdJUfi3KaxhopxdMq3nCjIGnMZ2Iw43kFUPd+fkrcY3O/5e/NbaR3V/0HorRr
S2mmsV3cBdVoQTMjA3+VcrQ7bgr86qksyEIfc5sHQuDcwBShErpjKP5XJ1BnSO95
JHVfI637xUPZhHTBmDi/pLkG3jR/9/fGXdMn+oA+RkBXptaovbno0U2E0QGPz4Te
VNzwbta8AIm2vYiNSy2MKd54U3Wvaonzw5r/3MhSBDfZ8xp8U/9A/xHTML68XR8o
aiphlBujqmesgPcK/DkgidYXMQcSP4mUEQIDAQABo4IBFjCCARIwDAYDVR0TAQH/
BAIwADAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwLwYDVR0RBCgw
JoIkODhmNTNiNGItMWY4Ni00ZDhjLThjZjAtZjQ5NTc2Njc4YjYwMB0GA1UdDgQW
BBTrta2mWe9wyK8XaC/ngwVSQnJqiDCBjwYDVR0jBIGHMIGEgBRj5vOZQ0mGYOFn
sXR0HD9Vp7lt9KFapFgwVjELMAkGA1UEBhMCU0UxEDAOBgNVBAoMB01vZGlvQUIx
DzANBgNVBAsMBlNvbW1hcjEkMCIGA1UEAwwbQ2FyYW1lbCBTaWduaW5nIENlcnRp
ZmljYXRlghBYB3RCpwsR6pK4fhHMj0ipMA0GCSqGSIb3DQEBCwUAA4ICAQCIIb9P
IIg/f55FQTZ5+L2ela08jze13cqWU3GQZm5ctVtziw9+5fSJ6HtFEFO83q2QKoOZ
WAAhCl56IRLCgBd5NXDzf10UPiRC5rBHFHm7M5E/XO0lHLGZPR7ov7Env/acK1Ya
+b6yPNo6ov/eOFfE1sBv7HtRfbClqX2r4dfCefenxX3CfZwUOfOEgkqFDAyFVwDm
v4Ylr2qasbSsTMAdlL2VWtWC+CCsEc8lauOfVARDevCFDba55GmCBOGK3VtkJ89E
oRJZcxKQf2GbWLzEQvmvlgmy0I0z3gzdkCIMYIZnNzvkQl36LtCqq5VphNfPdU8x
GoVdY5t9Dwo1N3GHZWsMHueng8HgH1kP6BssjPjNG9NwHKzdUB2cvZ+xK0s4NKQa
22ztfdE9c9imI7vDk6wgIrLxbbSb1ukKWohuNQscRXZMyVM4mFR6Z3UTvFGXl/db
0d1REFvN2U2VpIwV/eVNUM12BWap004f4NdfcnFVrf6V7TuAEnMuIWmnQnRjraD1
Y+OyRCSWia33pYM8lH1vyffLGjNNUWR4UpOqvKCwDrh3w0XiALLRw4eTgmjrQbY2
n/35846/tw3um7LVm9V6p4R6xS5IDqUQ8WDqzPLZ87R7xD1CByk2Wj0DUGjxby23
EukQG+cffU+f3f0Sk77oP2yivS+pM1cmYNIUgg==
-----END CERTIFICATE-----
";
}
