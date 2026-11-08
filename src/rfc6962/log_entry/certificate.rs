use base64::{Engine, prelude::BASE64_STANDARD};
use jiff::Timestamp;
use x509_parser::{certificate::X509Certificate, extensions::GeneralName, pem::Pem};

use super::utils::bytes_to_u24;

#[derive(Debug)]
pub struct Certificate {
    pub subject: String,
    pub subject_alt_names: Vec<String>,
    pub issuer: String,
    pub issuer_uid: Option<Vec<u8>>,
    pub serial: String,
    pub version: u32,
    pub not_after: Timestamp,
    pub not_before: Timestamp,
    pub signature_algorithm: String,
}

impl Certificate {
    pub fn new(cert: X509Certificate<'_>) -> anyhow::Result<Self> {
        let subject = cert.subject().to_string();
        let subject_alt_names = cert
            .subject_alternative_name()
            .map(|alt_names| {
                alt_names
                    .iter()
                    .flat_map(|alt_name| {
                        alt_name.value.general_names.iter().map(|gn| match gn {
                            GeneralName::RFC822Name(name) => name.to_string(),
                            GeneralName::DNSName(name) => name.to_string(),
                            GeneralName::IPAddress(ip) => ip
                                .into_iter()
                                .map(|part| part.to_string())
                                .collect::<Vec<_>>()
                                .join(","),
                            GeneralName::URI(uri) => uri.to_string(),
                            GeneralName::DirectoryName(name) => name.to_string(),
                            GeneralName::RegisteredID(oid) => oid.to_string(),
                            GeneralName::OtherName(..) => todo!(),
                            GeneralName::X400Address(_) => todo!(),
                            GeneralName::EDIPartyName(_) => todo!(),
                            GeneralName::Invalid(tag, items) => todo!(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let issuer = cert.issuer().to_string();
        let issuer_uid = cert.issuer_uid.as_ref().map(|uid| uid.0.data.to_vec());

        let serial = cert.tbs_certificate.raw_serial_as_string();
        let version = cert.version().0;
        let not_after = Timestamp::from_nanosecond(
            cert.validity()
                .not_after
                .to_datetime()
                .unix_timestamp_nanos(),
        )?;
        let not_before = Timestamp::from_nanosecond(
            cert.validity()
                .not_before
                .to_datetime()
                .unix_timestamp_nanos(),
        )?;

        Ok(Self {
            subject,
            subject_alt_names,
            issuer,
            issuer_uid,
            serial,
            version,
            not_after,
            not_before,
            signature_algorithm: cert.signature_algorithm.algorithm.to_string(),
        })
    }
}

#[derive(Debug, Default)]
pub struct Certificates(pub Vec<Certificate>);

impl Certificates {
    pub fn parse(data: &[u8]) -> anyhow::Result<Self> {
        let encoded_data = BASE64_STANDARD.encode(data);
        let cert =
            format!("-----BEGIN CERTIFICATE-----\n{encoded_data}\n-----END CERTIFICATE-----");

        Pem::iter_from_buffer(cert.as_bytes())
            .try_fold(vec![], |mut certificates, pem| {
                certificates.push(Certificate::new(pem?.parse_x509()?)?);
                Ok(certificates)
            })
            .map(Self)
    }

    pub fn parse_chain(data: &[u8]) -> anyhow::Result<Self> {
        let (mut certificates, mut rest) = Self::parse_chain_section(data)?;

        while !rest.is_empty() {
            let data = Self::parse_chain_section(rest)?;
            certificates.0.extend(data.0.0);
            rest = data.1;
        }

        Ok(certificates)
    }

    pub fn parse_chain_section(data: &[u8]) -> anyhow::Result<(Self, &[u8])> {
        let size = bytes_to_u24(data[..3].try_into()?) as usize;
        let cert_data = &data[3..(3 + size)];
        let rest = &data[(3 + size)..];

        Ok((Self::parse(cert_data)?, rest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parsing_cert() {
        const CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIE8zCCA9ugAwIBAgIRANRjeKP8R0gkD14JQsWUaUkwDQYJKoZIhvcNAQELBQAw
QDELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczER
MA8GA1UEAxMIVGVzdCBXUjMwHhcNMjQwNjIyMTQwOTA2WhcNMjQwNjIzMTQwOTA1
WjAAMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAr4wxcCD9ab50ljxc
KkqXJ5UcPQ0/UQXMQHZLAspExWZIiV9CYxXRMUfcXPU5CCP//vCfzFeFPLKbpN80
iDXRFYJWt7z3PEAhPp5Ibz4dZE7CPs2/n8EXiwU9ParPhI1uiOZEmWIwMk8RF/EU
ahf17k+eb5Jb7MQN4dYaRt826W2s8o0Mu5R84UMFiWI7OVR8XPa3ULhpBDkT+oZf
L2AzPUUq3boqIqAYGWIN8rojYGSpMIGbKYutcHHuyMYmqQgQ1hmW3a/bYfsmL5kT
zZzQwogGxdnR/h/ogZZ6vrZzMFSWSjkvhznkzDZ2JDVgcHFOnkwZcURtil1437fG
m7kK9OClXgptKRX6Ff6Xk7WlS5G1ToN5z/mPv0+6C0ZGw9Z6D8ozV9s8suG0yLdU
SbIz6ad9wGpyxNFVpGMWQM8lgQ0sLkoGmpDmLPbY3Ut59aPz7MAMaxmn9K23LNrg
A97/fIYighMmOkziiOjIJZ9Ru/WnICmN0017GxgL5vIBomKdAgMBAAGjggGmMIIB
ojAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/
BAIwADAdBgNVHQ4EFgQUeTJ6XurB8oOhyMed+fUoXvui8h4wHwYDVR0jBBgwFoAU
hgj74MZYEj6IyDTIuTDryYVDlbgwawYIKwYBBQUHAQEEXzBdMCsGCCsGAQUFBzAB
hh9odHRwOi8vby5wa2kuZ29vZy9zL3Rlc3R3cjMvMUdNMC4GCCsGAQUFBzAChiJo
dHRwOi8vaS5wa2kuZ29vZy90ZXN0L3Rlc3R3cjMuY3J0MFUGA1UdEQEB/wRLMEmC
RzE3MTkwNjg5NDYzNTY2NzY5MzYtMzBoazNxejlsMXVwcC5nLWRucy1hY2N0LTAx
LnByZXByb2QuaGFwbG9ycmhpbmkuY29tMBMGA1UdIAQMMAowCAYGZ4EMAQIBMD8G
A1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jLnBraS5nb29nL3Rlc3QvdGVzdHdyMy9i
QVdYTHZENGFwNC5jcmwwEwYKKwYBBAHWeQIEAwEB/wQCBQAwDQYJKoZIhvcNAQEL
BQADggEBALPpBe8ov3ILYMjbgNqi5wbY9Ia8jtc5kv6PNazMw9qfiaXuaZ0qytx9
Sa3a3HtzXoy36NvuUWpb1LsYvsuxZ8D/q16hE/uRfFlTlhrRrPK0tYGZtqt1OfyS
idoHq0AJ7YFyluQfJzTesmBBVIoz5/XiFOiIpNwFO8hgxQUJ4DuQY4GO5/R78IZw
OdLNzA7qxV957/t0Y1O2R2Dsy5DI5esTj1R3lvlPf/7Kt73pUrlWjpH+fJQUUnIx
lyDl8OiBj+GMyKNGjA/Q8+yE8tBECSYOY7NNyTvPq7xIkib72Xcxzh9e6gis8b0Q
tOl3DRtKvXT/FWjebbs1Geeer3CUwqw=
-----END CERTIFICATE-----"#;

        let pem_cert =
            Pem::iter_from_buffer(CERT.as_bytes()).fold(vec![], |mut certificates, pem| {
                let pem = pem.unwrap();
                let x509_cert = pem.parse_x509().unwrap();
                dbg!(&x509_cert);

                certificates.push(Certificate::new(x509_cert).unwrap());
                certificates
            });

        dbg!(pem_cert);
    }
}
