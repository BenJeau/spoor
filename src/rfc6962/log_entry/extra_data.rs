use base64::{Engine, prelude::BASE64_STANDARD};

use super::{Kind, certificate::Certificates, utils::bytes_to_u24};

#[derive(Debug)]
pub struct ExtraData {
    pub certificates: Certificates,
}

impl ExtraData {
    pub fn parse(data: String, log_entry_kind: Kind) -> anyhow::Result<Self> {
        let decoded_data = BASE64_STANDARD.decode(data)?;
        let chain_length = bytes_to_u24(decoded_data[0..3].try_into()?) as usize;
        let chain_buffer = &decoded_data[3..3 + chain_length];

        match log_entry_kind {
            Kind::X509 => Ok(Self {
                certificates: Certificates::parse_chain(chain_buffer)?,
            }),
            Kind::Precert => {
                let extra_chain_buffer = &decoded_data[6 + chain_length..];

                let mut certificates = Certificates::parse(&chain_buffer)?;
                certificates
                    .0
                    .extend(Certificates::parse_chain(extra_chain_buffer)?.0);

                Ok(Self { certificates })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use jiff::Timestamp;

    use super::*;

    const EXTRA_DATA: &str = r#"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"#;

    #[test]
    fn test_extra_data() {
        let extra_data = ExtraData::parse(EXTRA_DATA.to_string(), Kind::Precert).unwrap();

        assert_eq!(extra_data.certificates.0.len(), 4);

        let certificate = &extra_data.certificates.0[0];
        assert_eq!(certificate.subject, "");
        assert_eq!(certificate.subject_alt_names.len(), 1);
        assert_eq!(
            certificate.subject_alt_names[0],
            "1719068946356676936-30hk3qz9l1upp.g-dns-acct-01.preprod.haplorrhini.com"
        );
        assert_eq!(
            certificate.issuer,
            "C=US, O=Google Trust Services, CN=Test WR3"
        );
        assert_eq!(
            certificate.serial,
            "00:d4:63:78:a3:fc:47:48:24:0f:5e:09:42:c5:94:69:49"
        );
        assert_eq!(certificate.version, 2);
        assert_eq!(
            certificate.not_after,
            Timestamp::new(1719151745, 0).unwrap()
        );
        assert_eq!(
            certificate.not_before,
            Timestamp::new(1719065346, 0).unwrap()
        );
    }
}
