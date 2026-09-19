//! Production HTTP defaults with an explicitly compiled local-fixture transport.
//! The fixture changes DNS and certificate roots, never request authentication,
//! signed protocol verification, endpoint identity, or TLS hostname checks.

#[cfg(all(feature = "local-runtime-fixture", not(debug_assertions)))]
compile_error!("local-runtime-fixture is forbidden in release artifacts");

pub(crate) fn builder() -> reqwest::ClientBuilder {
    let builder = reqwest::Client::builder();
    #[cfg(feature = "local-runtime-fixture")]
    let builder = fixture::configure(builder)
        .expect("invalid isolated local runtime fixture transport configuration");
    builder
}

#[cfg(feature = "local-runtime-fixture")]
mod fixture {
    use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf};

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Transport {
        profile: String,
        ca_pem: PathBuf,
        hosts: BTreeMap<String, SocketAddr>,
    }

    fn validate(config: &Transport, profile: Option<&str>) -> Result<(), &'static str> {
        let suffix = config
            .profile
            .strip_prefix("t17-cli-")
            .ok_or("fixture requires a unique t17-cli profile")?;
        let id = uuid::Uuid::parse_str(suffix).map_err(|_| "invalid fixture profile UUID")?;
        if id.to_string() != suffix || profile != Some(config.profile.as_str()) {
            return Err("fixture profile does not match selected isolated profile");
        }
        if !config.ca_pem.is_absolute() || config.hosts.is_empty() || config.hosts.len() > 16 {
            return Err("invalid fixture CA path or host count");
        }
        for (host, address) in &config.hosts {
            if !(host == "chat.catbird.blue" || host.ends_with(".request-fixture.catbird.blue"))
                || host.len() > 253
                || !host
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.')
                || !address.ip().is_loopback()
                || address.port() == 0
            {
                return Err(
                    "fixture mappings require explicit synthetic hosts and loopback sockets",
                );
            }
        }
        Ok(())
    }

    pub(super) fn configure(
        mut builder: reqwest::ClientBuilder,
    ) -> Result<reqwest::ClientBuilder, Box<dyn std::error::Error>> {
        let path = std::env::var_os("CATMOS_LOCAL_RUNTIME_TRANSPORT")
            .ok_or("fixture-only artifact requires an explicit local transport manifest")?;
        use std::io::Read;
        let read_bounded = |path: &std::path::Path| {
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take(65_537)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 65_536 {
                return Err(std::io::Error::other(
                    "fixture transport file exceeds bound",
                ));
            }
            Ok(bytes)
        };
        let config: Transport =
            serde_json::from_slice(&read_bounded(PathBuf::from(path).as_path())?)?;
        validate(&config, crate::storage::config::Config::fixture_profile())?;
        let certificate = reqwest::Certificate::from_pem(&read_bounded(&config.ca_pem)?)?;
        builder = builder
            .add_root_certificate(certificate)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none());
        for (host, address) in &config.hosts {
            builder = builder.resolve(host, *address);
        }
        Ok(builder)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn valid() -> Transport {
            Transport {
                profile: "t17-cli-01234567-89ab-4def-8123-456789abcdef".into(),
                ca_pem: "/tmp/unique-fixture/ca.pem".into(),
                hosts: [(
                    "chat.catbird.blue".into(),
                    "127.0.0.1:14443".parse().unwrap(),
                )]
                .into_iter()
                .collect(),
            }
        }

        #[test]
        fn fixture_transport_requires_exact_isolated_profile() {
            let config = valid();
            assert!(validate(&config, Some(&config.profile)).is_ok());
            assert!(validate(&config, None).is_err());
            assert!(validate(&config, Some("ordinary-profile")).is_err());
        }

        #[test]
        fn fixture_transport_rejects_external_routes_and_unrelated_hosts() {
            for (host, address) in [
                ("chat.catbird.blue", "192.0.2.1:443"),
                ("plc.directory", "127.0.0.1:14443"),
                ("chat.catbird.blue", "127.0.0.1:0"),
            ] {
                let mut config = valid();
                config.hosts = [(host.into(), address.parse().unwrap())]
                    .into_iter()
                    .collect();
                assert!(validate(&config, Some(&config.profile)).is_err());
            }
        }
    }
}
