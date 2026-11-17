use nullgate_core::AppConfig;
const BASE: &str = r#"schema_version=1
data_dir="data"
[dns]
udp_listen="127.0.0.1:5353"
tcp_listen="127.0.0.1:5353"
upstreams=["127.0.0.1:5354"]
[http]
listen="127.0.0.1:8080"
[web]
listen="127.0.0.1:8081"
public_origin="http://127.0.0.1:8081"
[auth]
mode="oidc"
"#;
const OIDC: &str = r#"[oidc]
issuer="http://127.0.0.1:8180/realms/nullgate"
client_id="nullgate"
redirect_uri="http://127.0.0.1:8081/api/v1/auth/oidc/callback"
client_secret_file="secrets/oidc-client"
role_claim="/realm_access/roles"
administrator_values=["nullgate-admin"]
viewer_values=["nullgate-viewer"]
"#;
#[test]
fn explicit_oidc_configuration_is_accepted_without_reading_secrets() {
    let result = AppConfig::parse(
        &format!("{BASE}{OIDC}"),
        std::path::Path::new("/isolated/config.toml"),
    );
    assert!(result.is_ok(), "{result:?}");
}
#[test]
fn oidc_mode_requires_provider_configuration() {
    assert!(AppConfig::parse(BASE, std::path::Path::new("/isolated/config.toml")).is_err());
}
#[test]
fn unsafe_or_ambiguous_provider_configuration_is_rejected() {
    for text in [
        OIDC.replace("nullgate-admin\"]", "nullgate-viewer\"]"),
        OIDC.replace("client_id=\"nullgate\"", "client_id=\"\""),
        OIDC.replace("/realm_access/roles", "invalid"),
        OIDC.replace("http://127.0.0.1:8180", "http://provider.example"),
        OIDC.replace("127.0.0.1:8081/api/v1", "127.0.0.1:9999/api/v1"),
    ] {
        assert!(
            AppConfig::parse(
                &format!("{BASE}{text}"),
                std::path::Path::new("/isolated/config.toml")
            )
            .is_err()
        );
    }
}
