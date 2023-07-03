use crate::Keycloak;
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct MtlsEndpointAliases {
    pub token_endpoint: String,
    pub revocation_endpoint: String,
    pub introspection_endpoint: String,
    pub device_authorization_endpoint: String,
    pub registration_endpoint: String,
    pub userinfo_endpoint: String,
    pub pushed_authorization_request_endpoint: String,
    pub backchannel_authentication_endpoint: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenIdConfiguration {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub introspection_endpoint: String,
    pub userinfo_endpoint: String,
    pub end_session_endpoint: String,
    pub frontchannel_logout_session_supported: bool,
    pub frontchannel_logout_supported: bool,
    pub jwks_uri: String,
    pub check_session_iframe: String,
    pub grant_types_supported: Vec<String>,
    pub acr_values_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub id_token_encryption_alg_values_supported: Vec<String>,
    pub id_token_encryption_enc_values_supported: Vec<String>,
    pub userinfo_signing_alg_values_supported: Vec<String>,
    pub userinfo_encryption_alg_values_supported: Vec<String>,
    pub userinfo_encryption_enc_values_supported: Vec<String>,
    pub request_object_signing_alg_values_supported: Vec<String>,
    pub request_object_encryption_alg_values_supported: Vec<String>,
    pub request_object_encryption_enc_values_supported: Vec<String>,
    pub response_modes_supported: Vec<String>,
    pub registration_endpoint: String,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub token_endpoint_auth_signing_alg_values_supported: Vec<String>,
    pub introspection_endpoint_auth_methods_supported: Vec<String>,
    pub introspection_endpoint_auth_signing_alg_values_supported: Vec<String>,
    pub authorization_signing_alg_values_supported: Vec<String>,
    pub authorization_encryption_alg_values_supported: Vec<String>,
    pub authorization_encryption_enc_values_supported: Vec<String>,
    pub claims_supported: Vec<String>,
    pub claim_types_supported: Vec<String>,
    pub claims_parameter_supported: bool,
    pub scopes_supported: Vec<String>,
    pub request_parameter_supported: bool,
    pub request_uri_parameter_supported: bool,
    pub require_request_uri_registration: bool,
    pub code_challenge_methods_supported: Vec<String>,
    pub tls_client_certificate_bound_access_tokens: bool,
    pub revocation_endpoint: String,
    pub revocation_endpoint_auth_methods_supported: Vec<String>,
    pub revocation_endpoint_auth_signing_alg_values_supported: Vec<String>,
    pub backchannel_logout_supported: bool,
    pub backchannel_logout_session_supported: bool,
    pub device_authorization_endpoint: String,
    pub backchannel_token_delivery_modes_supported: Vec<String>,
    pub backchannel_authentication_endpoint: String,
    pub backchannel_authentication_request_signing_alg_values_supported: Vec<String>,
    pub require_pushed_authorization_requests: bool,
    pub pushed_authorization_request_endpoint: String,
    pub mtls_endpoint_aliases: MtlsEndpointAliases,
}

impl Keycloak {
    pub async fn openid_configuration(
        &self,
        realm_name: &str,
    ) -> Result<OpenIdConfiguration, Box<dyn Error + Send + Sync>> {
        let uri =
            self.base_uri.clone() + "/realms/" + realm_name + "/.well-known/openid-configuration";
        let res = self.client.get(&uri).send().await?;
        let config = res.json().await?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_openid_configuration() {
        let keycloak = Keycloak::new("http://localhost:8080");
        let config = keycloak
            .openid_configuration("test")
            .await
            .expect("failed to fetch openid configuration");
    }
}
