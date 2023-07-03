#![allow(dead_code, unused)]

use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::str::FromStr;

use crate::realm;

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

#[derive(Debug, Serialize, Deserialize)]
pub struct Credentials {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_expires_in: u64,
    #[serde(default)]
    pub refresh_token: String,
    pub token_type: String,
    #[serde(rename(deserialize = "not-before-policy"))]
    pub not_before_policy: u32,
    #[serde(default)]
    pub session_state: String,
    pub scope: String,
}

pub struct Keycloak {
    pub base_uri: String,
    pub client: Client,
}

impl Keycloak {
    pub fn new(base_uri: &str) -> Self {
        Keycloak {
            base_uri: String::from_str(base_uri).unwrap(),
            client: reqwest::Client::new(),
        }
    }
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

    pub async fn login_client(
        &self,
        client_id: &str,
        client_secret: &str,
        realm: &str,
    ) -> Result<Credentials, Box<dyn Error + Send + Sync>> {
        let uri = self.base_uri.clone() + "/realms/" + realm + "/protocol/openid-connect/token";
        let mut params: HashMap<String, String> = HashMap::new();
        params.insert("client_id".to_string(), client_id.to_string());
        params.insert("grant_type".to_string(), "client_credentials".to_string());
        params.insert("client_secret".to_string(), client_secret.to_string());

        let res = self.client.post(uri).form(&params).send().await?;
        let credentials: Credentials = res.json().await?;

        Ok(credentials)
    }

    pub async fn login_admin(
        &self,
        username: &str,
        password: &str,
        realm: &str,
    ) -> Result<Credentials, Box<dyn Error + Send + Sync>> {
        let uri = self.base_uri.clone() + "/realms/" + realm + "/protocol/openid-connect/token";
        let mut params: HashMap<String, String> = HashMap::new();
        params.insert("client_id".to_string(), "admin-cli".to_string());
        params.insert("grant_type".to_string(), "password".to_string());
        params.insert("username".to_string(), username.to_string());
        params.insert("password".to_string(), password.to_string());

        let res = self.client.post(uri).form(&params).send().await?;
        let credentials: Credentials = res.json().await?;

        Ok(credentials)
    }

    pub async fn get_clients(
        &self,
        token: &str,
        realm: &str,
    ) -> Result<reqwest::Response, Box<dyn Error + Send + Sync>> {
        let uri = self.base_uri.clone() + "/admin/realms/" + realm + "/clients";
        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer ".to_string() + token);
        let res = self
            .client
            .get(uri)
            .header("Authorization", "Bearer ".to_string() + token)
            .send()
            .await?;
        Ok(res)
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

    #[tokio::test]
    async fn test_login_admin() {
        let keycloak = Keycloak::new("http://localhost:8080");
        let credentials = keycloak
            .login_admin("root", "root", "master")
            .await
            .expect("failed to login admin user");
    }

    #[tokio::test]
    async fn test_login_client() {
        let keycloak = Keycloak::new("http://localhost:8080");
        let credentials = keycloak
            .login_client("test-client", "rYAYB7hHiHzf7vGw5HpUomKuecqI3MpK", "test")
            .await
            .expect("failed to login client service account");
    }

    #[tokio::test]
    async fn test_get_clients() {
        let keycloak = Keycloak::new("http://localhost:8080");
        let credentials = keycloak
            .login_admin("root", "root", "master")
            .await
            .expect("error fetching credentials");
        let access_token = credentials.access_token;
        let clients = keycloak
            .get_clients(&access_token, "test")
            .await
            .expect("error fetching clients");
        println!("{:#?}", clients.text().await.unwrap());
    }
}
