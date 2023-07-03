use crate::Keycloak;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;

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

impl Keycloak {
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
            .login_client("test-client1", "JRZCCKoIZoHmJk32kVHcDNGXagyGURaN", "test")
            .await
            .expect("failed to login client service account");
    }
}
