use crate::Keycloak;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct KeycloakClient {
    pub id: String,
    #[serde(rename(deserialize = "clientId"))]
    pub client_id: String,
    pub name: String,
    #[serde(rename(deserialize = "rootUrl"))]
    #[serde(default)]
    pub root_url: String,
    #[serde(rename(deserialize = "baseUrl"))]
    #[serde(default)]
    pub base_url: String,
    #[serde(rename(deserialize = "surrogateAuthRequired"))]
    pub surrogate_auth_required: bool,
    pub enabled: bool,
    #[serde(rename(deserialize = "alwaysDisplayInConsole"))]
    pub always_display_in_console: bool,
    #[serde(rename(deserialize = "clientAuthenticatorType"))]
    pub client_authenticator_type: String,
    #[serde(rename(deserialize = "redirectUris"))]
    pub redirect_uris: Vec<String>,
    #[serde(rename(deserialize = "webOrigins"))]
    pub web_origins: Vec<String>,
    #[serde(rename(deserialize = "notBefore"))]
    pub not_before: i32,
    #[serde(rename(deserialize = "bearerOnly"))]
    pub bearer_only: bool,
    #[serde(rename(deserialize = "consentRequired"))]
    pub consent_required: bool,
    #[serde(rename(deserialize = "standardFlowEnabled"))]
    pub standard_flow_enabled: bool,
    #[serde(rename(deserialize = "implicitFlowEnabled"))]
    pub implicit_flow_enabled: bool,
    #[serde(rename(deserialize = "directAccessGrantsEnabled"))]
    pub direct_access_grants_enabled: bool,
    #[serde(rename(deserialize = "serviceAccountsEnabled"))]
    pub service_accounts_enabled: bool,
    #[serde(rename(deserialize = "publicClient"))]
    pub public_client: bool,
    #[serde(rename(deserialize = "frontchannelLogout"))]
    pub frontchannel_logout: bool,
    pub protocol: String,
    pub attributes: HashMap<String, String>,
    #[serde(rename(deserialize = "authenticationFlowBindingOverrides"))]
    pub authentication_flow_binding_overrides: HashMap<String, String>,
    #[serde(rename(deserialize = "fullScopeAllowed"))]
    pub full_scope_allowed: bool,
    #[serde(rename(deserialize = "nodeReRegistrationTimeout"))]
    pub node_re_registration_timeout: i32,
    #[serde(rename(deserialize = "defaultClientScopes"))]
    pub default_client_scopes: Vec<String>,
    #[serde(rename(deserialize = "optionalClientScopes"))]
    pub optional_client_scopes: Vec<String>,
    pub access: HashMap<String, bool>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ClientSecretData {
    #[serde(rename(deserialize = "type"))]
    pub type_: String,
    pub value: String,
}

impl Keycloak {
    pub async fn get_clients(
        &self,
        token: &str,
        realm: &str,
    ) -> Result<Vec<KeycloakClient>, Box<dyn Error + Send + Sync>> {
        let uri = self.base_uri.clone() + "/admin/realms/" + realm + "/clients";
        let res = self
            .client
            .get(uri)
            .header("Authorization", "Bearer ".to_string() + token)
            .send()
            .await?;
        let clients: Vec<KeycloakClient> = res.json().await?;
        Ok(clients)
    }

    pub async fn get_client(
        &self,
        token: &str,
        client_internal_id: &str,
        realm: &str,
    ) -> Result<KeycloakClient, Box<dyn Error + Send + Sync>> {
        let uri =
            self.base_uri.clone() + "/admin/realms/" + realm + "/clients/" + client_internal_id;
        let res = self
            .client
            .get(uri)
            .header("Authorization", "Bearer ".to_string() + token)
            .send()
            .await?;
        let client: KeycloakClient = res.json().await?;
        Ok(client)
    }

    pub async fn regenerate_client_secret(
        &self,
        token: &str,
        client_internal_id: &str,
        realm: &str,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        let uri = self.base_uri.clone()
            + "/admin/realms/"
            + realm
            + "/clients/"
            + client_internal_id
            + "/client-secret";
        let res = self
            .client
            .post(uri)
            .header("Authorization", "Bearer ".to_string() + token)
            .send()
            .await?;
        let client_secret_data: ClientSecretData = res.json().await?;
        Ok(client_secret_data.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[tokio::test]
    async fn test_get_client() {
        let keycloak = Keycloak::new("http://localhost:8080");
        let credentials = keycloak
            .login_admin("root", "root", "master")
            .await
            .expect("error fetching credentials");
        let access_token = credentials.access_token;
        let client = keycloak
            .get_client(
                &access_token,
                "c698fd5b-6e9b-4ced-90e6-daa5ac450634",
                "test",
            )
            .await
            .expect("error fetching client");
    }

    #[tokio::test]
    async fn test_regenerate_client_secret() {
        let keycloak = Keycloak::new("http://localhost:8080");
        let credentials = keycloak
            .login_admin("root", "root", "master")
            .await
            .expect("error fetching credentials");
        let access_token = credentials.access_token;
        let client_secret = keycloak
            .regenerate_client_secret(
                &access_token,
                "c698fd5b-6e9b-4ced-90e6-daa5ac450634",
                "test",
            )
            .await
            .expect("error regenerating client secret");
    }
}
