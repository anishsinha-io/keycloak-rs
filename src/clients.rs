use crate::Keycloak;
use reqwest::Request;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;

/// Representation of the information used to create a Keycloak client
#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct CreateClient {
    #[serde(rename(serialize = "clientId"))]
    pub client_id: String,
    pub name: Option<String>,
    #[serde(rename(serialize = "adminUrl"))]
    pub admin_url: Option<String>,
    #[serde(rename(serialize = "alwaysDisplayInConsole"))]
    pub always_display_in_console: Option<bool>,
    pub access: Option<HashMap<String, bool>>,
    pub attributes: Option<HashMap<String, String>>,
    #[serde(rename(serialize = "authenticationFlowBindingOverrides"))]
    pub authentication_flow_binding_overrides: Option<HashMap<String, String>>,
    #[serde(rename(serialize = "authorizationServicesEnabled"))]
    pub authorization_services_enabled: Option<bool>,
    #[serde(rename(serialize = "bearerOnly"))]
    pub bearer_only: Option<bool>,
    #[serde(rename(serialize = "directAccessGrantsEnabled"))]
    pub direct_access_grants_enabled: Option<bool>,
    pub enabled: Option<bool>,
    pub protocol: Option<String>,
    pub description: Option<String>,
    #[serde(rename(serialize = "rootUrl"))]
    pub root_url: Option<String>,
    #[serde(rename(serialize = "baseUrl"))]
    pub base_url: Option<String>,
    #[serde(rename(serialize = "surrogateAuthRequired"))]
    pub surrogate_auth_required: Option<bool>,
    #[serde(rename(serialize = "clientAuthenticatorType"))]
    pub client_authenticator_type: Option<String>,
    #[serde(rename(serialize = "defaultRoles"))]
    pub default_roles: Option<Vec<String>>,
    #[serde(rename(serialize = "redirectUris"))]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(rename(serialize = "webOrigins"))]
    pub web_origins: Option<Vec<String>>,
    #[serde(rename(serialize = "notBefore"))]
    pub not_before: Option<i32>,
    #[serde(rename(serialize = "consentRequired"))]
    pub consent_required: Option<bool>,
    #[serde(rename(serialize = "standardFlowEnabled"))]
    pub standard_flow_enabled: Option<bool>,
    #[serde(rename(serialize = "implicitFlowEnabled"))]
    pub implicit_flow_enabled: Option<bool>,
    #[serde(rename(serialize = "serviceAccountsEnabled"))]
    pub service_accounts_enabled: Option<bool>,
    #[serde(rename(serialize = "publicClient"))]
    pub public_client: Option<bool>,
    #[serde(rename(serialize = "frontchannelLogout"))]
    pub frontchannel_logout: Option<bool>,
    #[serde(rename(serialize = "fullScopeAllowed"))]
    pub full_scope_allowed: Option<bool>,
    #[serde(rename(serialize = "nodeReRegistrationTimeout"))]
    pub node_re_registration_timeout: Option<i32>,
    #[serde(rename(serialize = "defaultClientScopes"))]
    pub default_client_scopes: Option<Vec<String>>,
    #[serde(rename(serialize = "optionalClientScopes"))]
    pub optional_client_scopes: Option<Vec<String>>,
}

impl CreateClient {
    pub fn default(client_id: &str) -> Self {
        let mut access: HashMap<String, bool> = HashMap::new();
        access.insert("view".to_string(), true);
        access.insert("configure".to_string(), true);
        access.insert("manage".to_string(), true);

        CreateClient {
            client_id: client_id.to_string(),
            name: Option::from(client_id.to_string()),
            admin_url: None,
            always_display_in_console: None,
            access: None,
            attributes: None,
            authentication_flow_binding_overrides: None,
            authorization_services_enabled: None,
            bearer_only: None,
            direct_access_grants_enabled: None,
            enabled: None,
            protocol: None,
            description: None,
            root_url: None,
            base_url: None,
            surrogate_auth_required: None,
            client_authenticator_type: None,
            default_roles: None,
            redirect_uris: None,
            web_origins: None,
            not_before: None,
            consent_required: None,
            standard_flow_enabled: None,
            implicit_flow_enabled: None,
            service_accounts_enabled: None,
            public_client: None,
            frontchannel_logout: None,
            full_scope_allowed: None,
            node_re_registration_timeout: None,
            default_client_scopes: None,
            optional_client_scopes: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientRepresentation {
    pub id: String,
    #[serde(rename(deserialize = "clientId"))]
    pub client_id: String,
    pub name: String,
    #[serde(default, rename(deserialize = "rootUrl"))]
    pub root_url: String,
    #[serde(default, rename(deserialize = "baseUrl"))]
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

impl ClientRepresentation {
    pub fn new() {}
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
    ) -> Result<Vec<ClientRepresentation>, Box<dyn Error + Send + Sync>> {
        let uri = self.base_uri.clone() + "/admin/realms/" + realm + "/clients";
        let res = self
            .client
            .get(uri)
            .header("Authorization", "Bearer ".to_string() + token)
            .send()
            .await?;
        let clients: Vec<ClientRepresentation> = res.json().await?;
        Ok(clients)
    }

    pub async fn get_client(
        &self,
        token: &str,
        client_internal_id: &str,
        realm: &str,
    ) -> Result<ClientRepresentation, Box<dyn Error + Send + Sync>> {
        let uri =
            self.base_uri.clone() + "/admin/realms/" + realm + "/clients/" + client_internal_id;
        let res = self
            .client
            .get(uri)
            .header("Authorization", "Bearer ".to_string() + token)
            .send()
            .await?;
        let client: ClientRepresentation = res.json().await?;
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

    pub async fn get_client_secret(
        &self,
        token: &str,
        client_internal_id: &str,
        realm: &str,
    ) -> Result<reqwest::Response, Box<dyn Error + Send + Sync>> {
        let uri = self.base_admin_uri(realm) + "/clients/" + client_internal_id + "/client-secret";
        let res = self
            .client
            .get(uri)
            .header("Authorization", "Bearer ".to_string() + token)
            .send()
            .await?;
        Ok(res)
    }

    pub async fn create_client(
        &self,
        token: &str,
        realm: &str,
        client: &CreateClient,
    ) -> Result<Option<ClientRepresentation>, Box<dyn Error + Send + Sync>> {
        let uri = self.base_admin_uri(realm) + "/clients";
        let res = self
            .client
            .post(uri)
            .header("Authorization", "Bearer ".to_string() + token)
            .json(&client)
            .send()
            .await?;
        let client_id = client.client_id.clone();
        let clients = match self.get_clients(token, realm).await {
            Ok(clients) => clients,
            Err(_) => vec![],
        };
        let new_client = clients.into_iter().find(|c| c.client_id == client_id);
        Ok(new_client)
    }

    pub async fn get_client_by_client_id(
        &self,
        token: &str,
        realm: &str,
        client_id: &str,
    ) -> Result<Option<ClientRepresentation>, Box<dyn Error + Send + Sync>> {
        let uri = self.base_admin_uri(realm) + "/clients";
        let res = self
            .client
            .get(uri)
            .header("Authorization", "Bearer ".to_string() + token)
            .send()
            .await?;
        let clients: Vec<ClientRepresentation> = res.json().await?;
        let client = clients.into_iter().find(|c| c.client_id == client_id);
        Ok(client)
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

    #[tokio::test]
    async fn test_get_client_secret() {
        let keycloak = Keycloak::new("http://localhost:8080");
        let credentials = keycloak
            .login_admin("root", "root", "master")
            .await
            .expect("error fetching credentials");
        let access_token = credentials.access_token;
        let client_secret = keycloak
            .get_client_secret(
                &access_token,
                "c698fd5b-6e9b-4ced-90e6-daa5ac450634",
                "test",
            )
            .await
            .expect("error fetching client secret");
    }

    #[tokio::test]
    async fn test_create_client() {
        let keycloak = Keycloak::new("http://localhost:8080");
        let credentials = keycloak
            .login_admin("root", "root", "master")
            .await
            .expect("error fetching credentials");
        let access_token = credentials.access_token;
        let new_client = keycloak
            .create_client(
                &access_token,
                "test",
                &CreateClient::default("i-love-jenny"),
            )
            .await
            .expect("error creating new client");
    }

    #[tokio::test]
    async fn test_get_client_by_client_id() {
        let keycloak = Keycloak::new("http://localhost:8080");
        let credentials = keycloak
            .login_admin("root", "root", "master")
            .await
            .expect("error fetching credentials");
        let access_token = credentials.access_token;
        let client = keycloak
            .get_client_by_client_id(&access_token, "test", "i-love-jenny")
            .await
            .expect("error creating new client");
    }
}
