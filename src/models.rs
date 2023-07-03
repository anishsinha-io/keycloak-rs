use std::collections::HashMap;

use serde::{Deserialize, Serialize};

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
