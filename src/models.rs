use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct KeycloakClient {
    pub id: String,
    #[serde(rename(deserialize = "clientId"))]
    pub client_id: String,
    pub name: String,
    #[serde(rename(deserialize = "rootUrl"))]
    pub root_url: String,
    #[serde(rename(deserialize = "baseUrl"))]
    pub base_url: String,
    #[serde(rename(deserialize = "surrogateAuthRequired"))]
    pub surrogate_auth_required: bool,
    pub enabled: bool,
    #[serde(rename(deserialize = "alwaysDisplayInConsole"))]
    pub always_display_in_console: bool,
}
