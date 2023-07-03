#![allow(dead_code, unused)]

mod admin;
mod clients;
mod credentials;
mod models;
mod openid;

use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::str::FromStr;

use crate::models::{ClientSecretData, KeycloakClient};

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
