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

    fn base_client_uri(&self, realm: &str) -> String {
        self.base_uri.clone() + "/realms/" + realm + "/clients"
    }

    fn base_admin_uri(&self, realm: &str) -> String {
        self.base_uri.clone() + "/admin/realms/" + realm
    }
}

#[cfg(test)]
mod tests {}
