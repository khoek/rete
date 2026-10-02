use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};

pub const AUTHORIZED_PARTY_CLAIM: &str = "azp";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Subject(String);

impl Subject {
    pub fn new(value: impl Into<String>) -> anyhow::Result<Self> {
        let value = value.into();
        if value.trim().is_empty() || value.contains(char::is_whitespace) {
            anyhow::bail!("subject must be non-empty and contain no whitespace");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn strip_kind(&self, kind: &str) -> Option<&str> {
        let prefix = format!("{kind}:");
        self.0.strip_prefix(&prefix)
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Subject {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for Subject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Subject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Subject::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScopeSet(Vec<String>);

impl ScopeSet {
    pub fn new(scopes: impl IntoIterator<Item = impl Into<String>>) -> anyhow::Result<Self> {
        let mut scopes = scopes
            .into_iter()
            .map(Into::into)
            .map(|scope| scope.trim().to_string())
            .filter(|scope| !scope.is_empty())
            .collect::<Vec<_>>();
        scopes.sort();
        scopes.dedup();
        for scope in &scopes {
            if scope.contains(char::is_whitespace) {
                anyhow::bail!("scope `{scope}` contains whitespace");
            }
        }
        Ok(Self(scopes))
    }

    pub fn contains(&self, scope: &str) -> bool {
        self.0.iter().any(|candidate| candidate == scope)
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }

    pub fn as_space_delimited(&self) -> String {
        self.0.join(" ")
    }
}

impl Serialize for ScopeSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.as_space_delimited())
    }
}

impl<'de> Deserialize<'de> for ScopeSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        ScopeSet::new(String::deserialize(deserializer)?.split(' '))
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccessClaims {
    pub iss: String,
    pub sub: Subject,
    pub aud: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub client_id: String,
    pub scope: ScopeSet,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(default, rename = "azp", skip_serializing_if = "Option::is_none")]
    pub authorized_party: Option<String>,
}

impl AccessClaims {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scope.contains(scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_set_serializes_as_space_delimited_string() {
        let scopes = ScopeSet::new(["z", "a", "a"]).expect("scope set should build");
        assert_eq!(
            serde_json::json!("a z"),
            serde_json::to_value(scopes).expect("serialize")
        );
    }

    #[test]
    fn subject_rejects_whitespace() {
        Subject::new("principal:alice@example.com").expect("subject should build");
        Subject::new("principal:alice example.com").expect_err("subject should reject whitespace");
    }
}
