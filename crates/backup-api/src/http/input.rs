use crate::{ErrorCode, Operation, Request, model::uuid4};
use anyhow::{Context, Result, ensure};
use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, header},
};
use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::{Map, Value};
use std::{fmt, time::Duration};
use uuid::Uuid;

const BODY_LIMIT: usize = 16 * 1024;

pub(super) fn single<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>> {
    let mut values = headers.get_all(name).iter();
    let value = values.next();
    ensure!(values.next().is_none(), ErrorCode::InvalidRequest);
    value
        .map(|value| value.to_str().map_err(|_| ErrorCode::InvalidRequest.into()))
        .transpose()
}

pub(super) async fn body(headers: &HeaderMap, body: Body, expect_json: bool) -> Result<Fields> {
    if let Some(encoding) = single(headers, header::CONTENT_ENCODING.as_str())? {
        ensure!(
            encoding.eq_ignore_ascii_case("identity"),
            ErrorCode::UnsupportedMedia
        );
    }
    if let Some(size) = single(headers, header::CONTENT_LENGTH.as_str())? {
        let size = size.parse::<u64>().context(ErrorCode::InvalidRequest)?;
        ensure!(size <= BODY_LIMIT as u64, ErrorCode::BodyTooLarge);
    }
    if expect_json {
        let media =
            single(headers, header::CONTENT_TYPE.as_str())?.context(ErrorCode::UnsupportedMedia)?;
        let (mime, charset) = media
            .split_once(';')
            .map_or((media, None), |(mime, charset)| (mime, Some(charset)));
        ensure!(
            mime.trim().eq_ignore_ascii_case("application/json")
                && charset.is_none_or(|value| value.trim().eq_ignore_ascii_case("charset=utf-8")),
            ErrorCode::UnsupportedMedia
        );
    }
    // The Limit applies to chunked bodies as well as known Content-Length.
    let bytes = tokio::time::timeout(Duration::from_secs(10), to_bytes(body, BODY_LIMIT))
        .await
        .context(ErrorCode::InvalidRequest)?
        .map_err(|e| {
            if std::error::Error::source(&e)
                .is_some_and(|e| e.is::<http_body_util::LengthLimitError>())
            {
                ErrorCode::BodyTooLarge
            } else {
                ErrorCode::InvalidRequest
            }
        })?;
    if expect_json {
        serde_json::from_slice(&bytes).map_err(|_| ErrorCode::InvalidRequest.into())
    } else {
        ensure!(bytes.is_empty(), ErrorCode::InvalidRequest);
        Ok(Fields(Map::new()))
    }
}

// All current request objects are flat. Refuse duplicate members before
// translating to the closed worker request enum.
pub(super) struct Fields(Map<String, Value>);

impl<'de> Deserialize<'de> for Fields {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct FlatObject;
        impl<'de> Visitor<'de> for FlatObject {
            type Value = Fields;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object with unique scalar members")
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut access: A,
            ) -> std::result::Result<Fields, A::Error> {
                let mut fields = Map::new();
                while let Some((key, value)) = access.next_entry::<String, Value>()? {
                    if value.is_object() || value.is_array() || fields.insert(key, value).is_some()
                    {
                        return Err(de::Error::custom("non-scalar or duplicate field"));
                    }
                }
                Ok(Fields(fields))
            }
        }
        deserializer.deserialize_map(FlatObject)
    }
}

impl Fields {
    pub fn empty(&self) -> Result<()> {
        ensure!(self.0.is_empty(), ErrorCode::InvalidRequest);
        Ok(())
    }

    pub fn login_token(&self) -> Result<&str> {
        ensure!(self.0.len() == 1, ErrorCode::InvalidRequest);
        self.0
            .get("token")
            .and_then(Value::as_str)
            .context(ErrorCode::InvalidRequest)
    }

    pub fn worker_request(mut self, operation: Operation) -> Result<Request> {
        for name in ["artifact_id", "intent_id"] {
            if let Some(value) = self.0.get(name) {
                id(value.as_str().context(ErrorCode::InvalidRequest)?)?;
            }
        }
        if let Some(profile) = self.0.get("profile_id").filter(|value| !value.is_null()) {
            let profile = profile.as_str().context(ErrorCode::InvalidRequest)?;
            ensure!(
                profile.len() <= 64
                    && profile
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_lowercase)
                    && profile.bytes().all(|b| b.is_ascii_lowercase()
                        || b.is_ascii_digit()
                        || matches!(b, b'_' | b'-')),
                ErrorCode::InvalidRequest
            );
        }
        if operation == Operation::RetentionPreview {
            if self.0.get("operation").and_then(Value::as_str) == Some("prune") {
                ensure!(self.0.contains_key("profile_id"), ErrorCode::InvalidRequest);
            }
            let selection = serde_json::from_value(Value::Object(self.0))
                .map_err(|_| ErrorCode::InvalidRequest)?;
            let request = Request::RetentionPreview { selection };
            request.validate()?;
            return Ok(request);
        }
        if operation == Operation::Backup {
            ensure!(self.0.contains_key("profile_id"), ErrorCode::InvalidRequest);
        }
        ensure!(!self.0.contains_key("operation"), ErrorCode::InvalidRequest);
        self.0
            .insert("operation".into(), serde_json::to_value(operation)?);
        let request: Request =
            serde_json::from_value(Value::Object(self.0)).map_err(|_| ErrorCode::InvalidRequest)?;
        request.validate()?;
        Ok(request)
    }
}

pub(super) fn id(text: &str) -> Result<Uuid> {
    let value = Uuid::parse_str(text).context(ErrorCode::InvalidRequest)?;
    ensure!(
        uuid4(value) && value.to_string() == text,
        ErrorCode::InvalidRequest
    );
    Ok(value)
}

pub(super) struct Page {
    pub after: Option<Uuid>,
    pub limit: usize,
}

pub(super) fn page(query: Option<&str>) -> Result<Page> {
    let mut after = None;
    let mut limit = None;
    if let Some(query) = query {
        for part in query.split('&') {
            let (name, value) = part.split_once('=').context(ErrorCode::InvalidRequest)?;
            match name {
                "after" if after.is_none() => after = Some(id(value)?),
                "limit" if limit.is_none() => {
                    ensure!(
                        value.len() <= 3 && value.bytes().all(|b| b.is_ascii_digit()),
                        ErrorCode::InvalidRequest
                    );
                    let parsed = value.parse::<usize>().context(ErrorCode::InvalidRequest)?;
                    ensure!((1..=100).contains(&parsed), ErrorCode::InvalidRequest);
                    limit = Some(parsed);
                }
                _ => anyhow::bail!(ErrorCode::InvalidRequest),
            }
        }
    }
    Ok(Page {
        after,
        limit: limit.unwrap_or(50),
    })
}
