use super::input::single;
use crate::{Actor, Control, ErrorCode, config::Authority, model::hash};
use anyhow::{Context, Result, ensure};
use axum::http::{HeaderMap, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use serde::Serialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

struct Secret([u8; 32]);

impl Secret {
    fn parse(text: &str, code: ErrorCode) -> Result<Self> {
        let mut bytes = [0; 32];
        ensure!(
            text.len() == 43 && URL_SAFE_NO_PAD.decode_slice(text, &mut bytes).ok() == Some(32),
            code
        );
        Ok(Self(bytes))
    }

    fn generate() -> Result<Self> {
        let mut bytes = [0; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| ErrorCode::InternalError)?;
        Ok(Self(bytes))
    }

    fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    fn hash(&self) -> String {
        hash(&self.0)
    }

    fn csrf(&self) -> Secret {
        let mut digest = Sha256::new();
        digest.update(b"backupctl-api-csrf-v1\0");
        digest.update(self.0);
        Secret(digest.finalize().into())
    }
}

struct Credentials {
    bearer: Option<Secret>,
    cookie: Option<Secret>,
}

impl Credentials {
    fn read(headers: &HeaderMap, name: &str) -> Result<Self> {
        let bearer = single(headers, header::AUTHORIZATION.as_str())?
            .map(|value| -> Result<Secret> {
                let (scheme, token) = value.split_once(' ').context(ErrorCode::AuthRequired)?;
                ensure!(
                    scheme.eq_ignore_ascii_case("Bearer"),
                    ErrorCode::AuthRequired
                );
                Secret::parse(token, ErrorCode::AuthRequired)
            })
            .transpose()?;
        let mut cookie = None;
        for header in headers.get_all(header::COOKIE) {
            let header = header.to_str().map_err(|_| ErrorCode::InvalidRequest)?;
            for pair in header.split(';') {
                let Some((key, value)) = pair.trim().split_once('=') else {
                    continue;
                };
                if key == name {
                    ensure!(cookie.is_none(), ErrorCode::InvalidRequest);
                    cookie = Some(Secret::parse(value, ErrorCode::AuthRequired)?);
                }
            }
        }
        ensure!(
            bearer.is_none() || cookie.is_none(),
            ErrorCode::InvalidRequest
        );
        Ok(Self { bearer, cookie })
    }
}

pub(super) struct Identity {
    pub actor: Actor,
    pub authority: Authority,
    session: Option<BrowserSession>,
}

struct BrowserSession {
    secret: Secret,
    expires: u64,
}

#[derive(Serialize)]
pub(super) struct SessionView {
    actor_id: uuid::Uuid,
    permissions: Vec<&'static str>,
    expires_unix_ms: Option<u64>,
    csrf_token: Option<String>,
}

impl Identity {
    pub fn view(&self) -> SessionView {
        SessionView {
            actor_id: self.actor.actor_id,
            permissions: self.authority.permissions(),
            expires_unix_ms: self.session.as_ref().map(|s| s.expires),
            csrf_token: self.session.as_ref().map(|s| s.secret.csrf().encode()),
        }
    }

    pub fn revoke(&self, control: &Control) -> Result<String> {
        let session = self.session.as_ref().context(ErrorCode::AuthRequired)?;
        control.store()?.revoke_session(&session.secret.hash())?;
        Ok(cookie_header(control, "", 0))
    }
}

pub(super) fn authenticate(
    control: &Control,
    headers: &HeaderMap,
    mutation: bool,
) -> Result<Identity> {
    let credentials = Credentials::read(headers, cookie_name(control))?;
    if let Some(token) = credentials.bearer {
        let (actor, authority) = control.config().authenticate(&token.hash())?;
        return Ok(Identity {
            actor,
            authority,
            session: None,
        });
    }
    let secret = credentials.cookie.context(ErrorCode::AuthRequired)?;
    let session = control.store()?.session(&secret.hash())?;
    let authority = control
        .config()
        .authorize(session.actor, None)
        .context(ErrorCode::AuthRequired)?;
    if mutation {
        require_origin(control, headers)?;
        let text = single(headers, "x-csrf-token")?.context(ErrorCode::AccessDenied)?;
        let csrf = Secret::parse(text, ErrorCode::AccessDenied)?;
        ensure!(
            bool::from(secret.csrf().0.ct_eq(&csrf.0)),
            ErrorCode::AccessDenied
        );
    }
    Ok(Identity {
        actor: session.actor,
        authority,
        session: Some(BrowserSession {
            secret,
            expires: session.expires,
        }),
    })
}

pub(super) fn login(
    control: &Control,
    headers: &HeaderMap,
    token: &str,
) -> Result<(SessionView, String)> {
    require_origin(control, headers)?;
    let credentials = Credentials::read(headers, cookie_name(control))?;
    ensure!(credentials.bearer.is_none(), ErrorCode::InvalidRequest);
    let token = Secret::parse(token, ErrorCode::AuthRequired)?;
    let (actor, authority) = control.config().authenticate(&token.hash())?;
    let secret = Secret::generate()?;
    let cookie = cookie_header(control, &secret.encode(), 8 * 60 * 60);
    let mut store = control.store()?;
    let previous = credentials.cookie.map(|cookie| cookie.hash());
    let session = store.new_session(&secret.hash(), actor, previous.as_deref())?;
    let identity = Identity {
        actor,
        authority,
        session: Some(BrowserSession {
            secret,
            expires: session.expires,
        }),
    };
    Ok((identity.view(), cookie))
}

pub(super) fn require_origin(control: &Control, headers: &HeaderMap) -> Result<()> {
    ensure!(
        single(headers, header::ORIGIN.as_str())? == Some(control.config().public_origin.as_str()),
        ErrorCode::AccessDenied
    );
    Ok(())
}

fn cookie_name(control: &Control) -> &'static str {
    if control.config().development_http {
        "backupctl-dev"
    } else {
        "__Host-backupctl"
    }
}

fn cookie_header(control: &Control, value: &str, max_age: u32) -> String {
    let name = cookie_name(control);
    let secure = if control.config().development_http {
        ""
    } else {
        "; Secure"
    };
    format!("{name}={value}; Max-Age={max_age}; Path=/; HttpOnly; SameSite=Strict{secure}")
}
