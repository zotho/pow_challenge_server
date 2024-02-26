//! Based on example of JWT authorization/authentication.
//! Source: https://github.com/tokio-rs/axum/blob/b03f6c1184723bdc079215222fc168ef96847dea/examples/jwt/src/main.rs
//!
//! Run with
//!
//! ```not_rust
//! JWT_SECRET=secret cargo run --bin server
//! ```

use std::{
    env::args,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    async_trait,
    extract::{FromRequestParts, State},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, RequestPartsExt, Router,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use dashmap::DashMap;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use pow_challenge_server_http_lib::{verify_proof, ADDR};
use rand::{
    distributions::{Alphanumeric, DistString},
    seq::SliceRandom,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Quick instructions
//
// - get an authorization token:
//
// curl -s \
//     -w '\n' \
//     -H 'Content-Type: application/json' \
//     http://localhost:3000/authorize
//
// - visit the protected area using the authorized token and solution
//
// curl -s \
//     -w '\n' \
//     -H 'Content-Type: application/json' \
//     -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjEwMDAwMDAwMDAwfQ.M3LAZmrzUkXDC1q5mSzFAs_kJrwuKz3jOoDmjJ0G4gM' \
//     -d '{"input":"foo","zero_count":5,"postfix":1234}' \
//     http://localhost:3000/protected
//
// - try to visit the protected area using an invalid token
//
// curl -s \
//     -w '\n' \
//     -H 'Content-Type: application/json' \
//     -H 'Authorization: Bearer blahblahblah' \
//     -d '{"input":"foo","zero_count":5,"postfix":1234}' \
//     http://localhost:3000/protected

static KEYS: Lazy<Keys> = Lazy::new(|| {
    let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| {
        let string = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
        warn!("JWT_SECRET var must be set. Setting: {string}");
        string
    });

    Keys::new(secret.as_bytes())
});

#[derive(Debug, Clone)]
struct AppState {
    jwt_exp: Duration,
    jwt_leeway: Duration,
    jwt_invalidated: Arc<DashMap<String, u64>>,
    zero_count: u8,
    quotes: Vec<String>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "server=INFO".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let quotes: Vec<_> = include_str!("../../quotes.txt")
        .trim()
        .lines()
        .map(|line| line.to_string())
        .collect();

    let jwt_exp =
        Duration::from_secs_f32(args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(5.0));
    let zero_count: u8 = args().nth(2).and_then(|a| a.parse().ok()).unwrap_or(5);

    let jwt_invalidated = Arc::new(DashMap::new());
    let jwt_leeway = Duration::from_secs(1);

    let app = Router::new()
        .route("/authorize", post(authorize))
        .route("/protected", post(protected))
        .with_state(AppState {
            jwt_exp,
            jwt_leeway,
            jwt_invalidated: Arc::clone(&jwt_invalidated),
            zero_count,
            quotes,
        });

    let listener = tokio::net::TcpListener::bind(ADDR).await.unwrap();
    info!("listening on {}", listener.local_addr().unwrap());
    let _serve_task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let _jwt_invalidated_cleanup_task = tokio::spawn(async move {
        loop {
            let since_the_epoch = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards");
            jwt_invalidated.retain(|_k, exp| {
                exp.saturating_add(jwt_leeway.as_secs()) > since_the_epoch.as_secs()
            });
            let after_clean = jwt_invalidated.len();
            while jwt_invalidated.len() == after_clean {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    });

    _serve_task.await.unwrap();

    _jwt_invalidated_cleanup_task.abort();
}

#[instrument(target = "pow_challenge_server_http::authorize", err(Debug), skip_all)]
async fn authorize(State(state): State<AppState>) -> Result<Json<serde_json::Value>, AuthError> {
    info!("New request");
    let input = Alphanumeric.sample_string(&mut rand::thread_rng(), 36);

    let since_the_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let exp = since_the_epoch.saturating_add(state.jwt_exp);

    let claims = Claims {
        input: input.clone(),
        zero_count: state.zero_count,
        // Mandatory expiry time as UTC timestamp, seconds
        exp: exp.as_secs(),
    };
    // Create the authorization token
    let token = encode(&Header::default(), &claims, &KEYS.encoding)
        .map_err(|_| AuthError::TokenCreation)?;

    // Send the authorized token
    Ok(Json(json!({
        "access_token": token,
        "token_type": "Bearer",
        "input": input,
        "zero_count": state.zero_count,
    })))
}

#[instrument(target = "pow_challenge_server_http::protected", err(Debug), skip_all)]
async fn protected(
    State(state): State<AppState>,
    (claims, bearer): (Claims, Bearer),
    Json(payload): Json<ProofPayload>,
) -> Result<String, AuthError> {
    info!("New request");
    if state.jwt_invalidated.contains_key(bearer.token()) {
        return Err(AuthError::InvalidToken);
    }
    state
        .jwt_invalidated
        .insert(bearer.token().to_string(), claims.exp);

    if claims.input != payload.input || claims.zero_count != payload.zero_count {
        return Err(AuthError::InvalidPayload);
    }

    if !verify_proof(payload.zero_count as usize, &payload.input, payload.postfix) {
        return Err(AuthError::InvalidProof);
    }
    // Send the protected data to the user
    Ok(state
        .quotes
        .choose(&mut rand::thread_rng())
        .unwrap()
        .clone())
}

#[derive(Debug, Deserialize)]
struct ProofPayload {
    input: String,
    zero_count: u8,
    postfix: u32,
}

#[async_trait]
impl FromRequestParts<AppState> for (Claims, Bearer) {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;
        // Decode the user data
        let mut validation = Validation::default();
        validation.leeway = state.jwt_leeway.as_secs();
        let token_data = decode::<Claims>(bearer.token(), &KEYS.decoding, &validation)
            .map_err(|_| AuthError::InvalidToken)?;

        Ok((token_data.claims, bearer))
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
            AuthError::InvalidProof => (StatusCode::BAD_REQUEST, "Invalid proof"),
            AuthError::InvalidPayload => (StatusCode::BAD_REQUEST, "Invalid payload"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl Keys {
    fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    input: String,
    zero_count: u8,
    exp: u64,
}

#[derive(Debug)]
enum AuthError {
    TokenCreation,
    InvalidToken,
    InvalidProof,
    InvalidPayload,
}
