use std::{env::args, time::Duration};

use anyhow::bail;
use pow_challenge_server_http_lib::{solve_challenge, ADDR};
use reqwest::{RequestBuilder, Response};
use serde_json::json;
use tracing::{debug, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

async fn retry(request: RequestBuilder) -> anyhow::Result<Response> {
    let mut n_retry = 0;
    let response = loop {
        if let Ok(response) = request.try_clone().unwrap().send().await {
            break response;
        }
        debug!("Failing response");
        n_retry += 1;
        if n_retry >= 10 {
            bail!("request failed");
        }
        tokio::time::sleep(Duration::from_secs_f32(0.1)).await;
    };
    if !response.status().is_success() {
        warn!(
            "Request status: {:?} - {:?}",
            response.status(),
            response.text().await,
        );
        bail!("request failed");
    } else {
        Ok(response)
    }
}

async fn client(addr: String) -> anyhow::Result<()> {
    let response = retry(reqwest::Client::new().post(format!("http://{addr}/authorize"))).await?;
    let resp_json: serde_json::Value = response.json().await?;

    let access_token = resp_json["access_token"].as_str().unwrap();
    let input = resp_json["input"].as_str().unwrap();
    let zero_count = resp_json["zero_count"].as_u64().unwrap();

    let postfix = solve_challenge(zero_count as usize, input);

    let json = json!({
        "input": input,
        "zero_count": zero_count as u8,
        "postfix": postfix,
    });

    let response = retry(
        reqwest::Client::new()
            .post(format!("http://{addr}/protected"))
            .json(&json)
            .bearer_auth(access_token),
    )
    .await?;
    let resp_text = response.text().await?;
    info!("{resp_text}");

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "client=INFO".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let addr = args().nth(1).unwrap_or_else(|| ADDR.to_string());
    let n_clients: usize = args().nth(2).and_then(|a| a.parse().ok()).unwrap_or(1);

    let mut tasks = Vec::with_capacity(n_clients);
    for _ in 0..n_clients {
        tasks.push(tokio::task::spawn(client(addr.clone())));
    }
    let mut results = Vec::with_capacity(tasks.len());
    for task in tasks {
        results.push(task.await.map_err(|e| e.into()).and_then(|r| r));
    }
    debug!("RESULTS: {results:?}");
    debug!(
        "RESULTS sucess/total: {}/{}",
        results.iter().filter(|r| r.is_ok()).count(),
        results.len()
    );
    Ok(())
}
