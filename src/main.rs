use hyper::{client::HttpConnector, Body, Client, Method, Request};
use hyper_tls::HttpsConnector;
use std::future::Future;
use async_std::fs;
use serde_json::Value;
use futures::join;

async fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::from(""))
        .unwrap()
}

async fn build_cloudflare_request(post: bool, creds: Value, uri: &str, body: String) -> Request<Body> {
    Request::builder()
        .method(if post {Method::POST} else {Method::GET})
        .uri(uri)
        .header("content-type", "application/json")
        .header("X-Auth-Email", creds["email"].as_str().unwrap())
        .header("X-Auth-Key", creds["key"].as_str().unwrap())
        .body(Body::from(body))
        .unwrap()
}

async fn get_zone<T: Future<Output = String>>(request: T) -> String {
    let json: Value = serde_json::from_str(&request.await).unwrap();
    serde_json::from_value(json["result"][0]["id"].clone()).unwrap()
}

async fn make_req<T: Future<Output = Request<Body>>>(
    request: T,
    client: Client<HttpsConnector<HttpConnector>>,
) -> String {
    let t = request.await;
    let resp = client.request(t).await.unwrap();
    String::from_utf8(
        hyper::body::to_bytes(resp.into_body())
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

async fn get_creds() -> Value {
    serde_json::from_str(&fs::read_to_string("creds.json").await.unwrap()).unwrap()
}

#[tokio::main]
async fn main() {
    let creds = get_creds();
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, Body>(https);
    let ip_request = get("https://ipecho.net/plain");
    let ip_response = make_req(ip_request, client.clone());
    let creds = creds.await;
    let zones_request = build_cloudflare_request(false, creds.clone(), "https://api.cloudflare.com/client/v4/zones/", "".to_string());
    let zones_response = get_zone(make_req(zones_request, client));
    let (ip, zone) = join!(ip_response, zones_response);
    println!("{} {}", ip, zone);
}
