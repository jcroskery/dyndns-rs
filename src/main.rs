use async_std::fs;
use futures::future::join_all;
use futures::join;
use hyper::{client::HttpConnector, Body, Client, Method, Request};
use hyper_tls::HttpsConnector;
use serde_json::{from_value, json, Value};
use std::future::Future;

#[derive(serde::Deserialize)]
struct Creds {
    email: String,
    key: String,
    domains: Vec<String>,
}

async fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::from(""))
        .unwrap()
}

async fn build_cloudflare_request(
    put: bool,
    creds: &Value,
    uri: String,
    body: String,
) -> Request<Body> {
    Request::builder()
        .method(if put { Method::PUT } else { Method::GET })
        .uri(uri)
        .header("content-type", "application/json")
        .header("X-Auth-Email", creds["email"].as_str().unwrap())
        .header("X-Auth-Key", creds["key"].as_str().unwrap())
        .body(Body::from(body))
        .unwrap()
}

async fn get_zone<T: Future<Output = String>>(request: T) -> String {
    let json: Value = serde_json::from_str(&request.await).unwrap();
    from_value(json["result"][0]["id"].clone()).unwrap()
}

async fn get_domain_ids<T: Future<Output = String>>(
    request: T,
    creds: &Value,
) -> Vec<(String, String, String)> {
    let json: Value = serde_json::from_str(&request.await).unwrap();
    let mut ids = vec![];
    for domain in json["result"].as_array().unwrap() {
        for requested_domain in creds["domains"].as_array().unwrap() {
            if domain["type"] == json!("A") && &domain["name"] == requested_domain {
                ids.push((
                    from_value(domain["content"].clone()).unwrap(),
                    from_value(domain["name"].clone()).unwrap(),
                    from_value(domain["id"].clone()).unwrap(),
                ));
            }
        }
    }
    ids
}

async fn get_new_domain_ids<T: Future<Output = String>>(
    request: T,
    domain: String,
) -> (String, String, String) {
    let json: Value = serde_json::from_str(&request.await).unwrap();
    if from_value(json["success"].clone()).unwrap() {
        println!("Successfully updated the ip for {}.", domain);
    } else {
        println!("Failed to update the ip for {}.", domain)
    }
    (
        from_value(json["result"]["content"].clone()).unwrap(),
        domain,
        from_value(json["result"]["id"].clone()).unwrap(),
    )
}

async fn make_req<T: Future<Output = Request<Body>>>(
    request: T,
    client: &Client<HttpsConnector<HttpConnector>>,
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
    serde_json::from_str(&fs::read_to_string("/etc/dyndns/creds.json").await.unwrap()).unwrap()
}

async fn get_cache() -> Option<Value> {
    if let Ok(file) = fs::read_to_string("/var/lib/dyndns/dyndns.json").await {
        serde_json::from_str(&file).ok()
    } else {
        None
    }
}

async fn create_cache(zone: String, domain_ids: Vec<(String, String, String)>) {
    fs::write(
        "/var/lib/dyndns/dyndns.json",
        json!({"zone": zone, "domains": domain_ids}).to_string(),
    )
    .await
    .ok();
}

fn parse_cache(cache: Value) -> (String, Vec<(String, String, String)>) {
    let cool = from_value(cache["domains"].clone()).unwrap();
    (from_value(cache["zone"].clone()).unwrap(), cool)
}

#[tokio::main]
async fn main() {
    let mut gen_cache = false;
    let https = HttpsConnector::new();
    let client = &Client::builder().build::<_, Body>(https);
    let creds = get_creds().await;
    let url = "https://api.cloudflare.com/client/v4/zones/".to_string();
    let ip_request = get("https://ipecho.net/plain");
    let ip_response = make_req(ip_request, client);
    let (url, ip, domain_ids, zone) = if let Some(cache) = get_cache().await {
        let (zone, domain_ids) = parse_cache(cache);
        (
            format!("{}{}/dns_records", url, zone),
            ip_response.await,
            domain_ids,
            zone,
        )
    } else {
        let zones_request = build_cloudflare_request(false, &creds, url.clone(), "".to_string());
        let zones_response = get_zone(make_req(zones_request, client));
        let (ip, zone) = join!(ip_response, zones_response);
        let url = format!("{}{}/dns_records", url, zone);
        let zones_request = build_cloudflare_request(false, &creds, url.clone(), "".to_string());
        let domain_ids = get_domain_ids(make_req(zones_request, client), &creds).await;
        gen_cache = true;
        (url, ip, domain_ids, zone)
    };
    let mut futures = vec![];
    for (cloudflare_ip, domain, id) in domain_ids.clone() {
        if cloudflare_ip != ip {
            gen_cache = true;
            let url = format!("{}/{}", url, id.clone());
            let body =
                json!({"type": "A", "name": domain.clone(), "content": ip, "ttl": 1, "proxied": false})
                    .to_string();
            let change_request = build_cloudflare_request(true, &creds, url, body);
            futures.push(get_new_domain_ids(make_req(change_request, client), domain));
        } else {
            println!("{} is up to date.", domain);
        }
    }
    if futures.len() != 0 {
        create_cache(zone, join_all(futures).await).await;
    } else if gen_cache {
        create_cache(zone, domain_ids).await;
    }
}
