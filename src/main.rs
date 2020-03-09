use async_std::fs;
use futures::future::join_all;
use futures::join;
use hyper::{client::HttpConnector, Body, Client, Method, Request};
use hyper_tls::HttpsConnector;
use serde::{Deserialize, Serialize};
use serde_json::{from_value, json, Value};
use std::future::Future;

#[derive(Deserialize)]
struct Creds {
    email: String,
    key: String,
    domains: Vec<String>,
}

#[derive(Deserialize, Serialize)]
struct Cache {
    domains: Vec<Domain>,
    zone: String,
}
#[derive(Deserialize, Serialize, Clone)]
struct Domain {
    name: String,
    ip: String,
    id: String,
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
    creds: &Creds,
    uri: String,
    body: String,
) -> Request<Body> {
    Request::builder()
        .method(if put { Method::PUT } else { Method::GET })
        .uri(uri)
        .header("content-type", "application/json")
        .header("X-Auth-Email", creds.email.clone())
        .header("X-Auth-Key", creds.key.clone())
        .body(Body::from(body))
        .unwrap()
}

async fn get_zone<T: Future<Output = String>>(request: T) -> String {
    let json: Value = serde_json::from_str(&request.await).unwrap();
    from_value(json["result"][0]["id"].clone()).unwrap()
}

async fn get_domain_ids<T: Future<Output = String>>(request: T, creds: &Creds) -> Vec<Domain> {
    let json: Value = serde_json::from_str(&request.await).unwrap();
    let mut ids = vec![];
    for domain in json["result"].as_array().unwrap() {
        for requested_domain in creds.domains.clone() {
            if domain["type"] == json!("A") && domain["name"] == json!(requested_domain) {
                ids.push(Domain {
                    ip: from_value(domain["content"].clone()).unwrap(),
                    name: from_value(domain["name"].clone()).unwrap(),
                    id: from_value(domain["id"].clone()).unwrap(),
                });
            }
        }
    }
    ids
}

async fn get_new_domain_ids<T: Future<Output = String>>(request: T, domain: String) -> Domain {
    let json: Value = serde_json::from_str(&request.await).unwrap();
    if from_value(json["success"].clone()).unwrap() {
        println!("Successfully updated the ip for {}.", domain);
    } else {
        println!("Failed to update the ip for {}.", domain)
    }
    Domain {
        ip: from_value(json["result"]["content"].clone()).unwrap(),
        name: domain,
        id: from_value(json["result"]["id"].clone()).unwrap(),
    }
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

async fn get_creds() -> Creds {
    serde_json::from_str(&fs::read_to_string("/etc/dyndns/creds.json").await.unwrap()).unwrap()
}

async fn get_cache() -> Option<Cache> {
    if let Ok(file) = fs::read_to_string("/var/lib/dyndns/dyndns.json").await {
        serde_json::from_str(&file).ok()
    } else {
        None
    }
}

async fn create_cache(zone: String, domains: Vec<Domain>) {
    let cache = Cache { zone, domains };
    fs::write("/var/lib/dyndns/dyndns.json", json!(cache).to_string())
        .await
        .ok();
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
        (
            format!("{}{}/dns_records", url, cache.zone),
            ip_response.await,
            cache.domains,
            cache.zone,
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
    for domain in domain_ids.clone() {
        if domain.ip != ip {
            gen_cache = true;
            let url = format!("{}/{}", url, domain.id.clone());
            let body =
                json!({"type": "A", "name": domain.name.clone(), "content": ip, "ttl": 1, "proxied": false})
                    .to_string();
            let change_request = build_cloudflare_request(true, &creds, url, body);
            futures.push(get_new_domain_ids(
                make_req(change_request, client),
                domain.name,
            ));
        } else {
            println!("{} is up to date.", domain.name);
        }
    }
    if futures.len() != 0 {
        create_cache(zone, join_all(futures).await).await;
    } else if gen_cache {
        create_cache(zone, domain_ids).await;
    }
}
