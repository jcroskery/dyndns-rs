use futures::future::join_all;
use futures::join;
use http::Request;
use hyper::{Body, Method, Client};
use hyper::body::to_bytes;
use serde::{Deserialize, Serialize};
use serde_json::{from_str, from_value, json, Value};
use hyper_alpn::AlpnConnector;

use async_std::fs;

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

async fn get(uri: &str) -> Option<Request<Body>> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::from(""))
        .ok()
}

async fn build_cloudflare_request(
    put: bool,
    creds: &Creds,
    uri: String,
    body: String,
) -> Option<Request<Body>> {
    Request::builder()
        .method(if put { Method::PUT } else { Method::GET })
        .uri(uri)
        .header("content-type", "application/json")
        .header("X-Auth-Email", creds.email.clone())
        .header("X-Auth-Key", creds.key.clone())
        .body(Body::from(body))
        .ok()
}

async fn get_zone<T: Future<Output = Option<String>>>(request: T) -> Option<String> {
    let json: Value = from_str(&request.await?).ok()?;
    from_value(json["result"][0]["id"].clone()).ok()
}

async fn get_domain_ids<T: Future<Output = Option<String>>>(
    request: T,
    creds: &Creds,
) -> Option<Vec<Domain>> {
    let json: Value = from_str(&request.await?).ok()?;
    let mut ids = vec![];
    for domain in json["result"].as_array()? {
        for requested_domain in creds.domains.clone() {
            if domain["type"] == json!("A") && domain["name"] == json!(requested_domain) {
                ids.push(Domain {
                    ip: from_value(domain["content"].clone()).ok()?,
                    name: from_value(domain["name"].clone()).ok()?,
                    id: from_value(domain["id"].clone()).ok()?,
                });
            }
        }
    }
    Some(ids)
}

async fn get_new_domain_ids<T: Future<Output = Option<String>>>(
    request: T,
    domain: String,
) -> Option<Domain> {
    let json: Value = from_str(&request.await?).ok()?;
    if from_value(json["success"].clone()).ok()? {
        println!("Successfully updated the ip for {}.", domain);
    } else {
        println!("Failed to update the ip for {}.", domain)
    }
    Some(Domain {
        ip: from_value(json["result"]["content"].clone()).ok()?,
        name: domain,
        id: from_value(json["result"]["id"].clone()).ok()?,
    })
}

async fn make_req<T: Future<Output = Option<Request<Body>>>>(
    request: T,
    client: &Client<AlpnConnector>,
) -> Option<String> {
    let resp = client.request(request.await?).await.ok()?;
    String::from_utf8(to_bytes(resp.into_body()).await.ok()?.to_vec()).ok()
}

async fn get_creds() -> Option<Creds> {
    from_str(&fs::read_to_string("/etc/dyndns/creds.json").await.ok()?).ok()
}

async fn get_cache() -> Option<Cache> {
    if let Ok(file) = fs::read_to_string("/var/lib/dyndns/dyndns.json").await {
        from_str(&file).ok()
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

async fn delete_cache() {
    fs::write("/var/lib/dyndns/dyndns.json", "").await.ok();
}

async fn dyndns() -> Option<()> {
    let mut gen_cache = false;
    let client = &Client::builder().http2_only(true).build(AlpnConnector::new());
    let creds = get_creds().await?;
    let url = "https://api.cloudflare.com/client/v4/zones/".to_string();
    let ip_request = get("https://ipecho.net/plain");
    let ip_response = make_req(ip_request, client);
    let (url, ip, domain_ids, zone) = if let Some(cache) = get_cache().await {
        let domains: Vec<String> = cache.domains.iter().map(|x| x.name.clone()).collect();
        for domain in creds.domains.clone() {
            if !domains.contains(&domain) {
                return None;
            }
        }
        (
            format!("{}{}/dns_records", url, cache.zone),
            ip_response.await?,
            cache.domains,
            cache.zone,
        )
    } else {
        let zones_request = build_cloudflare_request(false, &creds, url.clone(), "".to_string());
        let zones_response = get_zone(make_req(zones_request, client));
        let (ip, zone) = join!(ip_response, zones_response);
        let url = format!("{}{}/dns_records", url, zone.clone()?);
        let zones_request = build_cloudflare_request(false, &creds, url.clone(), "".to_string());
        let domain_ids = get_domain_ids(make_req(zones_request, client), &creds).await;
        gen_cache = true;
        (url, ip?, domain_ids?, zone?)
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
        let mut domains = vec![];
        for domain in join_all(futures).await {
            domains.push(domain?);
        }
        create_cache(zone, domains).await;
    } else if gen_cache {
        create_cache(zone, domain_ids).await;
    }
    Some(())
}

#[tokio::main]
async fn main() {
    if let None = dyndns().await {
        delete_cache().await;
        dyndns().await;
    }
}
