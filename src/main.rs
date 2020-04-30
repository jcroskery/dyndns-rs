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
    cf_uale: String,
    zone: String,
    root: String,
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
    vses2: &str,
    atok: &str,
) -> Option<Request<Body>> {
    Request::builder()
        .method(if put { Method::PUT } else { Method::GET })
        .uri(uri)
        .header("content-type", "application/json")
        .header("Cookie", format!("vses2={}", vses2))
        .header("x-atok", atok)
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

async fn make_req_for_cookies<T: Future<Output = Option<Request<Body>>>>(
    request: T,
    client: &Client<AlpnConnector>,
) -> Option<(String, String)> {
    let resp = client.request(request.await?).await.ok()?;
    let mut vses2 = String::new();
    for cookie in resp.headers().get_all("set-cookie").iter() {
        let cookie = cookie.to_str().ok()?;
        if cookie.contains("vses2") {
            vses2 = cookie.split("vses2=").collect::<String>().split(";").next().unwrap().to_string();
        }
    }
    let string = String::from_utf8(to_bytes(resp.into_body()).await.ok()?.to_vec()).unwrap();
    let mut iter = string.split("\"atok\":\"");
    iter.next();
    let token = iter.next().unwrap().split("\"").next().unwrap();
    Some((vses2, token.to_string()))
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

async fn vses2_req(cf_uale: &str, zone: &str, root: &str) -> Option<Request<Body>> {
    Request::builder()
        .method(Method::GET)
        .uri(format!("https://dash.cloudflare.com/{}/{}/dns", zone, root))
        .header("Cookie", cf_uale)
        .body(Body::from(""))
        .ok()
}

async fn get_vses2(cf_uale: &str, zone: &str, root: &str, client: &Client<AlpnConnector>) -> (String, String) {
    make_req_for_cookies(vses2_req(cf_uale, zone, root), client).await.unwrap()
}

async fn dyndns() -> Option<()> {
    let mut gen_cache = false;
    let client = &Client::builder().http2_only(true).build(AlpnConnector::new());
    let creds = get_creds().await?;
    let url = "https://dash.cloudflare.com/api/v4/zones/".to_string();
    let ip_request = get("https://ipecho.net/plain");
    let ip_response = make_req(ip_request, client);
    let (vses2, atok) = get_vses2(&creds.cf_uale, &creds.zone, &creds.root, client).await;
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
        let zones_request = build_cloudflare_request(false, &creds, url.clone(), "".to_string(), &vses2, &atok);
        let zones_response = get_zone(make_req(zones_request, client));
        let (ip, zone) = join!(ip_response, zones_response);
        let url = format!("{}{}/dns_records", url, zone.clone()?);
        let zones_request = build_cloudflare_request(false, &creds, url.clone(), "".to_string(), &vses2, &atok);
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
            let change_request = build_cloudflare_request(true, &creds, url, body, &vses2, &atok);
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
