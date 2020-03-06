use hyper::{client::HttpConnector, Body, Client, Method, Request};
use hyper_tls::HttpsConnector;
use std::future::Future;

async fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::from(""))
        .unwrap()
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

#[tokio::main]
async fn main() {
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, Body>(https);
    let request = get("https://ipecho.net/plain");
    let f_response = make_req(request, client);
}
