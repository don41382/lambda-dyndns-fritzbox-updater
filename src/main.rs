mod errors;

use lambda_http::{Error, Request, RequestExt, Response, run, service_fn};
use lambda_http::aws_lambda_events::query_map::QueryMap;
use lambda_http::http::StatusCode;
use serde::{Deserialize, Serialize};
use crate::errors::DynDnsUpdateError;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    http_auth_token: String,
    http_dns_id: String,
    http_dns_name: String,
    http_zone_name: String,
    login_username: String,
    login_password: String
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HttpNetUpdate<'a> {
    auth_token: &'a str,
    zone_name: &'a str,
    records_to_modify: Vec<HttpNetRecordsToModify<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HttpNetRecordsToModify<'a> {
    id: &'a str,
    name: &'a str,
    #[serde(rename = "type")]
    _type: &'a str,
    content: &'a str,
    ttl: u32,
}

#[derive(Deserialize)]
struct HttpNetResponseError {
    text: String
}

#[derive(Deserialize)]
struct HttpNetResponse {
    status: String,
    errors: Vec<HttpNetResponseError>
}

fn query_parameter<'a>(key: &'a str, query: &'a QueryMap) -> Result<&'a str, DynDnsUpdateError> {
    let res = query.first(key).ok_or(DynDnsUpdateError::MissingParameter(key.to_string()))?;
    Ok(res)
}

async fn request_http_dns_update(config: &Config, ip: &str) -> Result<(), DynDnsUpdateError> {
    let client = reqwest::Client::new();
    let data = HttpNetUpdate {
        auth_token: config.http_auth_token.as_str(),
        zone_name: config.http_zone_name.as_str(),
        records_to_modify: vec![
            HttpNetRecordsToModify {
                id: config.http_dns_id.as_str(),
                name: config.http_dns_name.as_str(),
                _type: "A",
                content: ip,
                ttl: 60,
            }
        ],
    };
    let response: HttpNetResponse =
        client.post("https://partner.http.net/api/dns/v1/json/recordsUpdate")
            .json(&data)
            .send()
            .await
            .map_err(|e| DynDnsUpdateError::HttpNetDnsUpdate(e))?
            .error_for_status()?
            .json().await?;

    match response.status.as_str() {
        "pending" => Ok(()),
        status => Err(DynDnsUpdateError::HttpNetDnsUpdateInvalidResponse {
            status: status.to_string(),
            error: response.errors.first().map(|r| r.text.as_str()).unwrap_or("-").to_string()
        })
    }
}

async fn load_config_json(client: &aws_sdk_secretsmanager::Client) -> Result<Config, DynDnsUpdateError> {
    let value =
        client
            .get_secret_value().secret_id("lambda-dnydns-fritzbox-updater")
            .send()
            .await
            .map_err(DynDnsUpdateError::AwsSecretAccess)?;

    let config: Config =
        serde_json::from_str::<Config>(value.secret_string().unwrap()).map_err(|e| {
            DynDnsUpdateError::AwsInvalidJsonSecret(e)
        })?;

    Ok(config)
}

async fn load_config() -> Result<Config, DynDnsUpdateError> {
    let shared_config = aws_config::load_from_env().await;
    let aws_secret_client = aws_sdk_secretsmanager::Client::new(&shared_config);
    let config = load_config_json(&aws_secret_client).await?;
    Ok(config)
}

fn validate_authorization(config: &Config, username: &str, password: &str) -> Result<(), DynDnsUpdateError> {
    if config.login_username == username && config.login_password == password {
        Ok(())
    } else {
        Err(DynDnsUpdateError::UnAuthorized())
    }
}

async fn process_request(request: Request) -> Result<(), DynDnsUpdateError> {
    let config = &load_config().await?;

    let query = request.query_string_parameters();
    let username = query_parameter("username", &query)?;
    let password = query_parameter("password", &query)?;
    let my_ip = query_parameter("myip", &query)?;

    validate_authorization(config, &username, &password)?;
    request_http_dns_update(config, my_ip).await?;

    Ok(())
}

async fn function_handler_http(request: Request) -> Result<Response<String>, Error> {
    match process_request(request).await {
        Ok(_) => Ok(Response::new("ok".to_string())),
        Err(err) => {
            println!("error while processing the request: {:?}", err);
            Ok(
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(format!("error: {}", err))
                    .unwrap()
            )
        }
    }
}


#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .without_time()
        .init();

    run(service_fn(function_handler_http)).await
}
