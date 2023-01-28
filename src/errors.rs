use aws_sdk_secretsmanager::error::GetSecretValueError;
use aws_sdk_secretsmanager::types::SdkError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DynDnsUpdateError {
  #[error("missing param {0}")]
  MissingParameter(String),
  #[error("error while updating http dns: {0}")]
  HttpNetDnsUpdate(#[from] reqwest::Error),
  #[error("invalid response from http net: {status}, error: {error}")]
  HttpNetDnsUpdateInvalidResponse {
    status: String,
    error: String
  },
  #[error("can't access secrets: {0}")]
  AwsSecretAccess(#[from] SdkError<GetSecretValueError>),
  #[error("invalid json secret: {0}")]
  AwsInvalidJsonSecret(#[from] serde_json::Error),
  #[error("invalid username/password")]
  UnAuthorized()
}