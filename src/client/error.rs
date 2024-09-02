use bitcoin::address::ParseError;

#[derive(Debug)]
pub enum MempoolClientError {
    ReqwestError(reqwest::Error),
    SerdeJson(serde_json::Error),
}

impl From<reqwest::Error> for MempoolClientError {
    fn from(error: reqwest::Error) -> Self {
        MempoolClientError::ReqwestError(error)
    }
}

impl From<serde_json::Error> for MempoolClientError {
    fn from(error: serde_json::Error) -> Self {
        MempoolClientError::SerdeJson(error)
    }
}
