use axum::{
    Json,
    extract::{Form, FromRequest, Request, rejection::FormRejection},
    http::StatusCode,
    response::IntoResponse,
};
use ferriskey_core::domain::jwt::entities::JwtError;
use ferriskey_core::domain::{
    authentication::entities::AuthenticationError, webhook::entities::errors::WebhookError,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use validator::Validate;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiErrorData {
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationError {
    pub message: String,
    pub field: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    InternalServerError(String),
    UnProcessableEntity(Vec<ValidationError>),
    NotFound(String),
    Unauthorized(String),
    Forbidden(String),
    BadRequest(String),
    ServiceUnavailable(String),
}

impl ApiError {
    pub fn validation_error(message: &str, field: &str) -> Self {
        Self::UnProcessableEntity(vec![ValidationError {
            message: message.to_string(),
            field: field.to_string(),
        }])
    }

    pub fn validation_errors(errors: Vec<ValidationError>) -> Self {
        Self::UnProcessableEntity(errors)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ValidateJson<T>(pub T);

impl<T, S> FromRequest<S> for ValidateJson<T>
where
    T: DeserializeOwned + Validate,
    S: Send + Sync,
    Form<T>: FromRequest<S, Rejection = FormRejection>,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state)
            .await
            .map_err(|err| ApiError::InternalServerError(format!("Failed to parse JSON: {err}")))?;

        value.validate()?;

        Ok(ValidateJson(value))
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        match e {
            e if e.to_string().contains("validation error") => {
                Self::UnProcessableEntity(vec![ValidationError {
                    message: e.to_string(),
                    field: "unknown".to_string(),
                }])
            }
            _ => Self::InternalServerError(e.to_string()),
        }
    }
}

// Implémentation de From<validator::ValidationErrors> pour ApiError
impl From<validator::ValidationErrors> for ApiError {
    fn from(errors: validator::ValidationErrors) -> Self {
        let mut validation_errors = Vec::new();

        for (field, error_msgs) in errors.field_errors() {
            for error in error_msgs {
                let message = error
                    .message
                    .as_ref()
                    .map(|cow| cow.to_string())
                    .unwrap_or_else(|| format!("Validation failed on {field}"));

                validation_errors.push(ValidationError {
                    message,
                    field: field.to_string(),
                });
            }
        }

        Self::UnProcessableEntity(validation_errors)
    }
}

impl From<AuthenticationError> for ApiError {
    fn from(error: AuthenticationError) -> Self {
        match error {
            AuthenticationError::NotFound => Self::NotFound("Token not found".to_string()),
            AuthenticationError::Invalid => Self::Unauthorized("Invalid client".to_string()),
            AuthenticationError::InternalServerError => {
                Self::InternalServerError("Internal server error".to_string())
            }
            AuthenticationError::InvalidClient => Self::NotFound("Client not found".to_string()),
            AuthenticationError::InvalidPassword => {
                Self::Unauthorized("Invalid password".to_string())
            }
            AuthenticationError::InvalidRealm => Self::Unauthorized("Realm not found".to_string()),
            AuthenticationError::InvalidState => Self::Unauthorized("Invalid state".to_string()),
            AuthenticationError::InvalidUser => Self::Unauthorized("User not found".to_string()),
            AuthenticationError::ServiceAccountNotFound => {
                Self::NotFound("Service account not found".to_string())
            }
            AuthenticationError::InvalidRefreshToken => {
                Self::Unauthorized("Invalid refresh token".to_string())
            }
            AuthenticationError::InvalidClientSecret => {
                Self::Unauthorized("Invalid client secret".to_string())
            }
            AuthenticationError::InvalidRequest => {
                Self::Unauthorized("Invalid authorization request".to_string())
            }
        }
    }
}

impl From<JwtError> for ApiError {
    fn from(error: JwtError) -> Self {
        match error {
            JwtError::InvalidToken => Self::Unauthorized("Invalid token".to_string()),
            JwtError::ValidationError(e) => Self::InternalServerError(e),
            JwtError::ExpirationError(e) => Self::InternalServerError(e),
            JwtError::GenerationError(e) => Self::InternalServerError(e),
            JwtError::ExpiredToken => Self::InternalServerError("Token expired".to_string()),
            JwtError::InvalidKey(e) => Self::InternalServerError(e),
            JwtError::ParsingError(e) => Self::InternalServerError(e),
            JwtError::RealmKeyNotFound => {
                Self::InternalServerError("Realm key not found".to_string())
            }
        }
    }
}

impl From<WebhookError> for ApiError {
    fn from(error: WebhookError) -> Self {
        match error {
            WebhookError::Forbidden => Self::Unauthorized("Invalid webhook".to_string()),
            WebhookError::NotFound => Self::NotFound("Webhook not found".to_string()),
            WebhookError::InternalServerError => {
                Self::InternalServerError("Internal server error".to_string())
            }
            WebhookError::RealmNotFound => Self::InternalServerError("Realm not found".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiErrorResponse {
    pub code: String,
    pub status: u16,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationErrorResponse {
    pub errors: Vec<ValidationError>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        match self {
            ApiError::InternalServerError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiErrorResponse {
                    code: "E_INTERNAL_SERVER_ERROR".to_string(),
                    status: 500,
                    message: format!("Internal Server Error: {e}"),
                }),
            )
                .into_response(),
            ApiError::UnProcessableEntity(errors) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ValidationErrorResponse { errors }),
            )
                .into_response(),
            ApiError::NotFound(message) => (
                StatusCode::NOT_FOUND,
                Json(ApiErrorResponse {
                    code: "E_NOT_FOUND".to_string(),
                    status: 404,
                    message,
                }),
            )
                .into_response(),
            ApiError::Unauthorized(message) => (
                StatusCode::UNAUTHORIZED,
                Json(ApiErrorResponse {
                    code: "E_UNAUTHORIZED".to_string(),
                    status: 401,
                    message,
                }),
            )
                .into_response(),
            ApiError::Forbidden(message) => (
                StatusCode::FORBIDDEN,
                Json(ApiErrorResponse {
                    code: "E_FORBIDDEN".to_string(),
                    status: 403,
                    message,
                }),
            )
                .into_response(),
            ApiError::BadRequest(message) => (
                StatusCode::BAD_REQUEST,
                Json(ApiErrorResponse {
                    code: "E_BAD_REQUEST".to_string(),
                    status: 400,
                    message,
                }),
            )
                .into_response(),
            ApiError::ServiceUnavailable(message) => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiErrorResponse {
                    code: "E_SERVICE_UNAVAILABLE".to_string(),
                    status: 503,
                    message,
                }),
            )
                .into_response(),
        }
    }
}
