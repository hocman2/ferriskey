use axum::{Extension, extract::State};
use ferriskey_core::domain::{
    authentication::value_objects::Identity,
    trident::ports::{GenerateRecoveryCodeInput, TridentService},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use crate::application::http::server::{
    api_entities::{
        api_error::{ApiError, ValidateJson},
        response::Response,
    },
    app_state::AppState,
};

#[derive(Debug, Serialize, Deserialize, ToSchema, Validate)]
pub struct GenerateRecoveryCodesRequest {
    amount: u8,
    code_format: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct GenerateRecoveryCodesResponse {
    codes: Vec<String>,
}

#[utoipa::path(
    post,
    path = "/login-actions/generate-recovery-codes",
    tag = "auth",
    summary = "Generate recovery codes",
    description = "Generates recovery codes that allows the user to bypass a MFA challenge",
    request_body = GenerateRecoveryCodesRequest,
    responses(
        (status = 200, body = GenerateRecoveryCodesResponse),
        (status = 400, body = String)
    )
)]
pub async fn generate_recovery_codes(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    ValidateJson(payload): ValidateJson<GenerateRecoveryCodesRequest>,
) -> Result<Response<GenerateRecoveryCodesResponse>, ApiError> {
    let result = state
        .service
        .generate_recovery_code(
            identity,
            GenerateRecoveryCodeInput {
                amount: payload.amount,
                format: payload.code_format,
            },
        )
        .await
        .map_err(ApiError::from)?;

    Ok(Response::OK(GenerateRecoveryCodesResponse {
        codes: result.codes,
    }))
}
