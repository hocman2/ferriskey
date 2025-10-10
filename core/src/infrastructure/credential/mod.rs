use crate::domain::credential::entities::{Credential, CredentialError};
use crate::domain::credential::ports::CredentialRepository;
use crate::domain::crypto::entities::HashResult;
use crate::domain::trident::entities::{
    WebAuthnAuthenticatorAttestationResponse, WebAuthnCredentialId,
};
use crate::infrastructure::repositories::credential_repository::PostgresCredentialRepository;
use serde_json::Value;
use uuid::Uuid;

#[derive(Clone)]
pub enum CredentialRepoAny {
    Postgres(PostgresCredentialRepository),
}

impl CredentialRepository for CredentialRepoAny {
    async fn create_credential(
        &self,
        user_id: Uuid,
        credential_type: String,
        hash_result: HashResult,
        label: String,
        temporary: bool,
    ) -> Result<Credential, CredentialError> {
        match self {
            CredentialRepoAny::Postgres(repo) => {
                repo.create_credential(user_id, credential_type, hash_result, label, temporary)
                    .await
            }
        }
    }

    async fn get_password_credential(&self, user_id: Uuid) -> Result<Credential, CredentialError> {
        match self {
            CredentialRepoAny::Postgres(repo) => repo.get_password_credential(user_id).await,
        }
    }

    async fn delete_password_credential(&self, user_id: Uuid) -> Result<(), CredentialError> {
        match self {
            CredentialRepoAny::Postgres(repo) => repo.delete_password_credential(user_id).await,
        }
    }

    async fn get_credentials_by_user_id(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<Credential>, CredentialError> {
        match self {
            CredentialRepoAny::Postgres(repo) => repo.get_credentials_by_user_id(user_id).await,
        }
    }

    async fn delete_by_id(&self, credential_id: Uuid) -> Result<(), CredentialError> {
        match self {
            CredentialRepoAny::Postgres(repo) => repo.delete_by_id(credential_id).await,
        }
    }

    async fn create_custom_credential(
        &self,
        user_id: Uuid,
        credential_type: String,
        secret_data: String,
        label: Option<String>,
        credential_data: Value,
    ) -> Result<Credential, CredentialError> {
        match self {
            CredentialRepoAny::Postgres(repo) => {
                repo.create_custom_credential(
                    user_id,
                    credential_type,
                    secret_data,
                    label,
                    credential_data,
                )
                .await
            }
        }
    }

    async fn create_recovery_code_credentials(
        &self,
        user_id: Uuid,
        hashes: Vec<HashResult>,
    ) -> Result<(), CredentialError> {
        match self {
            CredentialRepoAny::Postgres(repo) => {
                repo.create_recovery_code_credentials(user_id, hashes).await
            }
        }
    }

    async fn create_webauthn_credential(
        &self,
        user_id: Uuid,
        webauthn_credential_id: WebAuthnCredentialId,
        attestation_response: WebAuthnAuthenticatorAttestationResponse,
    ) -> Result<Credential, CredentialError> {
        match self {
            CredentialRepoAny::Postgres(repo) => {
                repo.create_webauthn_credential(
                    user_id,
                    webauthn_credential_id,
                    attestation_response,
                )
                .await
            }
        }
    }
}
