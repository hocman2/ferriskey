use crate::domain::common::entities::app_errors::CoreError;
use crate::domain::credential::entities::Credential;
use crate::domain::crypto::entities::HashResult;
use crate::domain::trident::entities::MfaRecoveryCode;
use crate::domain::trident::ports::RecoveryCodeRepository;
use crate::infrastructure::repositories::random_bytes_recovery_code::{
    B32Split4RecoveryCodeFormatter, RandBytesRecoveryCodeRepository,
};

#[derive(Clone)]
pub enum RecoveryCodeRepoAny {
    RandomBytes10(RandBytesRecoveryCodeRepository<10, B32Split4RecoveryCodeFormatter>),
}

impl RecoveryCodeRepository for RecoveryCodeRepoAny {
    fn generate_recovery_code(&self) -> MfaRecoveryCode {
        match self {
            RecoveryCodeRepoAny::RandomBytes10(repo) => repo.generate_recovery_code(),
        }
    }

    fn to_string(&self, code: &MfaRecoveryCode) -> String {
        match self {
            RecoveryCodeRepoAny::RandomBytes10(repo) => repo.to_string(&code),
        }
    }
    fn from_string(&self, code: String) -> Result<MfaRecoveryCode, CoreError> {
        match self {
            RecoveryCodeRepoAny::RandomBytes10(repo) => repo.from_string(code),
        }
    }

    async fn secure_for_storage(
        &self,
        code: &MfaRecoveryCode
    ) -> Result<HashResult, CoreError> {
        match self {
            RecoveryCodeRepoAny::RandomBytes10(repo) => {
                repo.secure_for_storage(&code).await
            }
        }
    }

    async fn verify(
        &self,
        in_code: String,
        against: Credential,
    ) -> Result<bool, CoreError> {
        match self {
            RecoveryCodeRepoAny::RandomBytes10(repo) => {
                repo.verify(in_code, against).await
            }
        }
    }
}
