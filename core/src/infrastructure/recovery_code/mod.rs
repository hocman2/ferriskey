use crate::domain::trident::ports::MfaRecoveryCodeRepository;
use crate::infrastructure::repositories::random_bytes_recovery_code::RandBytesMfaRecoveryCodeRepository;

#[derive(Clone)]
pub enum MfaRecoveryCodeRepoAny {
    RandomBytes(RandBytesMfaRecoveryCodeRepository),
}

impl MfaRecoveryCodeRepository for MfaRecoveryCodeRepoAny {
    fn generate_recovery_code(&self) -> MfaRecoveryCode {
        match self {
            MfaRecoveryCodeRepoAny::RandomBytes(repo) => repo.generate_recovery_code()
        }
    }
}
