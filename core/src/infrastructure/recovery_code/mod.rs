use crate::domain::trident::ports::MfaRecoveryCodeRepository;
use crate::domain::trident::entities::MfaRecoveryCode;
use crate::infrastructure::repositories::random_bytes_recovery_code::RandBytesMfaRecoveryCodeRepository;

#[derive(Clone)]
pub enum MfaRecoveryCodeRepoAny {
    RandomBytes6(RandBytesMfaRecoveryCodeRepository::<6>),
    RandomBytes8(RandBytesMfaRecoveryCodeRepository::<8>),
    RandomBytes10(RandBytesMfaRecoveryCodeRepository::<10>),
    RandomBytes12(RandBytesMfaRecoveryCodeRepository::<12>),
}

impl MfaRecoveryCodeRepository for MfaRecoveryCodeRepoAny {
    fn generate_recovery_code(&self) -> MfaRecoveryCode {
        match self {
            MfaRecoveryCodeRepoAny::RandomBytes6(repo)  => repo.generate_recovery_code(),
            MfaRecoveryCodeRepoAny::RandomBytes8(repo)  => repo.generate_recovery_code(),
            MfaRecoveryCodeRepoAny::RandomBytes10(repo) => repo.generate_recovery_code(),
            MfaRecoveryCodeRepoAny::RandomBytes12(repo) => repo.generate_recovery_code(),
        }
    }

    fn to_string(&self, code: &MfaRecoveryCode) -> String {
        match self {
            MfaRecoveryCodeRepoAny::RandomBytes6(repo)  => repo.to_string(&code),
            MfaRecoveryCodeRepoAny::RandomBytes8(repo)  => repo.to_string(&code),
            MfaRecoveryCodeRepoAny::RandomBytes10(repo) => repo.to_string(&code),
            MfaRecoveryCodeRepoAny::RandomBytes12(repo) => repo.to_string(&code),
        }
    }

    fn verify_recovery_code(&self, hash: &[u8], code: &MfaRecoveryCode) -> bool {
        return false;
    }
}
