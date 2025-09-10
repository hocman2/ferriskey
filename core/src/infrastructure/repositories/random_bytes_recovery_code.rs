use crate::domain::common::entities::app_errors::CoreError;
use crate::domain::credential::entities::Credential;
use crate::domain::crypto::ports::HasherRepository;
use crate::domain::trident::entities::MfaRecoveryCode;
use crate::domain::trident::ports::{RecoveryCodeFormatter, RecoveryCodeRepository};
use crate::infrastructure::repositories::HasherRepoAny;
use rand::prelude::*;
use std::marker::PhantomData;

/// MFA code of L bytes generated randomly.
/// You generally don't want to use this directly but rather variants of RecoveryCodeRepoAny
/// as different byte length/formatter combos aren't always user friendly for display
#[derive(Clone)]
pub struct RandBytesRecoveryCodeRepository<const L: usize, F: RecoveryCodeFormatter> {
    hasher: HasherRepoAny,
    _phantom: PhantomData<F>,
}

impl<const L: usize, F: RecoveryCodeFormatter> RandBytesRecoveryCodeRepository<L, F> {
    fn new(hasher: HasherRepoAny) -> Self {
        RandBytesRecoveryCodeRepository {
            _phantom: PhantomData::<F>,
            hasher,
        }
    }
}

/// Encodes MFA code as Z-B32 with a '-' separator every 4 characters.
/// e.g: abcd-efgh-ijkl-mnop for byte length of 10
///
/// You generally want to use this formatter with multiple of 5 byte lengths (5, 10, 15, etc.)
/// as 5 bytes = 8 character in this encoding.
///
/// If the resulting string can't be separated into equal chunks, the last chunk will be left
/// incomplete
#[derive(Clone)]
pub struct B32Split4RecoveryCodeFormatter;

impl<const L: usize, F> RecoveryCodeRepository for RandBytesRecoveryCodeRepository<L, F>
where
    F: RecoveryCodeFormatter,
{
    fn generate_recovery_code(&self) -> MfaRecoveryCode {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; L];
        rng.try_fill_bytes(&mut bytes)
            .expect("Thread rng failed to fill byte slice");
        MfaRecoveryCode::from_bytes(&bytes)
    }

    fn to_string(&self, code: &MfaRecoveryCode) -> String {
        F::format(&code)
    }

    async fn verify_recovery_code(
        &self,
        in_code: String,
        against: Credential,
    ) -> Result<bool, CoreError> {
        let in_code = F::decode(in_code)?;
        let in_code = String::from_utf8(in_code.0).map_err(|_| CoreError::Invalid)?;

        let salt = against.salt.ok_or(CoreError::InternalServerError)?;

        self.hasher.verify_password(
            in_code.as_str(),
            &against.secret_data,
            &against.credential_data,
            &salt
        )
        .await
        .map_err(|_e| {
                tracing::debug!("An error occured while verifying password. The error message is intentionally left empty as it may contain sensitive data");
                CoreError::VerifyPasswordError(String::from(""))
            })
    }
}

impl B32Split4RecoveryCodeFormatter {
    const SEPARATOR_STEP: usize = 4;
    const SEPARATOR: char = '-';
}

impl RecoveryCodeFormatter for B32Split4RecoveryCodeFormatter {
    fn format(code: &MfaRecoveryCode) -> String {
        let step = Self::SEPARATOR_STEP;
        let sep = Self::SEPARATOR;

        let s = base32::encode(base32::Alphabet::Z, code.0.as_slice());
        let n_chars = s.chars().count();

        let mut out = String::with_capacity(n_chars + n_chars / step);
        for (i, c) in s.chars().enumerate() {
            if i > 0 && i % step == 0 {
                out.push(sep);
            }
            out.push(c);
        }

        out
    }

    fn decode(mut code_str: String) -> Result<MfaRecoveryCode, CoreError> {
        code_str = code_str.replace(Self::SEPARATOR, "");

        base32::decode(base32::Alphabet::Z, code_str.as_str())
            .map(|bytes| MfaRecoveryCode(bytes))
            .ok_or(CoreError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type DefaultFormatter = B32Split4RecoveryCodeFormatter;

    #[test]
    fn test_random_bytes_recovery_code_generate() {
        let repo = RandBytesRecoveryCodeRepository::<10, DefaultFormatter>::new();
        let code = repo.generate_recovery_code();
        assert_eq!(
            code.0.len(),
            10,
            "The generated code length doesn't match the generic parameter"
        );
    }

    #[test]
    fn test_random_bytes_recovery_code_string_convertion() {
        // This test is incomplete as it only validates the format of the output, not its content
        let repo_a = RandBytesRecoveryCodeRepository::<10, B32Split4RecoveryCodeFormatter>::new();
        let mut code = MfaRecoveryCode([0u8; 10].to_vec());
        assert_eq!(
            "yyyy-yyyy-yyyy-yyyy",
            repo_a.to_string(&code),
            "The output formats don't match"
        );

        // Test on non-perfect byte length
        let repo_b = RandBytesRecoveryCodeRepository::<11, B32Split4RecoveryCodeFormatter>::new();
        code = MfaRecoveryCode([0u8; 11].to_vec());
        assert_eq!(
            "yyyy-yyyy-yyyy-yyyy-yy",
            repo_b.to_string(&code),
            "The output formats don't match"
        );
    }
}
