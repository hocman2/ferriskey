use crate::domain::trident::entities::MfaRecoveryCode;
use crate::domain::trident::ports::{RecoveryCodeFormatter, RecoveryCodeRepository};
use rand::prelude::*;
use std::marker::PhantomData;

/// MFA code of L bytes generated randomly.
/// You generally don't want to use this directly but rather variants of RecoveryCodeRepoAny
/// as different byte length/formatter combos aren't always user friendly for display
#[derive(Clone)]
pub struct RandBytesRecoveryCodeRepository<const L: usize, F: RecoveryCodeFormatter> {
    _phantom: PhantomData<F>,
}

impl<const L: usize, F: RecoveryCodeFormatter> RandBytesRecoveryCodeRepository<L, F> {
    fn new() -> Self {
        RandBytesRecoveryCodeRepository {
            _phantom: PhantomData::<F>,
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

    fn verify_recovery_code(&self, hash: &[u8], code: &MfaRecoveryCode) -> bool {
        return false;
    }
}

impl RecoveryCodeFormatter for B32Split4RecoveryCodeFormatter {
    fn format(code: &MfaRecoveryCode) -> String {
        const SEPARATOR_STEP: usize = 4;

        let mut s = base32::encode(base32::Alphabet::Z, code.0.as_slice());
        let n_chars = s.chars().count();

        if n_chars % SEPARATOR_STEP == 0 {
            s.reserve(n_chars / SEPARATOR_STEP);
        } else {
            s.reserve(n_chars / SEPARATOR_STEP + 1);
        }

        for i in (SEPARATOR_STEP..n_chars).step_by(SEPARATOR_STEP + 1) {
            s.insert(i, '-');
        }

        s
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
    fn test_random_bytes_recovery_code_string_convertion() {}
}
