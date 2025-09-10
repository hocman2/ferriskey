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
        let mut n_chars = s.chars().count();

        let mut out = String::with_capacity(n_chars + n_chars / SEPARATOR_STEP); 
        for (i,c) in s.chars().enumerate() {
            if i > 0 && i % SEPARATOR_STEP == 0 {
                out.push('-');
            }
            out.push(c);
        }

        out
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
        let mut code = MfaRecoveryCode([0u8;10].to_vec());
        assert_eq!("yyyy-yyyy-yyyy-yyyy", repo_a.to_string(&code),
            "The output formats don't match"
        );

        // Test on non-perfect byte length 
        let repo_b = RandBytesRecoveryCodeRepository::<11, B32Split4RecoveryCodeFormatter>::new();
        code = MfaRecoveryCode([0u8;11].to_vec());
        assert_eq!("yyyy-yyyy-yyyy-yyyy-yy", repo_b.to_string(&code),
            "The output formats don't match"
        );
    }
}
