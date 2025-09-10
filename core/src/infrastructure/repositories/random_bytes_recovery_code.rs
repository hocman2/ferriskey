use crate::domain::trident::ports::MfaRecoveryCodeRepository;
use crate::domain::trident::entities::MfaRecoveryCode;
use rand::prelude::*;

#[derive(Clone)]
pub struct RandBytesMfaRecoveryCodeRepository<const L: usize>;

impl<const L: usize> MfaRecoveryCodeRepository for RandBytesMfaRecoveryCodeRepository<L> {
    fn generate_recovery_code(&self) -> MfaRecoveryCode {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; L];
        rng.try_fill_bytes(&mut bytes).expect("Thread rng failed to fill byte slice");
        MfaRecoveryCode::from_bytes(&bytes)
    }

    fn to_string(&self, code: &MfaRecoveryCode) -> String {
        // Depending on what the length is a multiple of,
        // we can split the string representation in different chunks
        // separated by a "-" for human readability

        let length = L as usize;
        let mut num_parts = 1;
        let mut part_len = length;
        if length % 5 == 0 {
            num_parts = part_len / 5;
            part_len = 5;
        } else if length % 4 == 0 {
            num_parts = part_len / 4;
            part_len = 4;
        }

        let mut s = String::with_capacity(length + num_parts - 1);
        for i in 0..num_parts {
            let b32enc = base32::encode(
                base32::Alphabet::Rfc4648Lower { padding: false }, 
                &code.0[part_len*i..part_len*(i+1)]
            );
            if i == num_parts-1 {
                s.push_str(b32enc.as_str());
            } else {
                s.push_str(b32enc.as_str());
                s.push('-')
            }
        }
        s
    }

    fn verify_recovery_code(&self, hash: &[u8], code: &MfaRecoveryCode) -> bool {
        return false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_bytes_recovery_code() {
        let repo = RandBytesMfaRecoveryCodeRepository::<10>;
        let code = repo.generate_recovery_code();
        assert_eq!(code.0.len(), 10,
            "The generated code length doesn't match the generic parameter"
        );
    }
}
