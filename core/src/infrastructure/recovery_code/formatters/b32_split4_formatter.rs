use crate::domain::{
    common::entities::app_errors::CoreError,
    trident::{entities::MfaRecoveryCode, ports::RecoveryCodeFormatter},
};

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

impl B32Split4RecoveryCodeFormatter {
    const SEPARATOR_STEP: usize = 4;
    const SEPARATOR: char = '-';
}

impl RecoveryCodeFormatter for B32Split4RecoveryCodeFormatter {
    fn validate(code: &str) -> bool {
        let mut counter = 0;
        for c in code.chars() {
            counter += 1;
            if counter == Self::SEPARATOR_STEP + 1 {
                if c != Self::SEPARATOR {
                    return false;
                }
                counter = 0;
            } else if !(c.is_ascii_lowercase() || c.is_ascii_digit())
                || c == 'l'
                || c == 'v'
                || c == '0'
                || c == '2'
            {
                return false;
            }
        }

        true
    }

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
        if !Self::validate(code_str.as_str()) {
            return Err(CoreError::RecoveryCodeBurnError(
                "Failed to validate code as a valid B32 split 4 format".to_string(),
            ));
        }

        code_str = code_str.replace(Self::SEPARATOR, "");
        base32::decode(base32::Alphabet::Z, code_str.as_str())
            .map(MfaRecoveryCode)
            .ok_or(CoreError::Invalid)
    }
}
