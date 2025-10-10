use uuid::Uuid;

use crate::domain::{
    authentication::value_objects::Identity,
    common::entities::app_errors::CoreError,
    credential::entities::Credential,
    crypto::entities::HashResult,
    trident::entities::{
        MfaRecoveryCode, TotpSecret, WebAuthnAttestationConveyance, WebAuthnAttestationFormat,
        WebAuthnAuthenticatorAttestationResponse, WebAuthnChallenge, WebAuthnCredentialDescriptor,
        WebAuthnCredentialId, WebAuthnHint, WebAuthnPubKeyCredParams, WebAuthnRelayingParty,
        WebAuthnUser,
    },
};

pub trait TotpService: Send + Sync + Clone + 'static {
    fn generate_secret(&self) -> Result<TotpSecret, CoreError>;
    fn generate_otpauth_uri(&self, issuer: &str, user_email: &str, secret: &TotpSecret) -> String;
    fn verify(&self, secret: &TotpSecret, code: &str) -> Result<bool, CoreError>;
}

pub struct WebAuthnChallengeCreationInput {
    pub session_code: String,

    /// This gets passed in the output as RP ID
    /// (https://w3c.github.io/webauthn/#relying-party-identifier)
    /// This will work fine for localhost but may not work in other scenario
    pub server_host: String,
}

/// https://w3c.github.io/webauthn/#dictdef-publickeycredentialrpentity
pub struct WebAuthnChallengeCreationOutput {
    pub challenge: WebAuthnChallenge,
    pub rp: WebAuthnRelayingParty,
    pub user: WebAuthnUser,
    pub attestation: WebAuthnAttestationConveyance,
    pub attestation_formats: Vec<WebAuthnAttestationFormat>,
    pub pub_key_cred_params: Vec<WebAuthnPubKeyCredParams>,
    pub exclude_credentials: Vec<WebAuthnCredentialDescriptor>,
    pub hints: Vec<WebAuthnHint>,
    pub timeout: u64,
}

pub struct WebAuthnCredentialCreationInput {
    pub credential: WebAuthnCredentialId,
    pub response: WebAuthnAuthenticatorAttestationResponse,
    pub typ: String,
}

pub struct WebAuthnCredentialCreationOutput {}

pub struct ChallengeOtpInput {
    pub session_code: String,
    pub code: String,
}

pub struct ChallengeOtpOutput {
    pub login_url: String,
}

pub struct SetupOtpInput {
    pub issuer: String,
}

pub struct SetupOtpOutput {
    pub secret: String,
    pub otpauth_uri: String,
}

pub struct UpdatePasswordInput {
    pub realm_name: String,
    pub value: String,
}

pub struct VerifyOtpInput {
    pub secret: String,
    pub code: String,
    pub label: Option<String>,
}

pub struct VerifyOtpOutput {
    pub message: String,
    pub user_id: Uuid,
}

pub struct GenerateRecoveryCodeInput {
    pub amount: u8,
    pub format: String,
}

pub struct GenerateRecoveryCodeOutput {
    pub codes: Vec<String>,
}

pub struct BurnRecoveryCodeInput {
    pub session_code: String,
    pub format: String,
    pub code: String,
}

pub struct BurnRecoveryCodeOutput {
    pub login_url: String,
}

pub trait RecoveryCodeRepository: Send + Sync + Clone + 'static {
    fn generate_recovery_code(&self) -> MfaRecoveryCode;
    fn generate_n_recovery_code(&self, n: usize) -> Vec<MfaRecoveryCode> {
        let mut out = Vec::<MfaRecoveryCode>::with_capacity(n);
        for _ in 0..n {
            out.push(self.generate_recovery_code());
        }
        out
    }

    /// Returns a string safe for long term storage
    /// Generally this is just hashing the code using an internal hasher
    fn secure_for_storage(
        &self,
        code: &MfaRecoveryCode,
    ) -> impl Future<Output = Result<HashResult, CoreError>> + Send;

    /// Compares the given human-readable formatted code against a stored credential
    fn verify(
        &self,
        in_code: &MfaRecoveryCode,
        against: Credential,
    ) -> impl Future<Output = Result<Option<Credential>, CoreError>> + Send;
}

pub trait RecoveryCodeFormatter: Send + Sync + Clone + 'static {
    /// Returns a formatted string representing the code
    fn format(code: &MfaRecoveryCode) -> String;
    /// Returns wether or not a user string matches the expected format
    /// for this formatter.
    /// `decode` implementations must call this beforehand
    fn validate(code: &str) -> bool;
    /// Builds a code from a user string
    fn decode(code: String) -> Result<MfaRecoveryCode, CoreError>;
}

pub trait TridentService: Send + Sync + Clone + 'static {
    fn generate_recovery_code(
        &self,
        identity: Identity,
        input: GenerateRecoveryCodeInput,
    ) -> impl Future<Output = Result<GenerateRecoveryCodeOutput, CoreError>> + Send;
    fn burn_recovery_code(
        &self,
        identity: Identity,
        input: BurnRecoveryCodeInput,
    ) -> impl Future<Output = Result<BurnRecoveryCodeOutput, CoreError>> + Send;
    fn webauthn_challenge_for_credential_creation(
        &self,
        identity: Identity,
        input: WebAuthnChallengeCreationInput,
    ) -> impl Future<Output = Result<WebAuthnChallengeCreationOutput, CoreError>> + Send;
    fn finalize_webauthn_credential_creation(
        &self,
        identity: Identity,
        input: WebAuthnCredentialCreationInput,
    ) -> impl Future<Output = Result<WebAuthnCredentialCreationOutput, CoreError>> + Send;

    fn challenge_otp(
        &self,
        identity: Identity,
        input: ChallengeOtpInput,
    ) -> impl Future<Output = Result<ChallengeOtpOutput, CoreError>> + Send;
    fn setup_otp(
        &self,
        identity: Identity,
        input: SetupOtpInput,
    ) -> impl Future<Output = Result<SetupOtpOutput, CoreError>> + Send;
    fn update_password(
        &self,
        identity: Identity,
        input: UpdatePasswordInput,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;
    fn verify_otp(
        &self,
        identity: Identity,
        input: VerifyOtpInput,
    ) -> impl Future<Output = Result<VerifyOtpOutput, CoreError>> + Send;
}
