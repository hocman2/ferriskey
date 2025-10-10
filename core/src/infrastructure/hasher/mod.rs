use crate::domain::crypto::entities::HashResult;
use crate::domain::crypto::ports::HasherRepository;
use crate::infrastructure::repositories::argon2_hasher::Argon2HasherRepository;
use anyhow::Error;

#[derive(Clone)]
pub enum HasherRepoAny {
    Argon2(Argon2HasherRepository),
}

impl HasherRepository for HasherRepoAny {
    async fn hash_password(&self, password: &str) -> Result<HashResult, Error> {
        match self {
            HasherRepoAny::Argon2(repo) => repo.hash_password(password).await,
        }
    }

    async fn verify_password(
        &self,
        password: &str,
        secret_data: &str,
        hash_iterations: u32,
        algorithm: &str,
        salt: &str,
    ) -> Result<bool, Error> {
        match self {
            HasherRepoAny::Argon2(repo) => {
                repo.verify_password(password, secret_data, hash_iterations, algorithm, salt)
                    .await
            }
        }
    }
}
