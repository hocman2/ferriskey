use crate::domain::{
    authentication::{ports::AuthSessionRepository, value_objects::Identity},
    client::{
        entities::{
            Client, CreateClientInput, CreateRedirectUriInput, CreateRoleInput, DeleteClientInput,
            DeleteRedirectUriInput, GetClientInput, GetClientRolesInput, GetClientsInput,
            GetRedirectUrisInput, UpdateClientInput, UpdateRedirectUriInput,
            redirect_uri::RedirectUri,
        },
        ports::{ClientPolicy, ClientRepository, ClientService, RedirectUriRepository},
        value_objects::CreateClientRequest,
    },
    common::{
        entities::app_errors::CoreError, generate_random_string, policies::ensure_policy,
        services::Service,
    },
    credential::ports::CredentialRepository,
    crypto::ports::HasherRepository,
    health::ports::HealthCheckRepository,
    jwt::ports::{KeyStoreRepository, RefreshTokenRepository},
    realm::ports::RealmRepository,
    role::{
        entities::Role,
        ports::{RolePolicy, RoleRepository},
        value_objects::CreateRoleRequest,
    },
    trident::ports::RecoveryCodeRepository,
    user::ports::{UserRepository, UserRequiredActionRepository, UserRoleRepository},
    webhook::{
        entities::{webhook_payload::WebhookPayload, webhook_trigger::WebhookTrigger},
        ports::WebhookRepository,
    },
};

impl<R, C, U, CR, H, AS, RU, RO, KS, UR, URA, HC, W, RT, RC> ClientService
    for Service<R, C, U, CR, H, AS, RU, RO, KS, UR, URA, HC, W, RT, RC>
where
    R: RealmRepository,
    C: ClientRepository,
    U: UserRepository,
    CR: CredentialRepository,
    H: HasherRepository,
    AS: AuthSessionRepository,
    RU: RedirectUriRepository,
    RO: RoleRepository,
    KS: KeyStoreRepository,
    UR: UserRoleRepository,
    URA: UserRequiredActionRepository,
    HC: HealthCheckRepository,
    W: WebhookRepository,
    RT: RefreshTokenRepository,
    RC: RecoveryCodeRepository,
{
    async fn create_client(
        &self,
        identity: Identity,
        input: CreateClientInput,
    ) -> Result<Client, CoreError> {
        let realm = self
            .realm_repository
            .get_by_name(input.realm_name)
            .await
            .map_err(|_| CoreError::InvalidRealm)?
            .ok_or(CoreError::InvalidRealm)?;

        let realm_id = realm.id;

        ensure_policy(
            self.policy.can_create_client(identity, realm).await,
            "insufficient permissions",
        )?;

        let secret = (!input.public_client).then(generate_random_string);

        let client = self
            .client_repository
            .create_client(CreateClientRequest {
                realm_id,
                name: input.name,
                client_id: input.client_id,
                secret,
                enabled: input.enabled,
                protocol: input.protocol,
                public_client: input.public_client,
                service_account_enabled: input.service_account_enabled,
                direct_access_grants_enabled: input.direct_access_grants_enabled,
                client_type: input.client_type,
            })
            .await
            .map_err(|_| CoreError::CreateClientError)?;

        self.webhook_repository
            .notify(
                realm_id,
                WebhookPayload::new(
                    WebhookTrigger::ClientCreated,
                    realm_id,
                    Some(client.clone()),
                ),
            )
            .await?;

        Ok(client)
    }

    async fn create_redirect_uri(
        &self,
        identity: Identity,
        input: CreateRedirectUriInput,
    ) -> Result<RedirectUri, CoreError> {
        let realm = self
            .realm_repository
            .get_by_name(input.realm_name)
            .await
            .map_err(|_| CoreError::InvalidRealm)?
            .ok_or(CoreError::InvalidRealm)?;

        let realm_id = realm.id;
        ensure_policy(
            self.policy.can_create_client(identity, realm).await,
            "insufficient permissions",
        )?;

        let redirect_uri = self
            .redirect_uri_repository
            .create_redirect_uri(input.client_id, input.payload.value, input.payload.enabled)
            .await
            .map_err(|_| CoreError::InvalidRedirectUri)?;

        self.webhook_repository
            .notify(
                realm_id,
                WebhookPayload::new(
                    WebhookTrigger::RedirectUriCreated,
                    realm_id,
                    Some(redirect_uri.clone()),
                ),
            )
            .await?;

        Ok(redirect_uri)
    }

    async fn create_role(
        &self,
        identity: Identity,
        input: CreateRoleInput,
    ) -> Result<Role, CoreError> {
        let realm = self
            .realm_repository
            .get_by_name(input.realm_name)
            .await
            .map_err(|_| CoreError::InvalidRealm)?
            .ok_or(CoreError::InvalidRealm)?;

        let realm_id = realm.id;
        ensure_policy(
            self.policy.can_create_role(identity, realm).await,
            "insufficient permissions",
        )?;

        let role = self
            .role_repository
            .create(CreateRoleRequest {
                client_id: Some(input.client_id),
                description: input.description,
                name: input.name,
                permissions: input.permissions,
                realm_id,
            })
            .await
            .map_err(|_| CoreError::InternalServerError)?;

        self.webhook_repository
            .notify(
                realm_id,
                WebhookPayload::new(WebhookTrigger::RoleCreated, realm_id, Some(role.clone())),
            )
            .await?;

        Ok(role)
    }

    async fn delete_client(
        &self,
        identity: Identity,
        input: DeleteClientInput,
    ) -> Result<(), CoreError> {
        let realm = self
            .realm_repository
            .get_by_name(input.realm_name)
            .await
            .map_err(|_| CoreError::InvalidRealm)?
            .ok_or(CoreError::InvalidRealm)?;

        let realm_id = realm.id;

        ensure_policy(
            self.policy.can_delete_client(identity, realm).await,
            "insufficient permissions",
        )?;

        self.client_repository
            .delete_by_id(input.client_id)
            .await
            .map_err(|_| CoreError::InternalServerError)?;

        self.webhook_repository
            .notify(
                realm_id,
                WebhookPayload::new(
                    WebhookTrigger::ClientDeleted,
                    realm_id,
                    Some(input.client_id),
                ),
            )
            .await?;

        Ok(())
    }

    async fn delete_redirect_uri(
        &self,
        identity: Identity,
        input: DeleteRedirectUriInput,
    ) -> Result<(), CoreError> {
        let realm = self
            .realm_repository
            .get_by_name(input.realm_name)
            .await
            .map_err(|_| CoreError::InvalidRealm)?
            .ok_or(CoreError::InvalidRealm)?;

        let realm_id = realm.id;
        ensure_policy(
            self.policy.can_update_client(identity, realm).await,
            "insufficient permissions",
        )?;

        self.redirect_uri_repository
            .delete(input.uri_id)
            .await
            .map_err(|_| CoreError::RedirectUriNotFound)?;

        self.webhook_repository
            .notify(
                realm_id,
                WebhookPayload::new(
                    WebhookTrigger::RedirectUriDeleted,
                    realm_id,
                    Some(input.uri_id),
                ),
            )
            .await?;

        Ok(())
    }

    async fn get_client_by_id(
        &self,
        identity: Identity,
        input: GetClientInput,
    ) -> Result<Client, CoreError> {
        let realm = self
            .realm_repository
            .get_by_name(input.realm_name)
            .await
            .map_err(|_| CoreError::InvalidRealm)?
            .ok_or(CoreError::InvalidRealm)?;

        ensure_policy(
            self.policy.can_view_client(identity, realm).await,
            "insufficient permissions",
        )?;

        self.client_repository
            .get_by_id(input.client_id)
            .await
            .map_err(|_| CoreError::InvalidClient)
    }

    async fn get_client_roles(
        &self,
        identity: Identity,
        input: GetClientRolesInput,
    ) -> Result<Vec<Role>, CoreError> {
        let realm = self
            .realm_repository
            .get_by_name(input.realm_name)
            .await
            .map_err(|_| CoreError::InvalidRealm)?
            .ok_or(CoreError::InvalidRealm)?;

        ensure_policy(
            self.policy.can_view_client(identity, realm).await,
            "insufficient permissions",
        )?;

        self.role_repository
            .get_by_client_id(input.client_id)
            .await
            .map_err(|_| CoreError::NotFound)
    }

    async fn get_clients(
        &self,
        identity: Identity,
        input: GetClientsInput,
    ) -> Result<Vec<Client>, CoreError> {
        let realm = self
            .realm_repository
            .get_by_name(input.realm_name)
            .await
            .map_err(|_| CoreError::InvalidRealm)?
            .ok_or(CoreError::InvalidRealm)?;

        let realm_id = realm.id;
        ensure_policy(
            self.policy.can_view_client(identity, realm).await,
            "insufficient permissions",
        )?;

        self.client_repository
            .get_by_realm_id(realm_id)
            .await
            .map_err(|_| CoreError::NotFound)
    }

    async fn get_redirect_uris(
        &self,
        identity: Identity,
        input: GetRedirectUrisInput,
    ) -> Result<Vec<RedirectUri>, CoreError> {
        let realm = self
            .realm_repository
            .get_by_name(input.realm_name)
            .await
            .map_err(|_| CoreError::InvalidRealm)?
            .ok_or(CoreError::InvalidRealm)?;

        ensure_policy(
            self.policy.can_view_client(identity, realm).await,
            "insufficient permissions",
        )?;

        self.redirect_uri_repository
            .get_by_client_id(input.client_id)
            .await
            .map_err(|_| CoreError::NotFound)
    }

    async fn update_client(
        &self,
        identity: Identity,
        input: UpdateClientInput,
    ) -> Result<Client, CoreError> {
        let realm = self
            .realm_repository
            .get_by_name(input.realm_name)
            .await
            .map_err(|_| CoreError::InvalidRealm)?
            .ok_or(CoreError::InvalidRealm)?;

        let realm_id = realm.id;
        ensure_policy(
            self.policy.can_update_client(identity, realm).await,
            "insufficient permissions",
        )?;

        let client = self
            .client_repository
            .update_client(input.client_id, input.payload)
            .await
            .map_err(|_| CoreError::NotFound)?;

        self.webhook_repository
            .notify(
                realm_id,
                WebhookPayload::new(
                    WebhookTrigger::ClientUpdated,
                    realm_id,
                    Some(client.clone()),
                ),
            )
            .await?;

        Ok(client)
    }

    async fn update_redirect_uri(
        &self,
        identity: Identity,
        input: UpdateRedirectUriInput,
    ) -> Result<RedirectUri, CoreError> {
        let realm = self
            .realm_repository
            .get_by_name(input.realm_name)
            .await
            .map_err(|_| CoreError::InvalidRealm)?
            .ok_or(CoreError::InvalidRealm)?;

        let realm_id = realm.id;
        ensure_policy(
            self.policy.can_update_client(identity, realm).await,
            "insufficient permissions",
        )?;

        let redirect_uri = self
            .redirect_uri_repository
            .update_enabled(input.redirect_uri_id, input.enabled)
            .await
            .map_err(|_| CoreError::NotFound)?;

        self.webhook_repository
            .notify(
                realm_id,
                WebhookPayload::new(
                    WebhookTrigger::RedirectUriUpdated,
                    realm_id,
                    Some(redirect_uri.clone()),
                ),
            )
            .await?;

        Ok(redirect_uri)
    }
}
