use uuid::Uuid;

use crate::domain::{
    authentication::value_objects::Identity,
    common::entities::app_errors::CoreError,
    realm::entities::Realm,
    role::entities::Role,
    user::{
        entities::{
            AssignRoleInput, BulkDeleteUsersInput, CreateUserInput, GetUserInput, RequiredAction,
            RequiredActionError, ResetPasswordInput, UnassignRoleInput, UpdateUserInput, User,
        },
        value_objects::{CreateUserRequest, UpdateUserRequest},
    },
};

pub trait UserService: Send + Sync {
    fn delete_user(
        &self,
        identity: Identity,
        realm_name: String,
        user_id: Uuid,
    ) -> impl Future<Output = Result<u64, CoreError>> + Send;

    fn update_user(
        &self,
        identity: Identity,
        input: UpdateUserInput,
    ) -> impl Future<Output = Result<User, CoreError>> + Send;
    fn reset_password(
        &self,
        identity: Identity,
        input: ResetPasswordInput,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;
    fn get_users(
        &self,
        identity: Identity,
        realm_name: String,
    ) -> impl Future<Output = Result<Vec<User>, CoreError>> + Send;
    fn assign_role(
        &self,
        identity: Identity,
        input: AssignRoleInput,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;
    fn bulk_delete_users(
        &self,
        identity: Identity,
        input: BulkDeleteUsersInput,
    ) -> impl Future<Output = Result<u64, CoreError>> + Send;
    fn create_user(
        &self,
        identity: Identity,
        input: CreateUserInput,
    ) -> impl Future<Output = Result<User, CoreError>> + Send;
    fn get_user(
        &self,
        identity: Identity,
        input: GetUserInput,
    ) -> impl Future<Output = Result<User, CoreError>> + Send;
    fn unassign_role(
        &self,
        identity: Identity,
        input: UnassignRoleInput,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;
}

#[cfg_attr(test, mockall::automock)]
pub trait UserRepository: Send + Sync {
    fn create_user(
        &self,
        dto: CreateUserRequest,
    ) -> impl Future<Output = Result<User, CoreError>> + Send;

    fn get_by_username(
        &self,
        username: String,
        realm_id: Uuid,
    ) -> impl Future<Output = Result<User, CoreError>> + Send;

    fn get_by_client_id(
        &self,
        client_id: Uuid,
    ) -> impl Future<Output = Result<User, CoreError>> + Send;

    fn get_by_id(&self, user_id: Uuid) -> impl Future<Output = Result<User, CoreError>> + Send;

    fn find_by_realm_id(
        &self,
        realm_id: Uuid,
    ) -> impl Future<Output = Result<Vec<User>, CoreError>> + Send;

    fn bulk_delete_user(
        &self,
        ids: Vec<Uuid>,
    ) -> impl Future<Output = Result<u64, CoreError>> + Send;

    fn delete_user(&self, user_id: Uuid) -> impl Future<Output = Result<u64, CoreError>> + Send;

    fn update_user(
        &self,
        user_id: Uuid,
        dto: UpdateUserRequest,
    ) -> impl Future<Output = Result<User, CoreError>> + Send;
}

#[cfg_attr(test, mockall::automock)]
pub trait UserRequiredActionRepository: Send + Sync {
    fn add_required_action(
        &self,
        user_id: Uuid,
        action: RequiredAction,
    ) -> impl Future<Output = Result<(), RequiredActionError>> + Send;

    fn remove_required_action(
        &self,
        user_id: Uuid,
        action: RequiredAction,
    ) -> impl Future<Output = Result<(), RequiredActionError>> + Send;

    fn get_required_actions(
        &self,
        user_id: Uuid,
    ) -> impl Future<Output = Result<Vec<RequiredAction>, RequiredActionError>> + Send;

    fn clear_required_actions(
        &self,
        user_id: Uuid,
    ) -> impl Future<Output = Result<u64, RequiredActionError>> + Send;
}

pub trait UserRoleService: Send + Sync {
    fn assign_role(
        &self,
        realm_name: String,
        user_id: Uuid,
        role_id: Uuid,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;

    fn revoke_role(
        &self,
        realm_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;

    fn get_user_roles(
        &self,
        user_id: Uuid,
    ) -> impl Future<Output = Result<Vec<Role>, CoreError>> + Send;

    fn has_role(
        &self,
        user_id: Uuid,
        role_id: Uuid,
    ) -> impl Future<Output = Result<bool, CoreError>> + Send;
}

pub trait UserPolicy: Send + Sync {
    fn can_create_user(
        &self,
        identity: Identity,
        target_realm: Realm,
    ) -> impl Future<Output = Result<bool, CoreError>> + Send;
    fn can_view_user(
        &self,
        identity: Identity,
        target_realm: Realm,
    ) -> impl Future<Output = Result<bool, CoreError>> + Send;
    fn can_update_user(
        &self,
        identity: Identity,
        target_realm: Realm,
    ) -> impl Future<Output = Result<bool, CoreError>> + Send;
    fn can_delete_user(
        &self,
        identity: Identity,
        target_realm: Realm,
    ) -> impl Future<Output = Result<bool, CoreError>> + Send;
}

#[cfg_attr(test, mockall::automock)]
pub trait UserRoleRepository: Send + Sync {
    fn assign_role(
        &self,
        user_id: Uuid,
        role_id: Uuid,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;
    fn revoke_role(
        &self,
        user_id: Uuid,
        role_id: Uuid,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;
    fn get_user_roles(
        &self,
        user_id: Uuid,
    ) -> impl Future<Output = Result<Vec<Role>, CoreError>> + Send;
    fn has_role(
        &self,
        user_id: Uuid,
        role_id: Uuid,
    ) -> impl Future<Output = Result<bool, CoreError>> + Send;
}
