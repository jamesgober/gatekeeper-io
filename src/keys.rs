//! The gate's master secret, from key-vault.

use auth_gate::{AuthError, GateKeys};
use key_vault::{KeyHandle, KeyVault};

/// Derive the gate's keys from the master secret held in `vault` under
/// `handle`. The secret is read inside key-vault's scoped callback and
/// never copied out; only the derived keys leave it.
///
/// ```
/// use gatekeeper_io::keys_from_vault;
/// use key_vault::{KeyVaultBuilder, RawKey};
///
/// let vault = KeyVaultBuilder::new().build();
/// let handle = vault.register("gate/master", RawKey::new(vec![7u8; 32]))?;
/// let keys = keys_from_vault(&vault, handle)?;
/// # let _ = keys;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
///
/// [`AuthError::InvalidInput`] if the vault refuses (locked out, unknown
/// handle) or the secret is shorter than 32 bytes.
pub fn keys_from_vault(vault: &KeyVault, handle: KeyHandle) -> Result<GateKeys, AuthError> {
    vault
        .with_key(handle, GateKeys::derive)
        .map_err(|_| AuthError::InvalidInput("vault key"))?
}
