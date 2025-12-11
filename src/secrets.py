"""
Secrets Management - Vault Integration

Fetches secrets from HashiCorp Vault using AppRole or OIDC authentication.
NEVER stores secrets in code, environment variables (except Vault auth), or Docker images.
"""

import os
from functools import lru_cache
from typing import Any

import hvac
from hvac.exceptions import VaultError

from src.logger import get_logger

logger = get_logger(__name__)


class SecretsError(Exception):
    """Raised when secret retrieval fails."""
    pass


class SecretsManager:
    """
    Secure secrets management via HashiCorp Vault.
    
    Supports:
    - AppRole auth (for services)
    - OIDC auth (for CI/CD)
    - Short-lived credentials with automatic rotation
    """
    
    def __init__(self):
        self._client: hvac.Client | None = None
        self._vault_addr = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
    
    def _get_client(self) -> hvac.Client:
        """Get authenticated Vault client. Fails fast if not authenticated."""
        if self._client is not None and self._client.is_authenticated():
            return self._client
        
        self._client = hvac.Client(url=self._vault_addr)
        
        # Try AppRole first (service auth)
        role_id = os.environ.get("VAULT_ROLE_ID")
        secret_id = os.environ.get("VAULT_SECRET_ID")
        
        if role_id and secret_id:
            try:
                self._client.auth.approle.login(
                    role_id=role_id,
                    secret_id=secret_id  # Should be ephemeral
                )
                logger.info("vault_auth_success", method="approle")
            except VaultError as e:
                logger.error("vault_auth_failed", method="approle", error=str(e))
                raise SecretsError(f"Vault AppRole auth failed: {e}")
        
        # Fallback to token (for dev)
        elif token := os.environ.get("VAULT_TOKEN"):
            self._client.token = token
            logger.warning("vault_auth_token", msg="Using static token - not for production")
        
        else:
            raise SecretsError(
                "No Vault credentials. Set VAULT_ROLE_ID+VAULT_SECRET_ID or VAULT_TOKEN"
            )
        
        # Verify authentication
        if not self._client.is_authenticated():
            raise SecretsError("Vault client not authenticated after login attempt")
        
        return self._client
    
    def get_secret(self, path: str, key: str | None = None) -> dict[str, Any] | str:
        """
        Retrieve secret from Vault KV v2 store.
        
        Args:
            path: Secret path (e.g., "scanner/msf-rpc")
            key: Optional specific key to return (returns full dict if None)
        
        Returns:
            Secret data dict or specific key value
        
        Raises:
            SecretsError: If retrieval fails
        """
        try:
            client = self._get_client()
            response = client.secrets.kv.v2.read_secret_version(path=path)
            data = response["data"]["data"]
            
            if key:
                if key not in data:
                    raise SecretsError(f"Key '{key}' not found in secret '{path}'")
                return data[key]
            
            return data
            
        except VaultError as e:
            logger.error("vault_secret_read_failed", path=path, error=str(e))
            raise SecretsError(f"Failed to read secret '{path}': {e}")
    
    def get_database_url(self) -> str:
        """Get PostgreSQL connection URL from Vault."""
        creds = self.get_secret("scanner/postgres")
        assert isinstance(creds, dict)  # Type narrowing for mypy
        return (
            f"postgresql://{creds['username']}:{creds['password']}"
            f"@{creds['host']}:{creds['port']}/{creds['database']}"
            f"?sslmode={creds.get('ssl_mode', 'verify-full')}"
        )
    
    def get_msf_credentials(self) -> dict[str, str]:
        """Get Metasploit RPC credentials from Vault."""
        result = self.get_secret("scanner/msf-rpc")
        assert isinstance(result, dict)  # Type narrowing for mypy
        return result  # type: ignore[return-value]
    
    def get_hmac_key(self) -> bytes:
        """Get HMAC key for audit chain from Vault."""
        key = self.get_secret("scanner/audit-hmac-key", key="value")
        if isinstance(key, str):
            return key.encode()
        if isinstance(key, bytes):
            return key
        raise SecretsError("HMAC key must be str or bytes")


@lru_cache(maxsize=1)
def get_secrets_manager() -> SecretsManager:
    """Get singleton SecretsManager instance."""
    return SecretsManager()
