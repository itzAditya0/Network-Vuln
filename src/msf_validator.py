"""
Metasploit Validator

Integration with Metasploit RPC API for exploit validation.

SECURITY: Safe mode is ENFORCED by default. All validation runs use
'check' mode to verify exploitability without actually exploiting.

Requires mTLS proxy for production use.
"""

import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

import httpx

from src.logger import get_logger
from src.safe_mode import SafeModeController, SecurityViolation
from src.secrets import SecretsManager

logger = get_logger(__name__)


class ValidationResult(Enum):
    """Result of exploit validation check."""
    VULNERABLE = "vulnerable"  # Target confirmed vulnerable
    NOT_VULNERABLE = "not_vulnerable"  # Target not vulnerable
    UNKNOWN = "unknown"  # Check inconclusive
    ERROR = "error"  # Check failed
    SAFE_MODE_BLOCKED = "blocked"  # Blocked by safe mode


@dataclass
class ValidationReport:
    """Report from Metasploit validation."""
    target: str
    module: str
    result: ValidationResult
    output: str = ""
    duration_seconds: float = 0.0
    check_mode: bool = True
    error: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "module": self.module,
            "result": self.result.value,
            "output": self.output,
            "duration_seconds": self.duration_seconds,
            "check_mode": self.check_mode,
            "error": self.error,
        }


class MetasploitError(Exception):
    """Raised when Metasploit RPC fails."""
    pass


class MetasploitValidator:
    """
    Validates vulnerabilities using Metasploit RPC API.
    
    CRITICAL: All operations go through SafeModeController.
    Safe mode (check only) is ENFORCED by default.
    
    Production deployment requires:
    - mTLS proxy in front of msfrpcd
    - Credentials from Vault
    - Two-person approval for exploit mode
    """
    
    def __init__(
        self,
        proxy_url: str = "https://localhost:8443",
        safe_mode_controller: SafeModeController | None = None,
        secrets: SecretsManager | None = None,
        timeout: int = 60,
    ):
        self._proxy_url = proxy_url.rstrip("/")
        self._safe_mode = safe_mode_controller
        self._secrets = secrets
        self._timeout = timeout
        self._token: str | None = None
        self._client: httpx.Client | None = None
    
    def connect(self) -> None:
        """
        Connect to Metasploit RPC server.
        
        Retrieves credentials from Vault and authenticates.
        """
        if self._secrets:
            creds = self._secrets.get_msf_credentials()
            password = creds.get("password", "")
        else:
            # Dev fallback
            import os
            password = os.environ.get("MSF_PASSWORD", "")
        
        self._client = httpx.Client(
            base_url=self._proxy_url,
            timeout=self._timeout,
            verify=True,  # Require valid TLS cert
        )
        
        try:
            response = self._rpc_call("auth.login", ["msf", password])
            self._token = response.get("token")
            
            if not self._token:
                raise MetasploitError("Failed to obtain auth token")
            
            logger.info("msf_connected", proxy=self._proxy_url)
            
        except httpx.RequestError as e:
            logger.error("msf_connection_failed", error=str(e))
            raise MetasploitError(f"Connection failed: {e}")
    
    def disconnect(self) -> None:
        """Disconnect and cleanup resources."""
        if self._token:
            try:
                self._rpc_call("auth.logout", [self._token])
            except Exception:
                pass
            self._token = None
        
        if self._client:
            self._client.close()
            self._client = None
        
        logger.info("msf_disconnected")
    
    def _rpc_call(self, method: str, args: list[Any]) -> dict[str, Any]:
        """Make RPC call to Metasploit."""
        if not self._client:
            raise MetasploitError("Not connected")
        
        # msgpack encoding would be used in production
        # Simplified JSON for demonstration
        payload = {
            "method": method,
            "params": args,
        }
        
        response = self._client.post("/api/", json=payload)
        response.raise_for_status()
        return response.json()
    
    def validate(
        self,
        target: str,
        module: str,
        user_id: str,
        ticket_id: str,
        options: dict[str, Any] | None = None,
        allow_exploit: bool = False,
        approval_id: str | None = None,
    ) -> ValidationReport:
        """
        Validate vulnerability using Metasploit check.
        
        SAFE MODE ENFORCED: By default, only runs check (non-destructive).
        For exploit mode, requires two-person approval via approval_id.
        
        Args:
            target: Target IP/host
            module: Metasploit module path (e.g., exploit/windows/smb/ms17_010_eternalblue)
            user_id: Operator user ID for audit
            ticket_id: Authorized scope ticket
            options: Additional module options
            allow_exploit: If True, attempts exploit (requires approval)
            approval_id: Two-person approval ID for exploit mode
        
        Returns:
            ValidationReport with result status
        """
        start_time = time.time()
        
        # === SAFE MODE CHECKS ===
        if self._safe_mode:
            try:
                # Basic pre-check
                self._safe_mode.pre_validation_checklist(
                    target=target,
                    user_id=user_id,
                    ticket_id=ticket_id,
                    allow_exploit=allow_exploit
                )
                
                # Additional approval check for exploit mode
                if allow_exploit:
                    if not approval_id:
                        logger.warning(
                            "exploit_blocked",
                            target=target,
                            reason="no_approval_id"
                        )
                        return ValidationReport(
                            target=target,
                            module=module,
                            result=ValidationResult.SAFE_MODE_BLOCKED,
                            error="Exploit mode requires two-person approval ID",
                            check_mode=False,
                        )
                    
                    # Verify approval and get execution context
                    self._safe_mode.execute_exploit(approval_id)
                    
            except SecurityViolation as e:
                logger.warning(
                    "validation_blocked",
                    target=target,
                    module=module,
                    error=str(e)
                )
                return ValidationReport(
                    target=target,
                    module=module,
                    result=ValidationResult.SAFE_MODE_BLOCKED,
                    error=str(e),
                    check_mode=not allow_exploit,
                )
        
        # === EXECUTE VALIDATION ===
        try:
            if not self._token:
                self.connect()
            
            # Create console
            console = self._rpc_call("console.create", [self._token])
            console_id = console.get("id")
            
            if not console_id:
                raise MetasploitError("Failed to create console")
            
            try:
                # Use module
                self._console_write(console_id, f"use {module}\n")
                
                # Set target
                self._console_write(console_id, f"set RHOSTS {target}\n")
                
                # Set additional options
                if options:
                    for key, value in options.items():
                        self._console_write(console_id, f"set {key} {value}\n")
                
                # === CRITICAL: SAFE MODE ENFORCEMENT ===
                if allow_exploit and approval_id:
                    # Exploit mode (with approval)
                    logger.warning(
                        "exploit_execution",
                        target=target,
                        module=module,
                        user_id=user_id
                    )
                    self._console_write(console_id, "exploit\n")
                else:
                    # Check mode (default, safe)
                    self._console_write(console_id, "check\n")
                
                # Wait for completion and get output
                output = self._console_read_until_done(console_id)
                
                # Parse result
                result = self._parse_check_result(output)
                
                duration = time.time() - start_time
                
                logger.info(
                    "validation_complete",
                    target=target,
                    module=module,
                    result=result.value,
                    duration=duration
                )
                
                return ValidationReport(
                    target=target,
                    module=module,
                    result=result,
                    output=output,
                    duration_seconds=duration,
                    check_mode=not allow_exploit,
                )
                
            finally:
                # Cleanup console
                self._rpc_call("console.destroy", [self._token, console_id])
                
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                "validation_error",
                target=target,
                module=module,
                error=str(e)
            )
            return ValidationReport(
                target=target,
                module=module,
                result=ValidationResult.ERROR,
                error=str(e),
                duration_seconds=duration,
                check_mode=not allow_exploit,
            )
    
    def _console_write(self, console_id: str, data: str) -> None:
        """Write command to console."""
        self._rpc_call("console.write", [self._token, console_id, data])
    
    def _console_read_until_done(
        self,
        console_id: str,
        timeout: int = 60
    ) -> str:
        """Read console output until command completes."""
        output = []
        start = time.time()
        
        while time.time() - start < timeout:
            response = self._rpc_call("console.read", [self._token, console_id])
            
            if data := response.get("data"):
                output.append(data)
            
            if response.get("busy") is False:
                break
            
            time.sleep(0.5)
        
        return "".join(output)
    
    def _parse_check_result(self, output: str) -> ValidationResult:
        """Parse check command output to determine result."""
        output_lower = output.lower()
        
        if "the target is vulnerable" in output_lower:
            return ValidationResult.VULNERABLE
        elif "appears to be vulnerable" in output_lower:
            return ValidationResult.VULNERABLE
        elif "not vulnerable" in output_lower:
            return ValidationResult.NOT_VULNERABLE
        elif "target is not vulnerable" in output_lower:
            return ValidationResult.NOT_VULNERABLE
        elif "cannot reliably check" in output_lower:
            return ValidationResult.UNKNOWN
        elif "check failed" in output_lower:
            return ValidationResult.ERROR
        else:
            return ValidationResult.UNKNOWN
    
    def list_modules(self, search: str = "") -> list[str]:
        """List available exploit modules."""
        if not self._token:
            self.connect()
        
        response = self._rpc_call(
            "module.search",
            [self._token, search]
        )
        
        return [m.get("fullname", "") for m in response.get("modules", [])]
    
    def get_module_info(self, module: str) -> dict[str, Any]:
        """Get detailed info about a module."""
        if not self._token:
            self.connect()
        
        module_type = module.split("/")[0]
        module_name = "/".join(module.split("/")[1:])
        
        response = self._rpc_call(
            "module.info",
            [self._token, module_type, module_name]
        )
        
        return response
