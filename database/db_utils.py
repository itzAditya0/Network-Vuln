"""
Database Utilities

PostgreSQL connection management with:
- Connection pooling
- TLS support
- Backup utilities
- Migration helpers
"""

import os
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Generator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import QueuePool

from src.logger import get_logger
from src.secrets import SecretsManager, get_secrets_manager

logger = get_logger(__name__)


class DatabaseManager:
    """
    Manages PostgreSQL database connections.
    
    Features:
    - Connection pooling
    - TLS/SSL connections
    - Automatic reconnection
    - Backup utilities
    """
    
    def __init__(
        self,
        connection_url: str | None = None,
        pool_size: int = 10,
        max_overflow: int = 20,
        ssl_mode: str = "verify-full",
    ):
        self._connection_url = connection_url
        self._pool_size = pool_size
        self._max_overflow = max_overflow
        self._ssl_mode = ssl_mode
        self._engine: Engine | None = None
        self._session_factory: sessionmaker | None = None
    
    def _get_connection_url(self) -> str:
        """Get connection URL from config or Vault."""
        if self._connection_url:
            return self._connection_url
        
        # Try environment variable first (for dev)
        if url := os.environ.get("DATABASE_URL"):
            return url
        
        # Get from Vault
        try:
            secrets = get_secrets_manager()
            return secrets.get_database_url()
        except Exception as e:
            logger.error("database_url_error", error=str(e))
            raise RuntimeError(f"Failed to get database URL: {e}")
    
    def connect(self) -> None:
        """Initialize database connection pool."""
        url = self._get_connection_url()
        
        # Add SSL configuration
        connect_args = {}
        if self._ssl_mode != "disable":
            connect_args["sslmode"] = self._ssl_mode
        
        self._engine = create_engine(
            url,
            poolclass=QueuePool,
            pool_size=self._pool_size,
            max_overflow=self._max_overflow,
            pool_pre_ping=True,  # Verify connections
            connect_args=connect_args,
        )
        
        self._session_factory = sessionmaker(bind=self._engine)
        
        # Test connection
        with self._engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        
        logger.info("database_connected", pool_size=self._pool_size)
    
    def disconnect(self) -> None:
        """Close all connections."""
        if self._engine:
            self._engine.dispose()
            self._engine = None
            self._session_factory = None
        logger.info("database_disconnected")
    
    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        """Get database session with automatic cleanup."""
        if not self._session_factory:
            self.connect()
        
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    
    def execute(self, query: str, params: dict | None = None) -> Any:
        """Execute raw SQL query."""
        with self.session() as session:
            result = session.execute(text(query), params or {})
            return result.fetchall()
    
    # === CRUD Operations ===
    
    def save_scan(self, scan_data: dict[str, Any]) -> int:
        """Save scan record."""
        with self.session() as session:
            result = session.execute(
                text("""
                    INSERT INTO scans (
                        scan_id, user_id, ticket_id, scan_type, status,
                        targets_count, config
                    ) VALUES (
                        :scan_id, :user_id, :ticket_id, :scan_type, :status,
                        :targets_count, :config
                    )
                    RETURNING id
                """),
                scan_data
            )
            return result.scalar()
    
    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        vulnerabilities_count: int = 0,
        exploitable_count: int = 0,
        duration: float = 0,
        error: str | None = None,
    ) -> None:
        """Update scan completion status."""
        with self.session() as session:
            session.execute(
                text("""
                    UPDATE scans SET
                        status = :status,
                        vulnerabilities_count = :vulns,
                        exploitable_count = :exploitable,
                        duration_seconds = :duration,
                        completed_at = :completed_at,
                        error = :error
                    WHERE scan_id = :scan_id
                """),
                {
                    "scan_id": scan_id,
                    "status": status,
                    "vulns": vulnerabilities_count,
                    "exploitable": exploitable_count,
                    "duration": duration,
                    "completed_at": datetime.now(timezone.utc),
                    "error": error,
                }
            )
    
    def save_vulnerability(self, vuln_data: dict[str, Any]) -> int:
        """Save vulnerability record."""
        with self.session() as session:
            result = session.execute(
                text("""
                    INSERT INTO vulnerabilities (
                        scan_id, target, port, protocol, service, version,
                        cve, cvss, severity, final_score, exploit_probability,
                        validation_result, module, raw_data
                    ) VALUES (
                        :scan_id, :target, :port, :protocol, :service, :version,
                        :cve, :cvss, :severity, :final_score, :exploit_probability,
                        :validation_result, :module, :raw_data
                    )
                    RETURNING id
                """),
                vuln_data
            )
            return result.scalar()
    
    def save_audit_record(self, record: dict[str, Any]) -> int:
        """Save audit log record with HMAC."""
        with self.session() as session:
            result = session.execute(
                text("""
                    INSERT INTO audit_log (
                        user_id, action, target, scope_ticket,
                        trace_id, result, prev_hmac, hmac
                    ) VALUES (
                        :user_id, :action, :target, :scope_ticket,
                        :trace_id, :result, :prev_hmac, :hmac
                    )
                    RETURNING id
                """),
                record
            )
            return result.scalar()
    
    def get_last_audit_hmac(self) -> str | None:
        """Get HMAC of last audit record for chain continuation."""
        result = self.execute(
            "SELECT hmac FROM audit_log ORDER BY id DESC LIMIT 1"
        )
        return result[0][0] if result else None
    
    # === Verification ===
    
    def verify_audit_chain(self) -> list[dict[str, Any]]:
        """Verify audit chain integrity using DB function."""
        result = self.execute("SELECT * FROM verify_audit_chain()")
        return [
            {"id": r[0], "valid": r[1], "error": r[2]}
            for r in result
        ]
    
    # === Backup ===
    
    def create_backup(self, output_path: str) -> str:
        """
        Create database backup using pg_dump.
        
        NOTE: In production, use encrypted backups with Vault-stored keys.
        """
        import subprocess
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vulnscanner_backup_{timestamp}.sql"
        full_path = f"{output_path}/{filename}"
        
        # Get connection details (simplified - in production parse URL properly)
        url = self._get_connection_url()
        
        try:
            subprocess.run(
                ["pg_dump", "-f", full_path, url],
                check=True,
                capture_output=True,
            )
            logger.info("backup_created", path=full_path)
            return full_path
        except subprocess.CalledProcessError as e:
            logger.error("backup_failed", error=e.stderr.decode())
            raise
    
    def run_migrations(self) -> None:
        """Run Alembic migrations."""
        import subprocess
        
        try:
            subprocess.run(
                ["alembic", "upgrade", "head"],
                check=True,
                capture_output=True,
            )
            logger.info("migrations_complete")
        except subprocess.CalledProcessError as e:
            logger.error("migrations_failed", error=e.stderr.decode())
            raise


# Singleton
_db_manager: DatabaseManager | None = None


def get_database() -> DatabaseManager:
    """Get singleton DatabaseManager instance."""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager
