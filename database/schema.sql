-- Network Vulnerability Scanner Database Schema
-- PostgreSQL with TLS, role-based users, encrypted backups

-- =====================
-- Core Tables
-- =====================

CREATE TABLE IF NOT EXISTS endpoints (
    id SERIAL PRIMARY KEY,
    ip VARCHAR(45) NOT NULL UNIQUE,
    hostname VARCHAR(255),
    port INTEGER,
    asset_criticality DECIMAL(3,2) DEFAULT 1.0,
    owner VARCHAR(255),
    environment VARCHAR(50) DEFAULT 'production',
    tags TEXT[],
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_scan_at TIMESTAMPTZ
);

CREATE INDEX idx_endpoints_ip ON endpoints(ip);
CREATE INDEX idx_endpoints_environment ON endpoints(environment);

CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(36) NOT NULL UNIQUE,
    user_id VARCHAR(255) NOT NULL,
    ticket_id VARCHAR(255) NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    targets_count INTEGER DEFAULT 0,
    vulnerabilities_count INTEGER DEFAULT 0,
    exploitable_count INTEGER DEFAULT 0,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    duration_seconds DECIMAL(10,2),
    config JSONB,
    error TEXT
);

CREATE INDEX idx_scans_scan_id ON scans(scan_id);
CREATE INDEX idx_scans_user_id ON scans(user_id);
CREATE INDEX idx_scans_status ON scans(status);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(36) NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    target VARCHAR(45) NOT NULL,
    port INTEGER,
    protocol VARCHAR(10),
    service VARCHAR(100),
    version VARCHAR(255),
    cve VARCHAR(20),
    cvss DECIMAL(3,1),
    severity VARCHAR(20) NOT NULL,
    final_score DECIMAL(5,2) NOT NULL,
    exploit_probability DECIMAL(3,2),
    validation_result VARCHAR(50),
    module VARCHAR(255),
    script_name VARCHAR(100),
    script_output TEXT,
    raw_data JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_vulns_scan_id ON vulnerabilities(scan_id);
CREATE INDEX idx_vulns_target ON vulnerabilities(target);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulns_cve ON vulnerabilities(cve);

CREATE TABLE IF NOT EXISTS validations (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(36) REFERENCES scans(scan_id) ON DELETE CASCADE,
    target VARCHAR(45) NOT NULL,
    module VARCHAR(255) NOT NULL,
    result VARCHAR(50) NOT NULL,
    check_mode BOOLEAN DEFAULT TRUE,
    duration_seconds DECIMAL(10,2),
    output TEXT,
    error TEXT,
    user_id VARCHAR(255) NOT NULL,
    approval_id VARCHAR(36),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_validations_scan_id ON validations(scan_id);
CREATE INDEX idx_validations_result ON validations(result);

-- =====================
-- RBAC Tables
-- =====================

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(255) PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    role VARCHAR(50) NOT NULL DEFAULT 'viewer',
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret_vault_path VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);

CREATE INDEX idx_users_role ON users(role);

CREATE TABLE IF NOT EXISTS role_changes (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id),
    old_role VARCHAR(50) NOT NULL,
    new_role VARCHAR(50) NOT NULL,
    changed_by VARCHAR(255) NOT NULL,
    reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================
-- Authorization & Approval Tables
-- =====================

CREATE TABLE IF NOT EXISTS authorized_scopes (
    id SERIAL PRIMARY KEY,
    cidr VARCHAR(43) NOT NULL,
    ticket_id VARCHAR(255) NOT NULL,
    approved_by TEXT[] NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    allow_exploit BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT valid_dates CHECK (valid_from < valid_until)
);

CREATE INDEX idx_scopes_cidr ON authorized_scopes(cidr);
CREATE INDEX idx_scopes_valid ON authorized_scopes(valid_from, valid_until);

CREATE TABLE IF NOT EXISTS exploit_approvals (
    id VARCHAR(36) PRIMARY KEY,
    target VARCHAR(45) NOT NULL,
    module VARCHAR(255) NOT NULL,
    operator_id VARCHAR(255) NOT NULL,
    operator_fingerprint VARCHAR(255) NOT NULL,
    approver_id VARCHAR(255),
    approver_fingerprint VARCHAR(255),
    ticket_id VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    approved_at TIMESTAMPTZ,
    executed_at TIMESTAMPTZ,
    CONSTRAINT different_users CHECK (operator_id != approver_id OR approver_id IS NULL)
);

CREATE INDEX idx_approvals_status ON exploit_approvals(status);
CREATE INDEX idx_approvals_operator ON exploit_approvals(operator_id);

-- =====================
-- Audit Trail (HMAC Chain)
-- =====================

CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    user_id VARCHAR(255) NOT NULL,
    action VARCHAR(100) NOT NULL,
    target VARCHAR(255),
    scope_ticket VARCHAR(255),
    trace_id VARCHAR(36),
    result JSONB,
    prev_hmac VARCHAR(64),
    hmac VARCHAR(64) NOT NULL,
    CONSTRAINT first_record_no_prev CHECK (id = 1 OR prev_hmac IS NOT NULL)
);

CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_user ON audit_log(user_id);
CREATE INDEX idx_audit_action ON audit_log(action);

-- Function to verify audit chain integrity
CREATE OR REPLACE FUNCTION verify_audit_chain()
RETURNS TABLE(id INTEGER, valid BOOLEAN, error TEXT) AS $$
DECLARE
    rec RECORD;
    prev_hmac VARCHAR(64) := NULL;
BEGIN
    FOR rec IN SELECT * FROM audit_log ORDER BY id LOOP
        IF rec.id = 1 THEN
            IF rec.prev_hmac IS NOT NULL THEN
                RETURN QUERY SELECT rec.id, FALSE, 'First record should have NULL prev_hmac';
            END IF;
        ELSE
            IF rec.prev_hmac != prev_hmac THEN
                RETURN QUERY SELECT rec.id, FALSE, 'Chain broken: prev_hmac mismatch';
            END IF;
        END IF;
        prev_hmac := rec.hmac;
        RETURN QUERY SELECT rec.id, TRUE, NULL::TEXT;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- =====================
-- Retention Policy Views
-- =====================

-- Scans older than 90 days (for cleanup job)
CREATE VIEW scans_to_archive AS
SELECT * FROM scans
WHERE completed_at < NOW() - INTERVAL '90 days';

-- Audit logs older than 1 year (for archival)
CREATE VIEW audit_to_archive AS
SELECT * FROM audit_log
WHERE timestamp < NOW() - INTERVAL '1 year';

-- =====================
-- Performance Views
-- =====================

CREATE VIEW scan_summary AS
SELECT
    DATE_TRUNC('day', started_at) AS scan_date,
    COUNT(*) AS total_scans,
    AVG(duration_seconds) AS avg_duration,
    SUM(vulnerabilities_count) AS total_vulns,
    SUM(exploitable_count) AS total_exploitable
FROM scans
WHERE status = 'completed'
GROUP BY DATE_TRUNC('day', started_at)
ORDER BY scan_date DESC;

CREATE VIEW vulnerability_by_severity AS
SELECT
    severity,
    COUNT(*) AS count,
    AVG(final_score) AS avg_score
FROM vulnerabilities
GROUP BY severity
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
    END;

-- =====================
-- Grants (adjust user names as needed)
-- =====================

-- App user (limited privileges)
-- GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO vulnscanner_app;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO vulnscanner_app;

-- Migration user (full privileges)
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO vulnscanner_migrate;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO vulnscanner_migrate;

-- Read-only user (for dashboards)
-- GRANT SELECT ON ALL TABLES IN SCHEMA public TO vulnscanner_readonly;
