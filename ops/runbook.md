# Operational Runbook

## Safe Scan Procedure

### Pre-Scan Checklist
1. [ ] Verify scope authorization (JIRA ticket or signed approval)
2. [ ] Confirm targets are in authorized CIDR ranges
3. [ ] Check kill switch is not active
4. [ ] Verify operator has required permissions

### Running a Scan
```bash
python main.py scan \
  --targets-file targets.csv \
  --user-id $USER_ID \
  --ticket-id VULN-XXXX \
  --scan-type full \
  --validate
```

### Two-Person Approval (for exploit mode)
1. Operator requests approval:
   ```python
   approval_id = safe_mode.request_exploit_approval(
       target="10.0.0.1",
       module="exploit/...",
       operator_id="operator1",
       operator_fingerprint="device-uuid-1",
       ticket_id="VULN-001"
   )
   ```
2. Admin approves (different user, different device):
   ```python
   safe_mode.approve_exploit(
       approval_id=approval_id,
       approver_id="admin1",  # Must differ from operator
       approver_fingerprint="device-uuid-2"  # Must differ
   )
   ```

## Incident Response

### Kill Switch Activation
```python
# Any authenticated user can activate
safe_mode.activate_kill_switch(user_id="responder", reason="Security incident")
```

### Kill Switch Deactivation
```python
# Admin only
safe_mode.deactivate_kill_switch(user_id="admin")
```

## Credential Rotation

### Vault Secret Rotation
```bash
# Rotate Metasploit RPC password
vault kv put scanner/msf-rpc password="$(openssl rand -base64 32)"

# Rotate audit HMAC key
vault kv put scanner/audit-hmac-key value="$(openssl rand -hex 32)"
```

## Audit Chain Verification
```bash
python ops/verify_audit.py
```

## Backup & Restore
```bash
# Backup
pg_dump $DATABASE_URL > backup_$(date +%Y%m%d).sql
gpg --encrypt --recipient admin@example.com backup_*.sql

# Restore
gpg --decrypt backup_*.sql.gpg | psql $DATABASE_URL
```
