from datetime import datetime, timedelta

INACTIVITY_THRESHOLD_DAYS = 90


def is_orphaned(identity_id, baseline_map):
    """Check if identity exists in baseline"""
    return identity_id not in baseline_map


def is_privilege_escalation(current, baseline):
    """Check if user gained privileged access"""
    return not baseline["is_privileged"] and current["is_privileged"]


def is_inactive_privileged(identity):
    """Check if privileged account is inactive"""
    if not identity["is_privileged"]:
        return False
    
    last_active = identity.get("last_activity")
    if not last_active:
        return True  # No activity recorded
    
    try:
        last_active_date = datetime.fromisoformat(last_active)
        threshold = datetime.utcnow() - timedelta(days=INACTIVITY_THRESHOLD_DAYS)
        return last_active_date < threshold
    except (ValueError, TypeError):
        return True  # Invalid date = treat as inactive


def is_cross_cloud_mismatch(identity):
    """Check for cross-cloud role inconsistencies"""
    # Example: Azure Global Administrator without corresponding AWS admin role
    if identity["platform"] == "azure":
        has_global_admin = "Global Administrator" in identity["roles"]
        cross_cloud_roles = identity.get("cross_cloud_roles", [])
        has_cross_admin = any("Admin" in r for r in cross_cloud_roles)
        return has_global_admin and not has_cross_admin
    return False


def is_mfa_disabled(identity):
    """Check if MFA is disabled for the account"""
    return not identity.get("mfa_enabled", False)


def is_role_added(current, baseline):
    """Check if new roles were added"""
    if not baseline:
        return False
    
    baseline_roles = set(baseline.get("roles", []))
    current_roles = set(current.get("roles", []))
    
    return len(current_roles - baseline_roles) > 0
