import json
from typing import List, Dict
from datetime import datetime, timedelta


def normalize_azure_users(azure_users: List[Dict]) -> List[Dict]:
    """Normalize Azure users to common format"""
    normalized = []
    
    for user in azure_users:
        # Calculate last_activity date from last_login_days
        last_login_days = user.get("last_login_days")
        last_activity = None
        if last_login_days is not None:
            last_activity = (datetime.utcnow() - timedelta(days=last_login_days)).isoformat()
        
        normalized.append({
            "platform": "azure",
            "user_id": user.get("principal_id"),
            "username": user.get("upn"),
            "email": user.get("upn"),  # UPN typically is the email
            "account_type": "human",  # Can be enhanced with more logic
            "is_active": last_login_days is not None and last_login_days < 90,
            "is_privileged": user.get("privileged", False),
            "roles": user.get("roles", []),
            "last_activity": last_activity,
            "mfa_enabled": user.get("mfa_enabled", False),
            "source": "Azure AD"
        })
    
    return normalized


def normalize_aws_users(aws_users: List[Dict]) -> List[Dict]:
    """Normalize AWS users to common format"""
    normalized = []
    
    for user in aws_users:
        roles = user.get("attached_policies", [])
        
        # Calculate last_activity date from password_last_used_days
        password_last_used_days = user.get("password_last_used_days")
        last_activity = None
        if password_last_used_days is not None:
            last_activity = (datetime.utcnow() - timedelta(days=password_last_used_days)).isoformat()
        
        normalized.append({
            "platform": "aws",
            "user_id": user.get("arn"),
            "username": user.get("user_name"),
            "email": None,  # Not available in this format
            "account_type": "service" if user.get("user_name", "").startswith("svc_") else "human",
            "is_active": password_last_used_days is not None and password_last_used_days < 90,
            "is_privileged": user.get("is_admin", False),
            "roles": roles,
            "last_activity": last_activity,
            "mfa_enabled": user.get("mfa_enabled", False),
            "source": "AWS IAM"
        })
    
    return normalized


def load_json(path: str) -> List[Dict]:
    """Load JSON file"""
    with open(path, "r") as f:
        return json.load(f)


def normalize_identities(identities: List[Dict]) -> List[Dict]:
    """Helper function to normalize a mixed list of identities"""
    # This function can be enhanced to auto-detect platform
    return identities


def main():
    """Normalize both baseline and current identities"""
    print("=== Normalizing Baseline Identities ===")
    azure_baseline = load_json("data/baseline/azure_identities.json")
    aws_baseline = load_json("data/baseline/aws_identities.json")
    
    baseline_normalized = []
    baseline_normalized.extend(normalize_azure_users(azure_baseline))
    baseline_normalized.extend(normalize_aws_users(aws_baseline))
    
    with open("outputs/baseline_normalized.json", "w", encoding="utf-8") as f:
        json.dump(baseline_normalized, f, indent=2)
    
    print(f"Normalized {len(baseline_normalized)} baseline identities.")
    
    print("\n=== Normalizing Current Identities ===")
    azure_current = load_json("data/current/azure_identities.json")
    aws_current = load_json("data/current/aws_identities.json")
    
    current_normalized = []
    current_normalized.extend(normalize_azure_users(azure_current))
    current_normalized.extend(normalize_aws_users(aws_current))
    
    with open("outputs/current_normalized.json", "w", encoding="utf-8") as f:
        json.dump(current_normalized, f, indent=2)
    
    print(f"Normalized {len(current_normalized)} current identities.")
    print("\nNormalization complete!")


if __name__ == "__main__":
    main()
