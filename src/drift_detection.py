import json
import sys
from pathlib import Path

# Add src directory to path if needed
sys.path.insert(0, str(Path(__file__).parent))

from drift_rules import (
    is_orphaned,
    is_privilege_escalation,
    is_inactive_privileged,
    is_cross_cloud_mismatch,
    is_mfa_disabled,
    is_role_added
)


def load_json(path):
    """Load JSON file"""
    with open(path, "r") as f:
        return json.load(f)


def build_identity_map(identities):
    """Create a map of user_id to identity for quick lookup"""
    return {identity["user_id"]: identity for identity in identities}


def detect_drift(baseline, current):
    """Detect drift between baseline and current identities"""
    findings = []
    
    baseline_map = build_identity_map(baseline)
    
    for identity in current:
        identity_id = identity["user_id"]
        baseline_identity = baseline_map.get(identity_id)
        
        # Check for orphaned identity
        if is_orphaned(identity_id, baseline_map):
            findings.append(build_finding(identity, "Orphaned Identity", "HIGH"))
        
        # Check for privilege escalation
        if baseline_identity:
            if is_privilege_escalation(identity, baseline_identity):
                findings.append(build_finding(identity, "Privilege Escalation", "CRITICAL"))
            
            if is_role_added(identity, baseline_identity):
                findings.append(build_finding(identity, "New Roles Added", "MEDIUM"))
        
        # Check for inactive privileged accounts
        if is_inactive_privileged(identity):
            findings.append(build_finding(identity, "Inactive Privileged Account", "HIGH"))
        
        # Check for MFA disabled
        if identity.get("is_privileged") and is_mfa_disabled(identity):
            findings.append(build_finding(identity, "MFA Disabled on Privileged Account", "HIGH"))
        
        # Check for cross-cloud mismatch
        if is_cross_cloud_mismatch(identity):
            findings.append(build_finding(identity, "Cross-Cloud Mismatch", "MEDIUM"))
    
    return findings


def build_finding(identity, drift_type, severity):
    """Build a finding object"""
    return {
        "principal_id": identity["user_id"],
        "username": identity.get("username", "N/A"),
        "cloud": identity["platform"],
        "drift_type": drift_type,
        "severity": severity,
        "roles": identity["roles"],
        "is_privileged": identity.get("is_privileged", False),
        "mfa_enabled": identity.get("mfa_enabled", False)
    }


def main():
    """Main execution function"""
    print("=== Multi-Cloud IAM Drift Detection ===\n")
    
    # Load normalized baseline and current data
    print("Loading normalized data...")
    try:
        baseline = load_json("outputs/baseline_normalized.json")
        current = load_json("outputs/current_normalized.json")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("\nPlease run normalize.py first to create normalized data files.")
        sys.exit(1)
    
    print(f"Loaded {len(baseline)} baseline identities")
    print(f"Loaded {len(current)} current identities\n")
    
    # Detect drift
    print("Detecting drift...")
    findings = detect_drift(baseline, current)
    
    # Save findings
    with open("outputs/drift_report.json", "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)
    
    print(f"\nDrift Detection Complete!")
    print(f"Total Findings: {len(findings)}")
    
    # Print summary by severity
    severity_counts = {}
    for finding in findings:
        severity = finding["severity"]
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print("\nFindings by Severity:")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(severity, 0)
        if count > 0:
            print(f"  {severity}: {count}")
    
    print("\nResults saved to outputs/drift_report.json")
    print("Run report.py to generate CSV and summary reports.")


if __name__ == "__main__":
    main()
