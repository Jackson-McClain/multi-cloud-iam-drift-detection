import json
import csv
from pathlib import Path


def load_findings():
    """Load findings from drift detection"""
    findings_path = Path("outputs/drift_report.json")
    
    if not findings_path.exists():
        print("No findings file found. Please run drift_detection.py first.")
        return []
    
    with open(findings_path, "r") as f:
        return json.load(f)


def export_csv(findings):
    """Export findings to CSV"""
    if not findings:
        print("No findings to export.")
        return
    
    csv_path = Path("outputs/drift_report.csv")
    
    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["principal_id", "username", "cloud", "drift_type", "severity", 
                      "is_privileged", "mfa_enabled", "roles"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for finding in findings:
            # Convert roles list to string for CSV
            row = finding.copy()
            row["roles"] = ", ".join(row["roles"]) if row["roles"] else "None"
            writer.writerow(row)
    
    print(f"CSV report saved to {csv_path}")


def generate_summary(findings):
    """Generate markdown summary report"""
    summary = {
        "total": len(findings),
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in findings if f["severity"] == "LOW"),
    }
    
    # Group findings by type
    findings_by_type = {}
    for finding in findings:
        drift_type = finding["drift_type"]
        if drift_type not in findings_by_type:
            findings_by_type[drift_type] = []
        findings_by_type[drift_type].append(finding)
    
    # Group findings by cloud
    findings_by_cloud = {}
    for finding in findings:
        cloud = finding["cloud"]
        if cloud not in findings_by_cloud:
            findings_by_cloud[cloud] = []
        findings_by_cloud[cloud].append(finding)
    
    summary_path = Path("outputs/summary.md")
    
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("# Multi-Cloud IAM Drift Detection Report\n\n")
        f.write("## Executive Summary\n\n")
        f.write(f"**Total Findings:** {summary['total']}\n\n")
        
        f.write("### Findings by Severity\n\n")
        if summary['critical'] > 0:
            f.write(f"- **CRITICAL:** {summary['critical']}\n")
        if summary['high'] > 0:
            f.write(f"- **HIGH:** {summary['high']}\n")
        if summary['medium'] > 0:
            f.write(f"- **MEDIUM:** {summary['medium']}\n")
        if summary['low'] > 0:
            f.write(f"- **LOW:** {summary['low']}\n")
        
        f.write("\n### Findings by Cloud Platform\n\n")
        for cloud, cloud_findings in findings_by_cloud.items():
            f.write(f"- **{cloud.upper()}:** {len(cloud_findings)} findings\n")
        
        f.write("\n## Findings by Type\n\n")
        for drift_type, type_findings in sorted(findings_by_type.items()):
            f.write(f"### {drift_type} ({len(type_findings)})\n\n")
            
            for finding in type_findings[:5]:  # Show first 5 of each type
                f.write(f"- **{finding['username']}** ({finding['cloud']})\n")
                f.write(f"  - Severity: {finding['severity']}\n")
                f.write(f"  - Privileged: {finding['is_privileged']}\n")
                f.write(f"  - MFA: {'Enabled' if finding['mfa_enabled'] else 'Disabled'}\n")
                f.write(f"  - Roles: {', '.join(finding['roles']) if finding['roles'] else 'None'}\n")
            
            if len(type_findings) > 5:
                f.write(f"\n*...and {len(type_findings) - 5} more*\n")
            f.write("\n")
        
        f.write("\n## Recommendations\n\n")
        
        if summary['critical'] > 0 or summary['high'] > 0:
            f.write("### Immediate Actions Required\n\n")
            
            privilege_escalations = [f for f in findings if f['drift_type'] == 'Privilege Escalation']
            if privilege_escalations:
                f.write(f"1. **Review Privilege Escalations:** {len(privilege_escalations)} users gained privileged access\n")
            
            inactive = [f for f in findings if f['drift_type'] == 'Inactive Privileged Account']
            if inactive:
                f.write(f"2. **Disable Inactive Accounts:** {len(inactive)} privileged accounts are inactive\n")
            
            no_mfa = [f for f in findings if f['drift_type'] == 'MFA Disabled on Privileged Account']
            if no_mfa:
                f.write(f"3. **Enable MFA:** {len(no_mfa)} privileged accounts lack MFA\n")
        
        f.write("\n---\n")
        f.write(f"*Report generated: {Path('outputs/drift_report.json').stat().st_mtime}*\n")
    
    print(f"Summary report saved to {summary_path}")
    return summary


def main():
    """Generate all reports"""
    print("=== Generating Drift Reports ===\n")
    
    findings = load_findings()
    
    if not findings:
        print("No findings to report.")
        return
    
    print(f"Processing {len(findings)} findings...\n")
    
    export_csv(findings)
    generate_summary(findings)
    
    print("\n✅ All reports generated successfully!")
    print("\nGenerated files:")
    print("  - outputs/drift_report.csv")
    print("  - outputs/summary.md")


if __name__ == "__main__":
    main()
