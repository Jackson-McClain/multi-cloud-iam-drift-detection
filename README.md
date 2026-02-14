# Multi-Cloud IAM Drift Detection

A Python-based tool for detecting identity and access management (IAM) drift across AWS and Azure cloud environments.

## Overview

This tool helps security teams identify unauthorized changes, privilege escalations, and security risks in cloud IAM configurations by comparing baseline identity states with current states.

## Features

- ✅ **Multi-Cloud Support**: Works with both AWS and Azure identities
- ✅ **Drift Detection**: Identifies multiple types of security drift:
  - Orphaned identities (new users not in baseline)
  - Privilege escalation (users gaining admin rights)
  - Inactive privileged accounts (dormant admin accounts)
  - MFA disabled on privileged accounts
  - Cross-cloud mismatches
  - New roles added to existing users
- ✅ **Comprehensive Reports**: Generates JSON, CSV, and Markdown reports
- ✅ **Severity Classification**: CRITICAL, HIGH, MEDIUM, LOW

## Project Structure

```
multi-cloud-iam-drift-detection/
├── data/
│   ├── baseline/              # Baseline identity snapshots
│   │   ├── aws_identities.json
│   │   └── azure_identities.json
│   └── current/               # Current identity state
│       ├── aws_identities.json
│       └── azure_identities.json
├── outputs/                   # Generated reports
│   ├── baseline_normalized.json
│   ├── current_normalized.json
│   ├── drift_report.json
│   ├── drift_report.csv
│   └── summary.md
├── src/                       # Source code
│   ├── drift_detection.py     # Main drift detection logic
│   ├── drift_rules.py         # Drift detection rules
│   ├── load_data.py           # Data loading utilities
│   ├── normalize.py           # Data normalization
│   └── report.py              # Report generation
├── run.py                     # Main execution script
└── requirements.txt           # Python dependencies
```

## Installation

1. Clone the repository:
```bash
git clone <your-repo-url>
cd multi-cloud-iam-drift-detection
```

2. No external dependencies required! Uses only Python standard library.

## Usage

### Quick Start

Run the complete pipeline with a single command:

```bash
python run.py
```

This will:
1. Normalize the identity data from both clouds
2. Detect drift between baseline and current states
3. Generate reports in multiple formats

### Step-by-Step Execution

You can also run each step individually:

```bash
# Step 1: Normalize data
cd src
python normalize.py

# Step 2: Detect drift
python drift_detection.py

# Step 3: Generate reports
python report.py
```

## Data Format

### AWS Identity Format

```json
{
  "user_name": "jdoe",
  "arn": "arn:aws:iam::123456789012:user/jdoe",
  "attached_policies": ["AdministratorAccess"],
  "is_admin": true,
  "password_enabled": true,
  "password_last_used_days": 2,
  "access_key_active": false,
  "mfa_enabled": true
}
```

### Azure Identity Format

```json
{
  "principal_id": "user-001",
  "upn": "jdoe@corp.com",
  "roles": ["User Administrator"],
  "privileged": true,
  "last_login_days": 3,
  "mfa_enabled": true
}
```

## Drift Rules

The tool detects the following types of drift:

1. **Orphaned Identity** (HIGH): Identity exists in current but not in baseline
2. **Privilege Escalation** (CRITICAL): User gained privileged access
3. **Inactive Privileged Account** (HIGH): Admin account inactive for 90+ days
4. **MFA Disabled on Privileged Account** (HIGH): Admin without MFA
5. **Cross-Cloud Mismatch** (MEDIUM): Inconsistent roles across clouds
6. **New Roles Added** (MEDIUM): Additional roles assigned to user

## Output Files

After running the tool, check the `outputs/` directory for:

- **drift_report.json**: Detailed findings in JSON format
- **drift_report.csv**: Findings in CSV format (Excel-compatible)
- **summary.md**: Executive summary with recommendations
- **baseline_normalized.json**: Normalized baseline data
- **current_normalized.json**: Normalized current data

## Example Output

```
=== Multi-Cloud IAM Drift Detection ===

Loading normalized data...
Loaded 8 baseline identities
Loaded 8 current identities

Detecting drift...

Drift Detection Complete!
Total Findings: 12

Findings by Severity:
  CRITICAL: 2
  HIGH: 6
  MEDIUM: 4

Results saved to outputs/drift_report.json
```

## Configuration

### Adjusting Inactivity Threshold

Edit `src/drift_rules.py`:

```python
INACTIVITY_THRESHOLD_DAYS = 90  # Change to your requirement
```

## Common Issues & Solutions

### Issue: "File not found" errors

**Solution**: Make sure you're running the script from the project root directory:
```bash
cd /path/to/multi-cloud-iam-drift-detection
python run.py
```

### Issue: "No findings to report"

**Solution**: This means no drift was detected. Verify your baseline and current data files are different.

### Issue: Import errors

**Solution**: Run from project root and use `run.py` which handles paths automatically.

## Contributing

Contributions are welcome! Areas for improvement:

- [ ] Add more cloud providers (GCP, OCI)
- [ ] Add real-time monitoring
- [ ] Integrate with SIEM systems
- [ ] Add automated remediation suggestions
- [ ] Create web dashboard

## License

MIT License - See LICENSE file for details

## Security Note

This tool is designed for security auditing. Ensure you have proper authorization before scanning production cloud environments.

## Contact

For questions or issues, please open a GitHub issue.
