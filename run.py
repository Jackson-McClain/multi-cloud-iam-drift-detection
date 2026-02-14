#!/usr/bin/env python3
"""
Multi-Cloud IAM Drift Detection
Main execution script
"""

import sys
import os
from pathlib import Path

# Add src directory to Python path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

# Change to project root directory
os.chdir(Path(__file__).parent)


def main():
    print("=" * 60)
    print("  Multi-Cloud IAM Drift Detection System")
    print("=" * 60)
    print()
    
    # Step 1: Normalize data
    print("Step 1: Normalizing identity data...")
    print("-" * 60)
    from normalize import main as normalize_main
    normalize_main()
    print()
    
    # Step 2: Detect drift
    print("\nStep 2: Detecting drift...")
    print("-" * 60)
    from drift_detection import main as detect_main
    detect_main()
    print()
    
    # Step 3: Generate reports
    print("\nStep 3: Generating reports...")
    print("-" * 60)
    from report import main as report_main
    report_main()
    print()
    
    print("=" * 60)
    print("  ✅ Complete! Check the /outputs folder for results.")
    print("=" * 60)


if __name__ == "__main__":
    main()
