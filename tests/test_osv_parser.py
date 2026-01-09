#!/usr/bin/env python3
"""
Test script for OSV parser with new schema
"""

import sys
import os
import asyncio
import pytest

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from vma.osv import parse_osv_file

@pytest.mark.asyncio
async def test_osv_parser():
    """Test the OSV parser with sample data"""
    test_file = "osv/test_osv.json"

    print(f"Testing OSV parser with file: {test_file}")
    print("=" * 60)

    # Parse the test file
    result = await parse_osv_file(test_file)

    if not result or len(result) != 6:
        print("ERROR: Parser did not return expected format [vuln, aliases, refs, severity, affected, credits]")
        return False

    data_vuln, data_aliases, data_refs, data_severity, data_affected, data_credits = result

    print(f"\n✓ Parser returned data successfully")
    print(f"  - Vulnerability entries: {len(data_vuln)}")
    print(f"  - Aliases: {len(data_aliases)}")
    print(f"  - References: {len(data_refs)}")
    print(f"  - Severity entries: {len(data_severity)}")
    print(f"  - Affected packages: {len(data_affected)}")
    print(f"  - Credits: {len(data_credits)}")

    # Check vulnerability data
    if data_vuln:
        print("\nOSV Vulnerability Data (osv_vulnerabilities table):")
        print("-" * 60)
        vuln_entry = data_vuln[0]
        print(f"  OSV ID: {vuln_entry[0]}")
        print(f"  Schema Version: {vuln_entry[1]}")
        print(f"  Modified: {vuln_entry[2]}")
        print(f"  Published: {vuln_entry[3]}")
        print(f"  Withdrawn: {vuln_entry[4]}")
        print(f"  Summary: {vuln_entry[5]}")
        print(f"  Details: {vuln_entry[6][:100]}..." if vuln_entry[6] and len(vuln_entry[6]) > 100 else f"  Details: {vuln_entry[6]}")
        print(f"  Database Specific: {vuln_entry[7]}")

    # Check aliases
    if data_aliases:
        print("\nAliases Data (osv_aliases table):")
        print("-" * 60)
        for idx, alias_entry in enumerate(data_aliases, 1):
            print(f"  Alias {idx}: OSV_ID={alias_entry[0]}, Alias={alias_entry[1]}")

    # Check references
    if data_refs:
        print("\nReferences Data (osv_references table):")
        print("-" * 60)
        for idx, ref_entry in enumerate(data_refs, 1):
            print(f"  Ref {idx}: Type={ref_entry[1]}, URL={ref_entry[2][:50]}...")

    # Check severity data
    if data_severity:
        print("\nSeverity Data (osv_severity table):")
        print("-" * 60)
        for idx, sev_entry in enumerate(data_severity, 1):
            print(f"  Severity {idx}:")
            print(f"    OSV ID: {sev_entry[0]}")
            print(f"    Type: {sev_entry[1]}")
            print(f"    Score: {sev_entry[2]}")

    # Check affected packages
    if data_affected:
        print("\nAffected Packages Data (osv_affected table):")
        print("-" * 60)
        for idx, aff_entry in enumerate(data_affected, 1):
            print(f"  Package {idx}:")
            print(f"    Ecosystem: {aff_entry[1]}")
            print(f"    Name: {aff_entry[2]}")
            print(f"    Purl: {aff_entry[3]}")
            print(f"    Ranges: {aff_entry[4]}")
            print(f"    Versions: {aff_entry[5]}")

    # Check credits
    if data_credits:
        print("\nCredits Data (osv_credits table):")
        print("-" * 60)
        for idx, credit_entry in enumerate(data_credits, 1):
            print(f"  Credit {idx}: Name={credit_entry[1]}, Type={credit_entry[3]}")

    print("\n" + "=" * 60)
    print("✓ Test completed successfully!")
    return True

if __name__ == "__main__":
    success = test_osv_parser()
    sys.exit(0 if success else 1)
