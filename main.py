import json
import datetime
import os
from aws_connection import AWSConnection
from log_collector import LogCollector
from IAM_Analyzer import IAMAnalyzer
from report_generator import generate_text_report


def main():
    print("\n" + "="*60)
    print(" "*15 + "CLOUD SECURITY PLATFORM")
    print("="*60)
    
    # Step 1: Connect to AWS
    aws = AWSConnection()
    if not aws.connect():
        print("\n[-] Cannot proceed without AWS connection")
        print("\n[!] Troubleshooting tips:")
        print("    1. Verify your config.env file exists")
        print("    2. Check AWS credentials are correct")
        print("    3. Ensure IAM user has required permissions")
        return
    
    # Step 2: Collect CloudTrail logs
    collector = LogCollector(aws.cloudtrail)
    logs = collector.collect_logs(hours_back=24)
    
    if not logs:
        print("\n[!] No logs collected. This could mean:")
        print("    - CloudTrail is not enabled")
        print("    - No events in the last 24 hours")
        print("    - Insufficient permissions to read CloudTrail")
        print("\n[*] Continuing with IAM analysis (without usage data)...")
    
    # Step 3: Get permission usage from logs
    permission_usage = {}
    if logs:
        permission_usage = collector.get_permission_usage(logs)
    else:
        print("[!] Permission usage tracking will be limited without logs")
    
    # Step 4: Analyze IAM users
    analyzer = IAMAnalyzer(aws.iam)
    users = analyzer.analyze_users(permission_usage)
    
    if not users:
        print("\n[!] No users analyzed. Check IAM permissions.")
    
    # Step 5: Analyze IAM groups
    groups = analyzer.analyze_groups(permission_usage)
    
    if not groups:
        print("\n[!] No groups analyzed. Check IAM permissions or no groups exist.")
    
    # Step 6: Check if we have data to proceed
    if not users and not groups:
        print("\n[-] No data to generate report. Please check your IAM permissions.")
        return
    
    # Display summary
    print("\n" + "="*60)
    print("[+] ANALYSIS COMPLETE!")
    print("="*60)
    print(f"[*] Users analyzed: {len(users)}")
    print(f"[*] Groups analyzed: {len(groups)}")
    print(f"[*] Events processed: {len(logs)}")
    
    if users:
        high_risk = [u for u in users if u['risk_level'] in ['HIGH', 'CRITICAL']]
        print(f"[*] High-risk users: {len(high_risk)}")
        if high_risk:
            print("\n[!] High-risk users detected:")
            for user in high_risk[:5]:  # Show top 5
                print(f"    - {user['username']}: {user['risk_level']} (Score: {user['risk_score']})")
    
    if groups:
        high_risk_groups = [g for g in groups if g['risk_level'] in ['HIGH', 'CRITICAL']]
        if high_risk_groups:
            print(f"\n[!] High-risk groups: {len(high_risk_groups)}")
    
    print("="*60)
    
    # Step 7: Generate Text Report
    print("\n[*] Generating security report...")
    report_path = r"D:\cyber\Projects\cloud sec project\CloudSec Rport.txt"
    report_generated = generate_text_report(users, groups, logs, report_path)
    
    # Final summary
    print("\n" + "="*60)
    print("[+] ALL TASKS COMPLETED")
    print("="*60)
    print("\n[*] Output files created:")
    print("    ✓ iam_users_analysis.json")
    print("    ✓ iam_groups_analysis.json")
    print("    ✓ cloudtrail_logs.json")
    if report_generated:
        print("    ✓ CloudSec Rport.txt")
    else:
        print("    ✗ CloudSec Rport.txt (failed)")
    
    print("\n[*] You can now:")
    print("    - Review the text report for detailed findings")
    print("    - Check JSON files for raw analysis data")
    print("    - Re-run anytime to get updated analysis")
    print("="*60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Analysis interrupted by user")
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
