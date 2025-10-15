"""
Text-based Cloud Security Report Generator
Generates comprehensive security report in TXT format
"""

import datetime
import os


def generate_text_report(users, groups, logs, output_path=None):
    """Generate comprehensive text report"""
    
    if output_path is None:
        output_path = r"D:\cyber\Projects\cloud sec project\CloudSec Rport.txt"
    
    print("\n" + "=" * 60)
    print("GENERATING SECURITY REPORT")
    print("=" * 60)

    # Ensure inputs are lists
    if not isinstance(users, list):
        users = []
    if not isinstance(groups, list):
        groups = []
    if not isinstance(logs, list):
        logs = []

    if not users and not groups:
        print("\n[-] No data to generate report!")
        return False

    # Create summary data
    summary = {
        'total_users': len(users),
        'total_groups': len(groups),
        'total_events': len(logs),
        'high_risk_users': len([u for u in users if isinstance(u, dict) and u.get('risk_level') in ['HIGH', 'CRITICAL']]),
        'high_risk_groups': len([g for g in groups if isinstance(g, dict) and g.get('risk_level') in ['HIGH', 'CRITICAL']]),
        'total_unused_permissions': sum(len(u.get('unused_permissions', [])) for u in users if isinstance(u, dict))
    }

    # Build report content
    report_lines = []
    
    # Header
    report_lines.append("=" * 80)
    report_lines.append("AWS CLOUD SECURITY ASSESSMENT REPORT".center(80))
    report_lines.append("=" * 80)
    report_lines.append("")
    report_lines.append(f"Generated: {datetime.datetime.now().strftime('%B %d, %Y at %H:%M:%S')}")
    report_lines.append(f"Analysis Period: Last 24 hours")
    report_lines.append("")
    report_lines.append("=" * 80)
    report_lines.append("")
    
    # Table of Contents
    report_lines.append("TABLE OF CONTENTS")
    report_lines.append("-" * 80)
    report_lines.append("1. Executive Summary")
    report_lines.append("2. Security Risk Overview")
    report_lines.append("3. IAM Users Analysis")
    report_lines.append("4. IAM Groups Analysis")
    report_lines.append("5. CloudTrail Activity Summary")
    report_lines.append("6. Recommendations and Remediation Steps")
    report_lines.append("")
    report_lines.append("=" * 80)
    report_lines.append("")
    
    # 1. Executive Summary
    report_lines.append("1. EXECUTIVE SUMMARY")
    report_lines.append("=" * 80)
    report_lines.append("")
    report_lines.append("This report provides a comprehensive security assessment of the AWS environment,")
    report_lines.append("focusing on IAM user permissions, group configurations, and CloudTrail activity.")
    report_lines.append("The assessment identifies unused permissions, overprivileged accounts, and")
    report_lines.append("potential security risks based on the principle of least privilege.")
    report_lines.append("")
    
    # Summary Table
    report_lines.append("KEY METRICS")
    report_lines.append("-" * 80)
    report_lines.append(f"Total Users Analyzed:           {summary['total_users']}")
    report_lines.append(f"Total Groups Analyzed:          {summary['total_groups']}")
    report_lines.append(f"Total CloudTrail Events:        {summary['total_events']}")
    report_lines.append(f"High/Critical Risk Users:       {summary['high_risk_users']}")
    report_lines.append(f"High/Critical Risk Groups:      {summary['high_risk_groups']}")
    report_lines.append(f"Total Unused Permissions:       {summary['total_unused_permissions']}")
    report_lines.append("")
    report_lines.append("=" * 80)
    report_lines.append("")
    
    # 2. Security Risk Overview
    report_lines.append("2. SECURITY RISK OVERVIEW")
    report_lines.append("=" * 80)
    report_lines.append("")
    
    # Risk distribution
    risk_dist = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for user in users:
        if isinstance(user, dict):
            level = user.get('risk_level', 'LOW')
            risk_dist[level] = risk_dist.get(level, 0) + 1
    
    report_lines.append("USER RISK DISTRIBUTION:")
    report_lines.append("-" * 80)
    report_lines.append(f"  CRITICAL Risk Users:  {risk_dist['CRITICAL']}")
    report_lines.append(f"  HIGH Risk Users:      {risk_dist['HIGH']}")
    report_lines.append(f"  MEDIUM Risk Users:    {risk_dist['MEDIUM']}")
    report_lines.append(f"  LOW Risk Users:       {risk_dist['LOW']}")
    report_lines.append("")
    
    # High-risk users detail
    high_risk = [u for u in users if isinstance(u, dict) and u.get('risk_level') in ['HIGH', 'CRITICAL']]
    if high_risk:
        report_lines.append("HIGH-RISK USERS REQUIRING IMMEDIATE ACTION:")
        report_lines.append("-" * 80)
        report_lines.append(f"Found {len(high_risk)} users requiring immediate attention:")
        report_lines.append("")
        
        for idx, user in enumerate(high_risk[:10], 1):
            report_lines.append(f"{idx}. {user.get('username', 'Unknown')}")
            report_lines.append(f"   Risk Level: {user.get('risk_level', 'UNKNOWN')} (Score: {user.get('risk_score', 0)})")
            report_lines.append(f"   Policies: {len(user.get('attached_policies', []))}, " +
                              f"Groups: {len(user.get('groups', []))}, " +
                              f"Unused Permissions: {len(user.get('unused_permissions', []))}")
            
            recommendations = user.get('recommendations', [])
            if recommendations:
                report_lines.append(f"   Recommendations: {'; '.join(recommendations)}")
            report_lines.append("")
    
    report_lines.append("=" * 80)
    report_lines.append("")
    
    # 3. IAM Users Analysis
    report_lines.append("3. IAM USERS ANALYSIS")
    report_lines.append("=" * 80)
    report_lines.append("")
    
    if users:
        report_lines.append(f"Total Users Analyzed: {len(users)}")
        if summary['high_risk_users'] > 0:
            report_lines.append(f"WARNING: HIGH/CRITICAL RISK USERS: {summary['high_risk_users']}")
        report_lines.append("")
        
        # Users table header
        report_lines.append("-" * 80)
        report_lines.append(f"{'Username':<20} {'Risk':<10} {'Score':<8} {'Policies':<10} {'Groups':<10} {'Issues':<20}")
        report_lines.append("-" * 80)
        
        # Sort by risk score
        sorted_users = sorted([u for u in users if isinstance(u, dict)], 
                             key=lambda x: x.get('risk_score', 0), reverse=True)
        
        for user in sorted_users[:20]:  # Top 20
            username = user.get('username', 'Unknown')[:19]
            risk_level = user.get('risk_level', 'LOW')
            risk_score = str(user.get('risk_score', 0))
            policies = str(len(user.get('attached_policies', [])))
            groups = str(len(user.get('groups', [])))
            
            # Build issues string
            issues = []
            unused = len(user.get('unused_permissions', []))
            if unused > 0:
                issues.append(f"{unused} unused")
            if len(user.get('attached_policies', [])) > 5:
                issues.append("Too many policies")
            issues_str = ', '.join(issues)[:19] if issues else 'None'
            
            report_lines.append(f"{username:<20} {risk_level:<10} {risk_score:<8} {policies:<10} {groups:<10} {issues_str:<20}")
        
        report_lines.append("-" * 80)
    else:
        report_lines.append("WARNING: No IAM users found during analysis.")
    
    report_lines.append("")
    report_lines.append("=" * 80)
    report_lines.append("")
    
    # 4. IAM Groups Analysis
    report_lines.append("4. IAM GROUPS ANALYSIS")
    report_lines.append("=" * 80)
    report_lines.append("")
    
    if groups and len(groups) > 0:
        report_lines.append(f"Total Groups Analyzed: {len(groups)}")
        if summary['high_risk_groups'] > 0:
            report_lines.append(f"WARNING: HIGH/CRITICAL RISK GROUPS: {summary['high_risk_groups']}")
        report_lines.append("")
        
        # Groups table header
        report_lines.append("-" * 80)
        report_lines.append(f"{'Group Name':<25} {'Risk':<10} {'Score':<8} {'Members':<10} {'Policies':<10} {'Issues':<15}")
        report_lines.append("-" * 80)
        
        sorted_groups = sorted([g for g in groups if isinstance(g, dict)], 
                              key=lambda x: x.get('risk_score', 0), reverse=True)
        
        for group in sorted_groups:
            group_name = group.get('group_name', 'Unknown')[:24]
            risk_level = group.get('risk_level', 'LOW')
            risk_score = str(group.get('risk_score', 0))
            members = str(group.get('member_count', 0))
            policies = str(len(group.get('attached_policies', [])))
            
            issues = []
            if group.get('member_count', 0) == 0:
                issues.append("Empty")
            unused = len(group.get('unused_permissions', []))
            if unused > 0:
                issues.append(f"{unused} unused")
            issues_str = ', '.join(issues)[:14] if issues else 'None'
            
            report_lines.append(f"{group_name:<25} {risk_level:<10} {risk_score:<8} {members:<10} {policies:<10} {issues_str:<15}")
        
        report_lines.append("-" * 80)
    else:
        report_lines.append("No IAM groups found or insufficient permissions to list groups.")
    
    report_lines.append("")
    report_lines.append("=" * 80)
    report_lines.append("")
    
    # 5. CloudTrail Activity
    report_lines.append("5. CLOUDTRAIL ACTIVITY SUMMARY")
    report_lines.append("=" * 80)
    report_lines.append("")
    
    if logs:
        report_lines.append(f"Total Events Collected: {len(logs)}")
        
        error_events = [log for log in logs if isinstance(log, dict) and log.get('error_code')]
        report_lines.append(f"Events with Errors: {len(error_events)}")
        
        # Event types
        event_types = {}
        for log in logs:
            if isinstance(log, dict):
                event_name = log.get('event_name', 'Unknown')
                event_types[event_name] = event_types.get(event_name, 0) + 1
        
        report_lines.append(f"Unique Event Types: {len(event_types)}")
        report_lines.append("")
        
        # Top events
        report_lines.append("TOP 10 EVENT TYPES:")
        report_lines.append("-" * 80)
        sorted_events = sorted(event_types.items(), key=lambda x: x[1], reverse=True)[:10]
        for event_name, count in sorted_events:
            report_lines.append(f"  {event_name:<50} {count:>5} occurrences")
        
        report_lines.append("")
        report_lines.append("MOST ACTIVE USERS:")
        report_lines.append("-" * 80)
        
        user_activity = {}
        for log in logs:
            if isinstance(log, dict):
                username = log.get('username', 'Unknown')
                if username != 'Unknown':
                    user_activity[username] = user_activity.get(username, 0) + 1
        
        sorted_users_activity = sorted(user_activity.items(), key=lambda x: x[1], reverse=True)[:5]
        for username, count in sorted_users_activity:
            report_lines.append(f"  {username:<50} {count:>5} actions")
    else:
        report_lines.append("No CloudTrail events found in the analysis period.")
        report_lines.append("This may indicate CloudTrail is disabled or insufficient permissions.")
    
    report_lines.append("")
    report_lines.append("=" * 80)
    report_lines.append("")
    
    # 6. Recommendations
    report_lines.append("6. RECOMMENDATIONS AND REMEDIATION STEPS")
    report_lines.append("=" * 80)
    report_lines.append("")
    
    recommendations = []
    
    if summary.get('high_risk_users', 0) > 0:
        recommendations.append({
            'priority': 'CRITICAL',
            'text': f"{summary['high_risk_users']} users have high-risk configurations. "
                   "Review and remediate unused permissions immediately."
        })
    
    if summary.get('high_risk_groups', 0) > 0:
        recommendations.append({
            'priority': 'HIGH',
            'text': f"{summary['high_risk_groups']} groups have high-risk configurations. "
                   "Review group policies and memberships."
        })
    
    if summary.get('total_unused_permissions', 0) > 50:
        recommendations.append({
            'priority': 'HIGH',
            'text': f"{summary['total_unused_permissions']} unused permissions detected. "
                   "Apply principle of least privilege."
        })
    
    if summary.get('total_events', 0) == 0:
        recommendations.append({
            'priority': 'HIGH',
            'text': "No CloudTrail events found. Enable CloudTrail logging."
        })
    
    if not recommendations:
        recommendations.append({
            'priority': 'INFO',
            'text': "No critical security issues identified."
        })
    
    for idx, rec in enumerate(recommendations, 1):
        report_lines.append(f"[{rec['priority']}] {idx}. {rec['text']}")
        report_lines.append("")
    
    # Action Items
    report_lines.append("")
    report_lines.append("IMMEDIATE ACTION ITEMS:")
    report_lines.append("-" * 80)
    action_items = [
        "Review all users and groups marked as HIGH or CRITICAL risk",
        "Remove unused permissions from IAM policies",
        "Implement regular access reviews (quarterly recommended)",
        "Enable CloudTrail in all regions if not already active",
        "Implement IAM Access Analyzer for continuous monitoring"
    ]
    
    for idx, item in enumerate(action_items, 1):
        report_lines.append(f"  {idx}. {item}")
    
    report_lines.append("")
    report_lines.append("=" * 80)
    report_lines.append("END OF REPORT")
    report_lines.append("=" * 80)
    
    # Write to file
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report_lines))
        
        print(f"\n[+] Report generated successfully!")
        print(f"[+] Location: {output_path}")
        print(f"\n[*] Report Summary:")
        print(f"    - {len(users)} users analyzed")
        print(f"    - {len(groups)} groups analyzed")
        print(f"    - {len(logs)} events processed")
        print(f"    - {summary.get('high_risk_users', 0)} high-risk users")
        print(f"    - {summary.get('high_risk_groups', 0)} high-risk groups")
        
        return True
        
    except Exception as e:
        print(f"\n[-] Error saving report: {e}")
        # Try alternate location
        try:
            alt_path = "CloudSec_Report.txt"
            with open(alt_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(report_lines))
            print(f"[+] Report saved to alternate location: {os.path.abspath(alt_path)}")
            return True
        except Exception as e2:
            print(f"[-] Failed to save report to alternate location: {e2}")
            return False
