import json
from dataclasses import dataclass
from typing import List

@dataclass
class UserAnalysis:
    username: str
    user_arn: str
    attached_policies: List[str]
    groups: List[str]
    all_permissions: List[str]
    used_permissions: List[str]
    unused_permissions: List[str]
    risk_score: int
    risk_level: str
    recommendations: List[str]

@dataclass
class GroupAnalysis:
    group_name: str
    member_count: int
    attached_policies: List[str]
    permissions: List[str]
    unused_permissions: List[str]
    risk_score: int
    risk_level: str
    recommendations: List[str]

class IAMAnalyzer:
    """Analyzes IAM users and groups for unused permissions"""
    
    def __init__(self, iam_client):
        self.iam = iam_client
        self.users_file = "iam_users_analysis.json"
        self.groups_file = "iam_groups_analysis.json"
    
    def analyze_users(self, permission_usage):
        """Analyze all IAM users"""
        print("\n[*] Analyzing IAM users...")
        
        users_analysis = []
        
        try:
            # Get all users
            paginator = self.iam.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page['Users']:
                    analysis = self._analyze_single_user(user, permission_usage)
                    if analysis:
                        users_analysis.append(analysis)
            
            # Save results
            self._save_results(users_analysis, self.users_file)
            
            print(f"[+] Analyzed {len(users_analysis)} users")
            return users_analysis
            
        except Exception as e:
            print(f"[-] Error analyzing users: {e}")
            return []
    
    def _analyze_single_user(self, user, permission_usage):
        """Analyze a single user"""
        try:
            username = user['UserName']
            user_arn = user['Arn']
            
            # Get user's groups
            groups = []
            try:
                response = self.iam.list_groups_for_user(UserName=username)
                groups = [g['GroupName'] for g in response.get('Groups', [])]
            except Exception as e:
                print(f"  [!] Could not get groups for {username}: {e}")
            
            # Get attached policies
            attached_policies = []
            try:
                response = self.iam.list_attached_user_policies(UserName=username)
                attached_policies = [p['PolicyName'] for p in response.get('AttachedPolicies', [])]
            except Exception as e:
                print(f"  [!] Could not get policies for {username}: {e}")
            
            # Get all permissions (simplified - just policy names for now)
            all_permissions = self._get_user_permissions(username, attached_policies, groups)
            
            # Get used permissions
            used_permissions = permission_usage.get(user_arn, [])
            
            # Calculate unused permissions
            unused_permissions = list(set(all_permissions) - set(used_permissions))
            
            # Calculate risk score (FIXED: improved logic)
            risk_score = 0
            
            # Base risk on unused permissions
            if len(all_permissions) > 0:
                unused_ratio = len(unused_permissions) / len(all_permissions)
                risk_score += int(unused_ratio * 60)  # Max 60 points from ratio
            
            # Add points for absolute number of unused permissions
            if len(unused_permissions) > 50:
                risk_score += 30
            elif len(unused_permissions) > 20:
                risk_score += 20
            elif len(unused_permissions) > 10:
                risk_score += 10
            
            # Cap at 100
            if risk_score > 100:
                risk_score = 100
            
            # Determine risk level
            if risk_score >= 70:
                risk_level = "CRITICAL"
            elif risk_score >= 50:
                risk_level = "HIGH"
            elif risk_score >= 30:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"
            
            # Generate recommendations
            recommendations = []
            if len(unused_permissions) > 20:
                recommendations.append(f"Remove {len(unused_permissions)} unused permissions")
            elif len(unused_permissions) > 10:
                recommendations.append("Review and optimize IAM policies")
            
            if len(attached_policies) > 5:
                recommendations.append("Consider consolidating policies")
            
            if len(groups) == 0 and len(attached_policies) > 0:
                recommendations.append("Consider using groups instead of direct policy attachments")
            
            if not recommendations:
                recommendations.append("User permissions are optimized")
            
            return UserAnalysis(
                username=username,
                user_arn=user_arn,
                attached_policies=attached_policies,
                groups=groups,
                all_permissions=all_permissions[:50],  # Limit for display
                used_permissions=used_permissions[:50],
                unused_permissions=unused_permissions[:50],
                risk_score=risk_score,
                risk_level=risk_level,
                recommendations=recommendations
            ).__dict__
            
        except Exception as e:
            print(f"  [!] Error analyzing user {user.get('UserName', 'unknown')}: {e}")
            return None
    
    def _get_user_permissions(self, username, attached_policies, groups):
        """Get all permissions for a user (simplified)"""
        permissions = []
        
        # Add policy names as "permissions" (simplified approach)
        for policy_name in attached_policies:
            permissions.append(f"policy:{policy_name}")
        
        # Add group policy names
        for group_name in groups:
            try:
                response = self.iam.list_attached_group_policies(GroupName=group_name)
                for policy in response.get('AttachedPolicies', []):
                    permissions.append(f"group:{group_name}:policy:{policy['PolicyName']}")
            except Exception as e:
                print(f"  [!] Could not get group policies for {group_name}: {e}")
        
        return permissions
    
    def analyze_groups(self, permission_usage):
        """Analyze all IAM groups"""
        print("\n[*] Analyzing IAM groups...")
        
        groups_analysis = []
        
        try:
            # Get all groups
            paginator = self.iam.get_paginator('list_groups')
            
            for page in paginator.paginate():
                for group in page['Groups']:
                    analysis = self._analyze_single_group(group, permission_usage)
                    if analysis:
                        groups_analysis.append(analysis)
            
            # Save results
            self._save_results(groups_analysis, self.groups_file)
            
            print(f"[+] Analyzed {len(groups_analysis)} groups")
            return groups_analysis
            
        except Exception as e:
            print(f"[-] Error analyzing groups: {e}")
            return []
    
    def _analyze_single_group(self, group, permission_usage):
        """Analyze a single group"""
        try:
            group_name = group['GroupName']
            
            # Get group members
            member_count = 0
            member_arns = []
            try:
                response = self.iam.get_group(GroupName=group_name)
                members = response.get('Users', [])
                member_count = len(members)
                member_arns = [m['Arn'] for m in members]
            except Exception as e:
                print(f"  [!] Could not get members for {group_name}: {e}")
            
            # Get attached policies
            attached_policies = []
            try:
                response = self.iam.list_attached_group_policies(GroupName=group_name)
                attached_policies = [p['PolicyName'] for p in response.get('AttachedPolicies', [])]
            except Exception as e:
                print(f"  [!] Could not get policies for {group_name}: {e}")
            
            # Get group permissions (simplified)
            permissions = [f"policy:{p}" for p in attached_policies]
            
            # Calculate unused permissions (check if members use them)
            used_by_members = set()
            for member_arn in member_arns:
                used_by_members.update(permission_usage.get(member_arn, []))
            
            unused_permissions = list(set(permissions) - used_by_members)
            
            # Calculate risk score (FIXED: improved logic)
            risk_score = 0
            
            if member_count == 0:
                risk_score += 40  # Empty group is risky
            
            if len(permissions) > 0:
                unused_ratio = len(unused_permissions) / len(permissions)
                risk_score += int(unused_ratio * 40)
            
            if len(unused_permissions) > 10:
                risk_score += 20
            
            # Cap at 100
            if risk_score > 100:
                risk_score = 100
            
            # Determine risk level
            if risk_score >= 70:
                risk_level = "CRITICAL"
            elif risk_score >= 50:
                risk_level = "HIGH"
            elif risk_score >= 30:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"
            
            # Generate recommendations
            recommendations = []
            if member_count == 0:
                recommendations.append("Group has no members - consider deletion")
            if len(unused_permissions) > 10:
                recommendations.append(f"Review {len(unused_permissions)} unused group permissions")
            if len(attached_policies) > 5:
                recommendations.append("Consider reducing number of attached policies")
            if not recommendations:
                recommendations.append("Group configuration is acceptable")
            
            return GroupAnalysis(
                group_name=group_name,
                member_count=member_count,
                attached_policies=attached_policies,
                permissions=permissions[:30],
                unused_permissions=unused_permissions[:30],
                risk_score=risk_score,
                risk_level=risk_level,
                recommendations=recommendations
            ).__dict__
            
        except Exception as e:
            print(f"  [!] Error analyzing group {group.get('GroupName', 'unknown')}: {e}")
            return None
    
    def _save_results(self, data, filename):
        """Save analysis results to JSON file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            print(f"  [+] Saved to {filename}")
        except Exception as e:
            print(f"[-] Error saving to {filename}: {e}")
