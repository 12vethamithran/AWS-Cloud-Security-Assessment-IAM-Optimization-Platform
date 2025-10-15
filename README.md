# AWS Cloud Security Assessment Platform

A Python-based security assessment tool that analyzes AWS IAM configurations and CloudTrail logs to identify security risks, unused permissions, and overprivileged accounts.

## 🎯 Overview

This platform performs comprehensive security assessments of AWS environments by:
- Analyzing IAM users and groups for unused permissions
- Collecting and analyzing CloudTrail logs
- Identifying high-risk configurations
- Generating detailed security reports
- Calculating risk scores based on the principle of least privilege

## 🚀 Features

- **IAM User Analysis**: Evaluates all IAM users for attached policies, group memberships, and permission usage
- **IAM Group Analysis**: Assesses group configurations, member counts, and policy attachments
- **CloudTrail Integration**: Collects and analyzes up to 1,000 recent events to track actual permission usage
- **Risk Scoring**: Assigns risk levels (LOW, MEDIUM, HIGH, CRITICAL) based on multiple factors
- **Automated Reporting**: Generates comprehensive text-based security assessment reports
- **Permission Tracking**: Identifies unused permissions by comparing granted vs. used permissions

## 📋 Prerequisites

- Python 3.7+
- AWS Account with appropriate permissions
- AWS IAM user with the following minimum permissions:
  - `iam:ListUsers`
  - `iam:ListGroups`
  - `iam:GetUser`
  - `iam:GetGroup`
  - `iam:ListAttachedUserPolicies`
  - `iam:ListAttachedGroupPolicies`
  - `iam:ListGroupsForUser`
  - `cloudtrail:LookupEvents`
  - `sts:GetCallerIdentity`

## 🛠️ Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/aws-cloud-security-platform.git
cd aws-cloud-security-platform
```

2. Install required dependencies:
```bash
pip install boto3
```

3. Configure AWS credentials in `config.env`:
```env
AWS_ACCESS_KEY_ID=your_access_key_here
AWS_SECRET_ACCESS_KEY=your_secret_key_here
AWS_REGION=your_region
```

## 📁 Project Structure

```
aws-cloud-security-platform/
│
├── main.py                      # Main entry point
├── aws_connection.py            # AWS connection handler
├── log_collector.py             # CloudTrail log collection
├── IAM_Analyzer.py              # IAM analysis engine
├── report_generator.py          # Report generation
├── config.env                   # AWS credentials configuration
│
├── iam_users_analysis.json      # Generated user analysis
├── iam_groups_analysis.json     # Generated group analysis
├── cloudtrail_logs.json         # Collected CloudTrail logs
└── CloudSec Rport.txt           # Final security report
```

## 🚦 Usage

1. **Configure your AWS credentials** in `config.env`

2. **Run the security assessment**:
```bash
python main.py
```

3. **Review the generated reports**:
   - `CloudSec Rport.txt` - Comprehensive security assessment report
   - `iam_users_analysis.json` - Detailed user analysis data
   - `iam_groups_analysis.json` - Detailed group analysis data
   - `cloudtrail_logs.json` - Raw CloudTrail event data

## 📊 Risk Scoring Methodology

The platform calculates risk scores (0-100) based on:

### Users:
- **Unused permission ratio**: Up to 60 points based on percentage of unused permissions
- **Absolute unused count**: 10-30 points based on total unused permissions
- **Risk Levels**:
  - CRITICAL: 70-100
  - HIGH: 50-69
  - MEDIUM: 30-49
  - LOW: 0-29

### Groups:
- **Empty groups**: 40 points
- **Unused permission ratio**: Up to 40 points
- **High unused count**: Additional 20 points for 10+ unused permissions

## 📈 Sample Output

```
============================================================
                 CLOUD SECURITY PLATFORM
============================================================

[+] Connected to AWS Account: 340705233801
[+] Region: eu-north-1

[+] Collected 293 events
[+] Analyzed 1 users
[+] Analyzed 1 groups

[!] High-risk users detected:
    - mith: HIGH (Score: 60)

[+] ALL TASKS COMPLETED
============================================================
```

## 📝 Configuration Options

Edit `config.env` to customize:

```env
# Analysis period
ANALYSIS_HOURS_BACK=24

# Event collection limit
MAX_EVENTS_TO_COLLECT=2000

# Risk thresholds
CRITICAL_RISK_THRESHOLD=80
HIGH_RISK_THRESHOLD=60
MEDIUM_RISK_THRESHOLD=30

# Data retention
KEEP_LOGS_DAYS=30
ARCHIVE_OLD_DATA=true
```

## 🔒 Security Best Practices

1. **Never commit** `config.env` with real credentials to version control
2. **Use IAM roles** instead of access keys when running on EC2
3. **Rotate credentials** regularly
4. **Apply least privilege** to the IAM user running this tool
5. **Review reports** regularly and take action on high-risk findings

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is open source and available under the MIT License.

## ⚠️ Disclaimer

This tool is for security assessment purposes only. Always test in a non-production environment first. The maintainers are not responsible for any damages or security issues that may arise from using this tool.

## 🐛 Known Limitations

- Maximum 1,000 CloudTrail events per analysis run
- Simplified permission tracking (uses policy names rather than individual actions)
- Requires CloudTrail to be enabled for permission usage tracking
- Does not analyze inline policies (only managed policies)

## 📞 Support

For issues, questions, or contributions, please open an issue on GitHub.

---

**Note**: Remember to add `config.env` to your `.gitignore` file to prevent accidentally committing sensitive credentials.
