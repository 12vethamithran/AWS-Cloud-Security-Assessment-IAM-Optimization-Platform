import boto3
import os

class AWSConnection:
    """Simple AWS connection handler with validation"""
    
    def __init__(self):
        self.session = None
        self.iam = None
        self.cloudtrail = None
        self.sts = None
    
    def load_credentials_from_env(self):
        """Load credentials from config.env file"""
        creds = {}
        
        # Check current directory
        config_path = 'config.env'
        print(f"Looking for config file at: {os.path.abspath(config_path)}")
        
        if not os.path.exists(config_path):
            print(f"Config file not found!")
            print(f"Current directory: {os.getcwd()}")
            print(f"Files in current directory: {os.listdir('.')}")
            return creds
        
        with open(config_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    creds[key.strip()] = value.strip()
        
        print(f"Loaded {len(creds)} configuration items")
        return creds
    
    def validate_credentials(self, creds):
        """Validate that credentials are not placeholders"""
        key = creds.get('AWS_ACCESS_KEY_ID', '')
        secret = creds.get('AWS_SECRET_ACCESS_KEY', '')
        
        if 'your_' in key.lower() or 'your_' in secret.lower():
            return False, "Placeholder credentials detected"
        
        if len(key) < 16:
            return False, "Access Key ID too short"
        
        if len(secret) < 20:
            return False, "Secret Access Key too short"
        
        return True, "Valid format"
    
    def connect(self):
        """Connect to AWS using credentials from config.env"""
        print("\nConnecting to AWS...")
        
        # Load from config.env
        creds = self.load_credentials_from_env()
        
        if not creds.get('AWS_ACCESS_KEY_ID') or not creds.get('AWS_SECRET_ACCESS_KEY'):
            print("Error: AWS credentials not found in config.env")
            print("Make sure:")
            print("  1. File is named 'config.env' (not .env)")
            print("  2. File is in the same directory as main.py")
            print("  3. Credentials are filled in (not placeholder values)")
            return False
        
        # Validate credentials
        is_valid, message = self.validate_credentials(creds)
        if not is_valid:
            print(f"Error: {message}")
            return False
        
        try:
            # Create boto3 session
            self.session = boto3.Session(
                aws_access_key_id=creds['AWS_ACCESS_KEY_ID'],
                aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'],
                region_name=creds.get('AWS_REGION', 'us-east-1')
            )
            
            # Initialize clients
            self.iam = self.session.client('iam')
            self.cloudtrail = self.session.client('cloudtrail')
            self.sts = self.session.client('sts')
            
            # Test connection
            identity = self.sts.get_caller_identity()
            print(f"Connected to AWS Account: {identity['Account']}")
            print(f"Region: {creds.get('AWS_REGION', 'us-east-1')}")
            
            return True
            
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
