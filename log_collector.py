import json
import datetime
from typing import List, Dict

class LogCollector:
    """Collects and stores CloudTrail logs"""
    
    def __init__(self, cloudtrail_client):
        self.cloudtrail = cloudtrail_client
        self.logs_file = "cloudtrail_logs.json"
    
    def collect_logs(self, hours_back=24):
        """Collect CloudTrail logs from last X hours"""
        print(f"\nCollecting CloudTrail logs (last {hours_back} hours)...")
        
        end_time = datetime.datetime.now(datetime.timezone.utc)
        start_time = end_time - datetime.timedelta(hours=hours_back)
        
        all_logs = []
        
        try:
            # Get CloudTrail events - MaxResults is valid for lookup_events
            response = self.cloudtrail.lookup_events(
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=50  # Max per page is 50 for lookup_events
            )
            
            events = response.get('Events', [])
            
            for event in events:
                # Parse event details
                ct_event = {}
                if event.get('CloudTrailEvent'):
                    try:
                        ct_event = json.loads(event['CloudTrailEvent'])
                    except json.JSONDecodeError:
                        pass
                
                # Safely extract user ARN from different identity types
                user_identity = ct_event.get('userIdentity', {})
                user_arn = user_identity.get('arn', '')
                
                # Handle different identity types (IAMUser, AssumedRole, etc.)
                if not user_arn and user_identity.get('type') == 'IAMUser':
                    user_arn = user_identity.get('principalId', '')
                
                log_entry = {
                    'event_id': event.get('EventId'),
                    'event_name': event.get('EventName'),
                    'event_time': event.get('EventTime').isoformat() if event.get('EventTime') else None,
                    'username': event.get('Username', 'Unknown'),
                    'user_arn': user_arn,
                    'source_ip': event.get('SourceIPAddress'),
                    'event_source': event.get('EventSource'),
                    'error_code': ct_event.get('errorCode'),
                    'read_only': ct_event.get('readOnly', True)
                }
                
                all_logs.append(log_entry)
            
            # Handle pagination
            while response.get('NextToken'):
                try:
                    response = self.cloudtrail.lookup_events(
                        StartTime=start_time,
                        EndTime=end_time,
                        MaxResults=50,
                        NextToken=response['NextToken']
                    )
                    
                    events = response.get('Events', [])
                    
                    for event in events:
                        ct_event = {}
                        if event.get('CloudTrailEvent'):
                            try:
                                ct_event = json.loads(event['CloudTrailEvent'])
                            except json.JSONDecodeError:
                                pass
                        
                        user_identity = ct_event.get('userIdentity', {})
                        user_arn = user_identity.get('arn', '')
                        
                        if not user_arn and user_identity.get('type') == 'IAMUser':
                            user_arn = user_identity.get('principalId', '')
                        
                        log_entry = {
                            'event_id': event.get('EventId'),
                            'event_name': event.get('EventName'),
                            'event_time': event.get('EventTime').isoformat() if event.get('EventTime') else None,
                            'username': event.get('Username', 'Unknown'),
                            'user_arn': user_arn,
                            'source_ip': event.get('SourceIPAddress'),
                            'event_source': event.get('EventSource'),
                            'error_code': ct_event.get('errorCode'),
                            'read_only': ct_event.get('readOnly', True)
                        }
                        
                        all_logs.append(log_entry)
                    
                    # Limit to prevent excessive API calls
                    if len(all_logs) >= 1000:
                        print(f"  [!] Reached limit of 1000 events")
                        break
                        
                except Exception as e:
                    print(f"  [!] Error during pagination: {e}")
                    break
            
            # Save logs to file
            self._save_logs(all_logs)
            
            print(f"[+] Collected {len(all_logs)} events")
            return all_logs
            
        except Exception as e:
            print(f"[-] Error collecting logs: {e}")
            print(f"    Make sure CloudTrail is enabled and you have permission to read events")
            return []
    
    def _save_logs(self, logs):
        """Save logs to JSON file"""
        try:
            with open(self.logs_file, 'w', encoding='utf-8') as f:
                json.dump(logs, f, indent=2, default=str)
            print(f"  [+] Saved logs to {self.logs_file}")
        except Exception as e:
            print(f"[-] Error saving logs: {e}")
    
    def load_logs(self):
        """Load logs from file"""
        try:
            with open(self.logs_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"[!] {self.logs_file} not found")
            return []
        except Exception as e:
            print(f"[-] Error loading logs: {e}")
            return []
    
    def get_permission_usage(self, logs):
        """Extract permission usage from logs"""
        print("\n[*] Analyzing permission usage from logs...")
        
        permission_usage = {}
        
        for log in logs:
            user_arn = log.get('user_arn', '')
            event_name = log.get('event_name', '')
            event_source = log.get('event_source', '')
            
            if not user_arn or not event_name:
                continue
            
            # Convert event to permission format (service:action)
            service = event_source.replace('.amazonaws.com', '') if event_source else 'unknown'
            permission = f"{service}:{event_name}"
            
            if user_arn not in permission_usage:
                permission_usage[user_arn] = set()
            
            permission_usage[user_arn].add(permission)
        
        # Convert sets to lists for JSON serialization
        for user in permission_usage:
            permission_usage[user] = list(permission_usage[user])
        
        print(f"[+] Tracked permissions for {len(permission_usage)} users")
        return permission_usage
