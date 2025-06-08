import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import re

class DataProcessor:
    """Handles email data processing and validation"""
    
    def __init__(self):
        self.required_fields = [
            '_time', 'policy_name', 'sender', 'transmitter', 'recipients', 'subject', 'wordlist_subject',
            'attachments', 'wordlist_attachment', 'justification', 'is_sensitive', 'bunit', 'department',
            'business_pillar', 'domain', 'breach_prevented', 'user_response', 'tessian_message_shown',
            'leaver', 'resignation_date'
        ]
    
    def validate_data(self, df):
        """Validate that the dataframe contains required fields"""
        missing_fields = [field for field in self.required_fields if field not in df.columns]
        
        if missing_fields:
            raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")
        
        return True
    
    def process_email_data(self, df):
        """Process and clean email data"""
        # Make a copy to avoid modifying original
        processed_df = df.copy()
        
        # Rename _time to time for internal consistency
        if '_time' in processed_df.columns:
            processed_df['time'] = processed_df['_time']
        
        # Convert time column to datetime
        processed_df['time'] = pd.to_datetime(processed_df['time'], errors='coerce')
        
        # Convert resignation_date to datetime
        processed_df['resignation_date'] = pd.to_datetime(processed_df['resignation_date'], errors='coerce')
        
        # Map old field names to new ones for backward compatibility
        processed_df['last_working_day'] = processed_df['resignation_date']
        processed_df['word_list_match'] = processed_df['wordlist_subject'].fillna('') + ' ' + processed_df['wordlist_attachment'].fillna('')
        processed_df['email_domain'] = processed_df['domain']
        processed_df['businessPillar'] = processed_df['business_pillar']
        
        # Create combined wordlist field for analysis
        processed_df['combined_wordlist'] = processed_df['wordlist_subject'].fillna('') + ' ' + processed_df['wordlist_attachment'].fillna('')
        processed_df['combined_wordlist'] = processed_df['combined_wordlist'].str.strip()
        
        # Clean and standardize email addresses
        processed_df['sender'] = processed_df['sender'].str.lower().str.strip()
        processed_df['recipients'] = processed_df['recipients'].str.lower().str.strip()
        
        # Extract hour from timestamp for after-hours analysis
        processed_df['hour'] = processed_df['time'].dt.hour
        processed_df['day_of_week'] = processed_df['time'].dt.dayofweek  # 0=Monday, 6=Sunday
        
        # Identify after-hours emails (before 8 AM or after 6 PM, weekends)
        processed_df['is_after_hours'] = (
            (processed_df['hour'] < 8) | 
            (processed_df['hour'] >= 18) | 
            (processed_df['day_of_week'] >= 5)  # Saturday or Sunday
        )
        
        # Calculate days from resignation date
        processed_df['days_from_last_working'] = (
            processed_df['time'] - processed_df['resignation_date']
        ).dt.days
        
        # Flag leavers based on leaver field and resignation date proximity
        processed_df['is_leaver'] = (
            (processed_df['leaver'].astype(str).str.lower().isin(['y', 'yes', 'true', '1'])) |
            (processed_df['days_from_last_working'].between(-7, 7))
        )
        
        # Process attachments information
        processed_df['has_attachments'] = processed_df['attachments'].notna() & (processed_df['attachments'] != '')
        
        # Extract file types from attachments
        processed_df['attachment_types'] = processed_df['attachments'].apply(self._extract_file_types)
        
        # Count recipients
        processed_df['recipient_count'] = processed_df['recipients'].apply(self._count_recipients)
        
        # Extract recipient domains from domain field or recipients
        if 'domain' in processed_df.columns:
            # Convert single domain to list format for consistency
            processed_df['recipient_domains'] = processed_df['domain'].apply(lambda x: [x] if pd.notna(x) and x != '' else [])
            processed_df['recipient_domain'] = processed_df['domain']
        else:
            processed_df['recipient_domains'] = processed_df['recipients'].apply(self._extract_domains)
            processed_df['recipient_domain'] = processed_df['recipient_domains'].apply(lambda x: x[0] if x else '')
        
        # Ensure primary recipient domain is available for classification
        processed_df['primary_recipient_domain'] = processed_df['domain']
        
        # Extract sender domain
        processed_df['sender_domain'] = processed_df['sender'].apply(lambda x: x.split('@')[-1] if '@' in str(x) else '')
        
        # Fill missing values
        processed_df['subject'] = processed_df['subject'].fillna('')
        processed_df['word_list_match'] = processed_df['word_list_match'].fillna('')
        
        return processed_df
    
    def _extract_file_types(self, attachments):
        """Extract file types from attachment string"""
        if pd.isna(attachments) or attachments == '':
            return []
        
        # Look for file extensions
        file_types = re.findall(r'\.([a-zA-Z0-9]+)', str(attachments))
        return list(set(file_types))
    
    def _count_recipients(self, recipients):
        """Count number of recipients in email"""
        if pd.isna(recipients) or recipients == '':
            return 0
        
        # Split by common separators
        recipients_list = re.split(r'[;,\s]+', str(recipients))
        return len([r for r in recipients_list if r.strip() and '@' in r])
    
    def _extract_domains(self, recipients):
        """Extract unique domains from recipients"""
        if pd.isna(recipients) or recipients == '':
            return []
        
        # Extract domains from email addresses
        email_pattern = r'[\w\.-]+@([\w\.-]+)'
        domains = re.findall(email_pattern, str(recipients))
        return list(set(domains))
    
    def calculate_email_volume_baseline(self, df, sender_col='sender', time_col='time'):
        """Calculate baseline email volume for each sender"""
        # Group by sender and calculate daily email counts
        df_temp = df.copy()
        df_temp['date'] = df_temp[time_col].dt.date
        
        daily_counts = df_temp.groupby([sender_col, 'date']).size().reset_index(name='daily_count')
        
        # Calculate baseline statistics for each sender
        baseline_stats = daily_counts.groupby(sender_col)['daily_count'].agg([
            'mean', 'std', 'median', 'max'
        ]).reset_index()
        
        baseline_stats.columns = [sender_col, 'avg_daily_emails', 'std_daily_emails', 
                                 'median_daily_emails', 'max_daily_emails']
        
        # Fill NaN std with 0
        baseline_stats['std_daily_emails'] = baseline_stats['std_daily_emails'].fillna(0)
        
        return baseline_stats
    
    def detect_volume_spikes(self, df, baseline_stats, threshold=2):
        """Detect volume spikes compared to user baseline"""
        # Calculate current day volume for each sender
        df_temp = df.copy()
        df_temp['date'] = df_temp['time'].dt.date
        
        current_volume = df_temp.groupby(['sender', 'date']).size().reset_index(name='current_count')
        
        # Merge with baseline
        volume_analysis = current_volume.merge(baseline_stats, on='sender', how='left')
        
        # Calculate z-score for volume spike detection
        volume_analysis['volume_zscore'] = np.where(
            volume_analysis['std_daily_emails'] > 0,
            (volume_analysis['current_count'] - volume_analysis['avg_daily_emails']) / volume_analysis['std_daily_emails'],
            0
        )
        
        # Flag spikes
        volume_analysis['is_volume_spike'] = volume_analysis['volume_zscore'] > threshold
        
        return volume_analysis
    
    def identify_new_domains(self, df, lookback_days=30):
        """Identify new external domains for each sender"""
        # Sort by time
        df_sorted = df.sort_values('time')
        
        # Get cutoff date
        cutoff_date = df_sorted['time'].max() - timedelta(days=lookback_days)
        
        # Split into historical and recent data
        historical_df = df_sorted[df_sorted['time'] < cutoff_date]
        recent_df = df_sorted[df_sorted['time'] >= cutoff_date]
        
        # Get historical domains for each sender
        historical_domains = {}
        for sender in historical_df['sender'].unique():
            sender_emails = historical_df[historical_df['sender'] == sender]
            domains = set()
            for recipient_domains in sender_emails['recipient_domains']:
                if isinstance(recipient_domains, list):
                    domains.update(recipient_domains)
            historical_domains[sender] = domains
        
        # Check for new domains in recent emails
        new_domain_flags = []
        for idx, row in recent_df.iterrows():
            sender = row['sender']
            recipient_domains = row.get('recipient_domains', [])
            
            if isinstance(recipient_domains, list) and sender in historical_domains:
                has_new_domain = any(domain not in historical_domains[sender] for domain in recipient_domains)
            else:
                has_new_domain = False
            
            new_domain_flags.append(has_new_domain)
        
        recent_df = recent_df.copy()
        recent_df['has_new_domain'] = new_domain_flags
        
        return recent_df
    
    def detect_burst_patterns(self, df, time_window_minutes=60, min_emails=5):
        """Detect burst patterns to same domain"""
        df_sorted = df.sort_values('time')
        burst_flags = []
        
        for idx, row in df_sorted.iterrows():
            sender = row['sender']
            email_time = row['time']
            recipient_domains = row.get('recipient_domains', [])
            
            if not isinstance(recipient_domains, list) or len(recipient_domains) == 0:
                burst_flags.append(False)
                continue
            
            # Check for burst pattern in time window
            time_start = email_time - timedelta(minutes=time_window_minutes)
            time_end = email_time + timedelta(minutes=time_window_minutes)
            
            window_emails = df_sorted[
                (df_sorted['sender'] == sender) &
                (df_sorted['time'] >= time_start) &
                (df_sorted['time'] <= time_end)
            ]
            
            is_burst = False
            for domain in recipient_domains:
                domain_count = 0
                for _, window_row in window_emails.iterrows():
                    window_domains = window_row.get('recipient_domains', [])
                    if isinstance(window_domains, list) and domain in window_domains:
                        domain_count += 1
                
                if domain_count >= min_emails:
                    is_burst = True
                    break
            
            burst_flags.append(is_burst)
        
        df_result = df_sorted.copy()
        df_result['has_burst_pattern'] = burst_flags
        
        return df_result
