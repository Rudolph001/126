import pandas as pd
import numpy as np
from datetime import datetime, timedelta

class RiskEngine:
    """Calculates risk scores based on various email patterns and behaviors"""
    
    def __init__(self):
        self.risk_weights = {
            'volume_spike': 10,
            'after_hours': 10,
            'free_email_domain': 20,
            'new_external_domain': 15,
            'unusual_attachment': 15,
            'leaver_activity': 70,  # Increased to ensure high risk classification
            'ip_keywords': 25,
            'burst_pattern': 15,
            'new_file_type': 10
        }
        
        self.risk_levels = {
            'normal': (0, 30),
            'medium': (31, 60),
            'high': (61, float('inf'))
        }
    
    def calculate_risk_scores(self, df, whitelist_df=None):
        """Calculate comprehensive risk scores for all emails"""
        risk_scores = []
        
        for idx, row in df.iterrows():
            score = self._calculate_individual_risk(row, df, whitelist_df)
            risk_scores.append(score)
        
        return np.array(risk_scores)
    
    def _calculate_individual_risk(self, email_row, full_df, whitelist_df):
        """Calculate risk score for individual email"""
        score = 0
        
        # Check if sender/recipient is whitelisted
        if self._is_whitelisted(email_row, whitelist_df):
            return 0
        
        # Volume spike detection
        if self._check_volume_spike(email_row, full_df):
            score += self.risk_weights['volume_spike']
        
        # After hours activity
        if email_row.get('is_after_hours', False):
            score += self.risk_weights['after_hours']
        
        # Free email domain recipients
        if self._check_free_email_domains(email_row):
            score += self.risk_weights['free_email_domain']
        
        # Business domain risk adjustment
        score = self._adjust_business_domain_risk(email_row, score)
        
        # New external domain
        if email_row.get('has_new_domain', False):
            score += self.risk_weights['new_external_domain']
        
        # Unusual attachments
        if self._check_unusual_attachments(email_row):
            score += self.risk_weights['unusual_attachment']
        
        # Leaver activity - check for last_working_day field
        if email_row.get('is_leaver', False) or pd.notna(email_row.get('last_working_day')):
            score += self.risk_weights['leaver_activity']
        
        # IP keywords
        if self._check_ip_keywords(email_row):
            score += self.risk_weights['ip_keywords']
        
        # Burst pattern
        if email_row.get('has_burst_pattern', False):
            score += self.risk_weights['burst_pattern']
        
        # New file type
        if self._check_new_file_type(email_row, full_df):
            score += self.risk_weights['new_file_type']
        
        return score
    
    def _is_whitelisted(self, email_row, whitelist_df):
        """Check if email sender or recipients are whitelisted"""
        if whitelist_df is None or whitelist_df.empty:
            return False
        
        sender = email_row.get('sender', '')
        recipients = email_row.get('recipients', '')
        recipient_domains = email_row.get('recipient_domains', [])
        
        # Check sender email
        if sender in whitelist_df['email_address'].values:
            return True
        
        # Check sender domain
        sender_domain = sender.split('@')[-1] if '@' in sender else ''
        if sender_domain in whitelist_df['domain'].values:
            return True
        
        # Check recipient domains
        if isinstance(recipient_domains, list):
            for domain in recipient_domains:
                if domain in whitelist_df['domain'].values:
                    return True
        
        return False
    
    def _check_volume_spike(self, email_row, full_df):
        """Check for volume spike compared to sender's baseline"""
        sender = email_row.get('sender', '')
        email_date = email_row.get('time')
        
        if pd.isna(email_date) or sender == '':
            return False
        
        # Get sender's historical email count
        sender_emails = full_df[full_df['sender'] == sender]
        
        if len(sender_emails) < 5:  # Need minimum history
            return False
        
        # Calculate daily email counts
        sender_emails = sender_emails.copy()
        sender_emails.loc[:, 'date'] = sender_emails['time'].dt.date
        daily_counts = sender_emails.groupby('date').size()
        
        if len(daily_counts) < 3:  # Need minimum days of history
            return False
        
        # Current day count
        current_date = email_date.date()
        current_count = daily_counts.get(current_date, 0)
        
        # Historical average (excluding current day)
        historical_counts = daily_counts[daily_counts.index != current_date]
        avg_count = historical_counts.mean()
        std_count = historical_counts.std()
        
        # Consider it a spike if current count > mean + 2*std
        threshold = avg_count + 2 * (std_count if not pd.isna(std_count) else avg_count * 0.5)
        
        return current_count > threshold
    
    def _check_free_email_domains(self, email_row):
        """Check if recipients include free email domains"""
        free_domains = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
            'icloud.com', 'protonmail.com', 'mail.com', 'yandex.com', 'zoho.com'
        }
        
        recipient_domains = email_row.get('recipient_domains', [])
        
        if isinstance(recipient_domains, list):
            return any(domain.lower() in free_domains for domain in recipient_domains)
        
        return False
    
    def _check_unusual_attachments(self, email_row):
        """Check for unusual or risky attachment types"""
        risky_extensions = {
            'exe', 'bat', 'cmd', 'com', 'pif', 'scr', 'vbs', 'js', 'jar',
            'zip', 'rar', '7z', 'sql', 'db', 'mdb', 'accdb'
        }
        
        large_file_threshold = 50  # MB (simplified check)
        
        attachment_types = email_row.get('attachment_types', [])
        
        if isinstance(attachment_types, list):
            # Check for risky file types
            if any(ext.lower() in risky_extensions for ext in attachment_types):
                return True
        
        # Check for large attachments (simplified)
        attachments = str(email_row.get('attachments', ''))
        if 'large' in attachments.lower() or 'mb' in attachments.lower():
            return True
        
        return False
    
    def _check_ip_keywords(self, email_row):
        """Check for intellectual property keywords"""
        ip_keywords = [
            'confidential', 'proprietary', 'trade secret', 'internal',
            'restricted', 'sensitive', 'classified', 'private',
            'financial', 'budget', 'salary', 'compensation', 'contract',
            'agreement', 'legal', 'patent', 'copyright', 'source code',
            'database', 'customer list', 'pricing', 'strategy'
        ]
        
        # Check subject line
        subject = str(email_row.get('subject', '')).lower()
        
        # Check word list matches (if available)
        word_matches = str(email_row.get('word_list_match', '')).lower()
        
        # Check attachments description
        attachments = str(email_row.get('attachments', '')).lower()
        
        combined_text = f"{subject} {word_matches} {attachments}"
        
        return any(keyword in combined_text for keyword in ip_keywords)
    
    def _check_new_file_type(self, email_row, full_df):
        """Check if sender is using new file types"""
        sender = email_row.get('sender', '')
        current_types = email_row.get('attachment_types', [])
        
        if not isinstance(current_types, list) or len(current_types) == 0:
            return False
        
        # Get sender's historical file types
        sender_emails = full_df[full_df['sender'] == sender]
        
        if len(sender_emails) < 5:  # Need minimum history
            return False
        
        historical_types = set()
        for _, row in sender_emails.iterrows():
            types = row.get('attachment_types', [])
            if isinstance(types, list):
                historical_types.update(types)
        
        # Check if any current type is new
        return any(file_type not in historical_types for file_type in current_types)
    
    def _adjust_business_domain_risk(self, email_row, current_score):
        """Adjust risk score for business domains based on IP keyword presence"""
        recipient_domains = email_row.get('recipient_domains', [])
        domain_type = email_row.get('domain_type', '')
        
        # Check if this is a business domain
        if domain_type == 'business' or (isinstance(recipient_domains, list) and 
                                       any('business' in str(domain).lower() for domain in recipient_domains)):
            
            # Check if it contains IP keywords
            has_ip_keywords = self._check_ip_keywords(email_row)
            
            if not has_ip_keywords:
                # Business domain without IP keywords - reduce risk significantly
                reduction = min(current_score * 0.3, 25)  # Reduce by 30% or max 25 points
                return max(current_score - reduction, 10)  # Minimum score of 10 for business domains
            else:
                # Business domain with IP keywords - keep at medium risk level
                # Ensure score stays in medium range (31-60)
                if current_score > 60:
                    return 55  # Cap at medium-high
                elif current_score < 31:
                    return 35  # Minimum medium risk
        
        return current_score
    
    def get_risk_level(self, score):
        """Convert risk score to risk level"""
        if score <= self.risk_levels['normal'][1]:
            return 'Normal'
        elif score <= self.risk_levels['medium'][1]:
            return 'Medium Risk'
        else:
            return 'High Risk'
    
    def get_risk_breakdown(self, email_row, full_df, whitelist_df=None):
        """Get detailed breakdown of risk factors for an email"""
        breakdown = {
            'total_score': 0,
            'factors': []
        }
        
        # Check each risk factor
        if self._is_whitelisted(email_row, whitelist_df):
            breakdown['factors'].append({
                'factor': 'Whitelisted',
                'score': 0,
                'description': 'Sender or recipient is whitelisted'
            })
            return breakdown
        
        if self._check_volume_spike(email_row, full_df):
            breakdown['total_score'] += self.risk_weights['volume_spike']
            breakdown['factors'].append({
                'factor': 'Volume Spike',
                'score': self.risk_weights['volume_spike'],
                'description': 'Email volume above sender baseline'
            })
        
        if email_row.get('is_after_hours', False):
            breakdown['total_score'] += self.risk_weights['after_hours']
            breakdown['factors'].append({
                'factor': 'After Hours',
                'score': self.risk_weights['after_hours'],
                'description': 'Email sent outside business hours'
            })
        
        if self._check_free_email_domains(email_row):
            breakdown['total_score'] += self.risk_weights['free_email_domain']
            breakdown['factors'].append({
                'factor': 'Free Email Domain',
                'score': self.risk_weights['free_email_domain'],
                'description': 'Recipients include free email providers'
            })
        
        # Apply business domain risk adjustment
        original_score = breakdown['total_score']
        breakdown['total_score'] = self._adjust_business_domain_risk(email_row, breakdown['total_score'])
        
        if breakdown['total_score'] != original_score:
            domain_type = email_row.get('domain_type', '')
            has_ip_keywords = self._check_ip_keywords(email_row)
            
            if domain_type == 'business' and not has_ip_keywords:
                adjustment = breakdown['total_score'] - original_score
                breakdown['factors'].append({
                    'factor': 'Business Domain (No IP Keywords)',
                    'score': adjustment,
                    'description': 'Risk reduced for business domain without sensitive keywords'
                })
            elif domain_type == 'business' and has_ip_keywords:
                breakdown['factors'].append({
                    'factor': 'Business Domain (With IP Keywords)',
                    'score': 0,
                    'description': 'Business domain with IP keywords - maintained at medium risk level'
                })
        
        if email_row.get('has_new_domain', False):
            breakdown['total_score'] += self.risk_weights['new_external_domain']
            breakdown['factors'].append({
                'factor': 'New External Domain',
                'score': self.risk_weights['new_external_domain'],
                'description': 'First time sending to this domain'
            })
        
        if self._check_unusual_attachments(email_row):
            breakdown['total_score'] += self.risk_weights['unusual_attachment']
            breakdown['factors'].append({
                'factor': 'Unusual Attachment',
                'score': self.risk_weights['unusual_attachment'],
                'description': 'Risky or large attachment detected'
            })
        
        if email_row.get('is_leaver', False) or pd.notna(email_row.get('last_working_day')):
            breakdown['total_score'] += self.risk_weights['leaver_activity']
            breakdown['factors'].append({
                'factor': 'Leaver Activity',
                'score': self.risk_weights['leaver_activity'],
                'description': 'Email from employee with last working day recorded - HIGH PRIORITY'
            })
        
        if self._check_ip_keywords(email_row):
            breakdown['total_score'] += self.risk_weights['ip_keywords']
            breakdown['factors'].append({
                'factor': 'IP Keywords',
                'score': self.risk_weights['ip_keywords'],
                'description': 'Sensitive keywords detected'
            })
        
        if email_row.get('has_burst_pattern', False):
            breakdown['total_score'] += self.risk_weights['burst_pattern']
            breakdown['factors'].append({
                'factor': 'Burst Pattern',
                'score': self.risk_weights['burst_pattern'],
                'description': 'Multiple emails to same domain in short time'
            })
        
        if self._check_new_file_type(email_row, full_df):
            breakdown['total_score'] += self.risk_weights['new_file_type']
            breakdown['factors'].append({
                'factor': 'New File Type',
                'score': self.risk_weights['new_file_type'],
                'description': 'Sender using new file type'
            })
        
        return breakdown
