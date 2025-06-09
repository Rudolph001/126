import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import re

class RiskEngine:
    """Calculates risk scores for email security analysis"""
    
    def __init__(self):
        self.free_email_domains = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
            'icloud.com', 'protonmail.com', 'mail.com', 'yandex.com', 'zoho.com'
        }
        
        self.high_risk_keywords = [
            'confidential', 'proprietary', 'internal', 'restricted', 'classified',
            'financial', 'salary', 'budget', 'revenue', 'profit', 'loss',
            'customer', 'client', 'patent', 'trademark', 'copyright',
            'password', 'login', 'credential', 'token', 'api key'
        ]
        
    def calculate_risk_scores(self, df, whitelist_df=None):
        """Calculate risk scores for all emails"""
        if df.empty:
            return []
            
        risk_scores = []
        
        for idx, row in df.iterrows():
            score = self._calculate_individual_risk(row, df, whitelist_df)
            risk_scores.append(score)
            
        return risk_scores
    
    def _calculate_individual_risk(self, row, full_df, whitelist_df=None):
        """Calculate risk score for individual email"""
        risk_score = 0
        
        # Base risk assessment
        risk_score += self._assess_domain_risk(row)
        risk_score += self._assess_content_risk(row)
        risk_score += self._assess_attachment_risk(row)
        risk_score += self._assess_timing_risk(row)
        risk_score += self._assess_recipient_risk(row)
        risk_score += self._assess_leaver_risk(row)
        risk_score += self._assess_volume_risk(row, full_df)
        
        # Apply whitelist filtering
        if whitelist_df is not None and not whitelist_df.empty:
            if self._is_whitelisted(row, whitelist_df):
                risk_score = max(0, risk_score - 30)  # Reduce risk for whitelisted
        
        return min(100, max(0, risk_score))  # Clamp between 0-100
    
    def _assess_domain_risk(self, row):
        """Assess risk based on email domains"""
        risk = 0
        
        # Sender domain risk
        sender = row.get('sender', '')
        if sender:
            sender_domain = self._extract_domain(sender)
            if sender_domain.lower() in self.free_email_domains:
                risk += 25
        
        # Recipient domain risk
        recipients = row.get('recipients', '')
        if recipients:
            recipient_domains = self._extract_recipient_domains(recipients)
            for domain in recipient_domains:
                if domain.lower() in self.free_email_domains:
                    risk += 15
                    break  # Don't double-count
        
        return risk
    
    def _assess_content_risk(self, row):
        """Assess risk based on email content"""
        risk = 0
        
        # Check subject for keywords
        subject = str(row.get('subject', '')).lower()
        for keyword in self.high_risk_keywords:
            if keyword in subject:
                risk += 10
                break
        
        # Check word list matches
        word_match = row.get('word_list_match', '')
        if pd.notna(word_match) and str(word_match).strip():
            risk += 20
        
        return risk
    
    def _assess_attachment_risk(self, row):
        """Assess risk based on attachments"""
        risk = 0
        
        attachments = row.get('attachments', '')
        if pd.notna(attachments) and str(attachments).strip() and str(attachments) != '0':
            risk += 15
            
            # Higher risk for certain file types
            attachment_str = str(attachments).lower()
            high_risk_extensions = ['.zip', '.rar', '.exe', '.bat', '.pdf', '.docx', '.xlsx']
            for ext in high_risk_extensions:
                if ext in attachment_str:
                    risk += 10
                    break
        
        return risk
    
    def _assess_timing_risk(self, row):
        """Assess risk based on email timing"""
        risk = 0
        
        # Check if email was sent after hours
        time_val = row.get('time', '')
        if pd.notna(time_val):
            try:
                # Try to parse time and check if after hours
                if isinstance(time_val, str):
                    # Simple heuristic for after hours (evening/night/weekend)
                    time_lower = time_val.lower()
                    if any(indicator in time_lower for indicator in ['pm', 'night', 'evening', 'weekend']):
                        risk += 10
            except:
                pass
        
        return risk
    
    def _assess_recipient_risk(self, row):
        """Assess risk based on recipient patterns"""
        risk = 0
        
        recipients = row.get('recipients', '')
        if recipients:
            # Multiple external recipients
            recipient_count = len(str(recipients).split(','))
            if recipient_count > 5:
                risk += 15
            elif recipient_count > 2:
                risk += 10
        
        return risk
    
    def _assess_leaver_risk(self, row):
        """Assess risk based on leaver status"""
        risk = 0
        
        last_working_day = row.get('last_working_day', '')
        if pd.notna(last_working_day) and str(last_working_day).strip():
            risk += 30  # High risk for departing employees
        
        return risk
    
    def _assess_volume_risk(self, row, full_df):
        """Assess risk based on email volume patterns"""
        risk = 0
        
        sender = row.get('sender', '')
        if sender and len(full_df) > 1:
            # Count emails from same sender
            sender_emails = full_df[full_df['sender'] == sender]
            if len(sender_emails) > 10:  # High volume sender
                risk += 10
        
        return risk
    
    def _is_whitelisted(self, row, whitelist_df):
        """Check if email is whitelisted"""
        if whitelist_df.empty:
            return False
            
        sender = row.get('sender', '')
        if not sender:
            return False
            
        sender_domain = self._extract_domain(sender)
        
        # Check email address whitelist
        if sender in whitelist_df.get('email_address', []):
            return True
            
        # Check domain whitelist
        if sender_domain in whitelist_df.get('domain', []):
            return True
            
        return False
    
    def _extract_domain(self, email):
        """Extract domain from email address"""
        if '@' in str(email):
            return str(email).split('@')[1].strip().lower()
        return ''
    
    def _extract_recipient_domains(self, recipients):
        """Extract domains from recipients string"""
        domains = set()
        if recipients:
            emails = str(recipients).split(',')
            for email in emails:
                domain = self._extract_domain(email.strip())
                if domain:
                    domains.add(domain)
        return list(domains)
    
    def get_risk_level(self, score):
        """Convert risk score to risk level"""
        if score >= 61:
            return 'High Risk'
        elif score >= 31:
            return 'Medium Risk'
        else:
            return 'Low Risk'
    
    def analyze_risk_factors(self, df):
        """Analyze and return risk factor statistics"""
        if df.empty or 'risk_score' not in df.columns:
            return {}
            
        risk_factors = {
            'total_emails': len(df),
            'high_risk_count': len(df[df['risk_score'] >= 61]),
            'medium_risk_count': len(df[(df['risk_score'] >= 31) & (df['risk_score'] < 61)]),
            'low_risk_count': len(df[df['risk_score'] < 31]),
            'avg_risk_score': df['risk_score'].mean(),
            'max_risk_score': df['risk_score'].max(),
            'min_risk_score': df['risk_score'].min()
        }
        
        return risk_factors