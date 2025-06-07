import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import re
from collections import Counter
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

class BAUAnalyzer:
    """Analyzes Business-as-Usual patterns and detects IP exfiltration in Low Risk emails"""
    
    def __init__(self):
        self.banking_keywords = [
            'financial', 'banking', 'credit', 'loan', 'investment', 'portfolio',
            'transaction', 'account', 'balance', 'statement', 'audit', 'compliance',
            'regulatory', 'risk', 'capital', 'asset', 'liability', 'derivative',
            'trading', 'securities', 'bonds', 'equity', 'forex', 'swift',
            'ach', 'wire', 'payment', 'settlement', 'clearing', 'aml', 'kyc',
            'basel', 'sarbanes', 'dodd-frank', 'mifid', 'gdpr', 'pci'
        ]
        
        self.ip_indicators = [
            'confidential', 'proprietary', 'trade secret', 'internal only',
            'restricted', 'sensitive', 'classified', 'non-disclosure',
            'algorithm', 'methodology', 'process', 'procedure', 'workflow',
            'strategy', 'roadmap', 'plan', 'forecast', 'projection',
            'client list', 'customer data', 'pricing', 'cost structure',
            'competitive', 'advantage', 'innovation', 'patent', 'copyright'
        ]
        
        self.business_hours = (9, 17)  # 9 AM to 5 PM
        self.business_days = [0, 1, 2, 3, 4]  # Monday to Friday
    
    def analyze_low_risk_patterns(self, df):
        """Comprehensive analysis of Low Risk email patterns"""
        # Filter for Low Risk emails only
        if 'risk_level' in df.columns:
            low_risk_df = df[df['risk_level'] == 'Low'].copy()
        else:
            # If no risk_level column, use all data for analysis
            low_risk_df = df.copy()
        
        if low_risk_df.empty:
            return {
                'bau_patterns': {},
                'anomalies': pd.DataFrame(),
                'banking_analysis': {},
                'ip_risks': pd.DataFrame(),
                'recommendations': []
            }
        
        # Convert timestamp if needed
        if 'time' in low_risk_df.columns:
            low_risk_df['time'] = pd.to_datetime(low_risk_df['time'])
            low_risk_df['hour'] = low_risk_df['time'].dt.hour
            low_risk_df['day_of_week'] = low_risk_df['time'].dt.dayofweek
            low_risk_df['is_business_hours'] = (
                (low_risk_df['hour'] >= self.business_hours[0]) & 
                (low_risk_df['hour'] <= self.business_hours[1]) &
                (low_risk_df['day_of_week'].isin(self.business_days))
            )
        
        analysis = {
            'bau_patterns': self._identify_bau_patterns(low_risk_df),
            'anomalies': self._detect_low_risk_anomalies(low_risk_df),
            'banking_analysis': self._analyze_banking_context(low_risk_df),
            'ip_risks': self._detect_hidden_ip_risks(low_risk_df),
            'recommendations': self._generate_recommendations(low_risk_df)
        }
        
        return analysis
    
    def _identify_bau_patterns(self, df):
        """Identify typical business-as-usual patterns"""
        patterns = {}
        
        # Temporal patterns
        if 'time' in df.columns and not df.empty:
            patterns['temporal'] = {
                'business_hours_percentage': (df['is_business_hours'].sum() / len(df)) * 100,
                'peak_hours': df.groupby('hour').size().idxmax() if len(df) > 0 else None,
                'daily_volume': df.groupby(df['time'].dt.date).size().describe().to_dict(),
                'weekly_pattern': df.groupby('day_of_week').size().to_dict()
            }
        
        # Communication patterns
        if 'sender' in df.columns:
            sender_stats = df['sender'].value_counts()
            patterns['communication'] = {
                'regular_senders': sender_stats.head(10).to_dict(),
                'sender_distribution': {
                    'total_unique_senders': len(sender_stats),
                    'avg_emails_per_sender': sender_stats.mean(),
                    'top_sender_dominance': (sender_stats.iloc[0] / len(df)) * 100 if len(sender_stats) > 0 else 0
                }
            }
        
        # Content patterns
        if 'subject' in df.columns:
            subject_keywords = self._extract_common_keywords(df['subject'].dropna())
            patterns['content'] = {
                'common_subject_keywords': subject_keywords[:20],
                'subject_length_stats': df['subject'].str.len().describe().to_dict()
            }
        
        # Domain patterns
        if 'recipient_domains' in df.columns:
            domain_analysis = self._analyze_domain_patterns(df)
            patterns['domains'] = domain_analysis
        
        return patterns
    
    def _detect_low_risk_anomalies(self, df):
        """Detect anomalies within low-risk emails that might indicate hidden threats"""
        anomalies = []
        
        # Volume anomalies in low-risk emails
        if 'time' in df.columns and len(df) > 1:
            daily_volumes = df.groupby(df['time'].dt.date).size()
            volume_threshold = daily_volumes.quantile(0.95)
            high_volume_days = daily_volumes[daily_volumes > volume_threshold]
            
            for date, volume in high_volume_days.items():
                anomalies.append({
                    'type': 'Volume Spike',
                    'date': date,
                    'value': volume,
                    'description': f'Unusually high volume of low-risk emails: {volume} emails',
                    'severity': 'Medium'
                })
        
        # Off-hours activity in low-risk emails
        if 'is_business_hours' in df.columns:
            off_hours_emails = df[~df['is_business_hours']]
            if len(off_hours_emails) > len(df) * 0.1:  # More than 10% off-hours
                anomalies.append({
                    'type': 'Off-Hours Activity',
                    'count': len(off_hours_emails),
                    'percentage': (len(off_hours_emails) / len(df)) * 100,
                    'description': f'{len(off_hours_emails)} low-risk emails sent outside business hours',
                    'severity': 'Low'
                })
        
        # Unusual attachment patterns
        if 'attachments' in df.columns:
            attachment_anomalies = self._detect_attachment_anomalies(df)
            anomalies.extend(attachment_anomalies)
        
        return pd.DataFrame(anomalies)
    
    def _analyze_banking_context(self, df):
        """Analyze banking-specific patterns in low-risk emails"""
        banking_analysis = {}
        
        # Identify banking-related emails
        banking_emails = self._identify_banking_emails(df)
        
        if not banking_emails.empty:
            banking_analysis['overview'] = {
                'total_banking_emails': len(banking_emails),
                'percentage_of_low_risk': (len(banking_emails) / len(df)) * 100,
                'banking_keywords_found': self._get_banking_keywords_in_data(banking_emails)
            }
            
            # Analyze banking email patterns
            banking_analysis['patterns'] = self._analyze_banking_patterns(banking_emails)
            
            # Risk assessment for banking emails
            banking_analysis['risk_assessment'] = self._assess_banking_risks(banking_emails)
        
        return banking_analysis
    
    def _detect_hidden_ip_risks(self, df):
        """Detect potential IP risks hidden in low-risk emails"""
        ip_risks = []
        
        # Text analysis for IP indicators
        text_columns = ['subject', 'body'] if 'body' in df.columns else ['subject']
        
        for idx, row in df.iterrows():
            risk_score = 0
            risk_factors = []
            
            # Analyze text content
            combined_text = ' '.join([str(row.get(col, '')) for col in text_columns]).lower()
            
            # Check for IP keywords
            ip_matches = [kw for kw in self.ip_indicators if kw in combined_text]
            if ip_matches:
                risk_score += len(ip_matches) * 2
                risk_factors.append(f"IP keywords: {', '.join(ip_matches[:3])}")
            
            # Check for financial + confidential combination
            banking_matches = [kw for kw in self.banking_keywords if kw in combined_text]
            if banking_matches and ip_matches:
                risk_score += 5
                risk_factors.append("Banking + Confidential content combination")
            
            # Check attachment patterns
            if pd.notna(row.get('attachments', '')):
                attachment_risk = self._assess_attachment_ip_risk(row['attachments'])
                risk_score += attachment_risk['score']
                if attachment_risk['factors']:
                    risk_factors.extend(attachment_risk['factors'])
            
            # Check for unusual recipients in banking context
            if banking_matches and 'recipient_domains' in row:
                domain_risk = self._assess_domain_risk_banking(row['recipient_domains'])
                risk_score += domain_risk
                if domain_risk > 0:
                    risk_factors.append("Banking content to external domains")
            
            if risk_score > 3:  # Threshold for flagging
                ip_risks.append({
                    'email_index': idx,
                    'sender': row.get('sender', ''),
                    'subject': row.get('subject', ''),
                    'time': row.get('time', ''),
                    'risk_score': risk_score,
                    'risk_factors': risk_factors,
                    'banking_keywords': banking_matches[:5],
                    'ip_keywords': ip_matches[:5]
                })
        
        return pd.DataFrame(ip_risks)
    
    def _identify_banking_emails(self, df):
        """Identify emails related to banking/financial sector"""
        banking_mask = pd.Series([False] * len(df), index=df.index)
        
        text_columns = ['subject']
        if 'body' in df.columns:
            text_columns.append('body')
        
        for col in text_columns:
            if col in df.columns:
                for keyword in self.banking_keywords:
                    banking_mask |= df[col].str.contains(keyword, case=False, na=False)
        
        return df[banking_mask]
    
    def _get_banking_keywords_in_data(self, banking_df):
        """Get banking keywords found in the data"""
        found_keywords = []
        text_columns = ['subject', 'body'] if 'body' in banking_df.columns else ['subject']
        
        combined_text = ' '.join([
            ' '.join(banking_df[col].dropna().astype(str).str.lower())
            for col in text_columns
        ])
        
        for keyword in self.banking_keywords:
            if keyword in combined_text:
                found_keywords.append(keyword)
        
        return found_keywords
    
    def _analyze_banking_patterns(self, banking_df):
        """Analyze patterns in banking-related emails"""
        patterns = {}
        
        if 'time' in banking_df.columns and not banking_df.empty:
            patterns['temporal'] = {
                'business_hours_compliance': (banking_df['is_business_hours'].sum() / len(banking_df)) * 100,
                'peak_banking_hours': banking_df.groupby('hour').size().idxmax(),
                'weekend_banking_activity': len(banking_df[banking_df['day_of_week'].isin([5, 6])])
            }
        
        if 'sender' in banking_df.columns:
            patterns['senders'] = {
                'unique_banking_senders': banking_df['sender'].nunique(),
                'top_banking_senders': banking_df['sender'].value_counts().head(5).to_dict()
            }
        
        return patterns
    
    def _assess_banking_risks(self, banking_df):
        """Assess risks in banking-related emails"""
        risks = {
            'compliance_risks': [],
            'data_protection_risks': [],
            'operational_risks': []
        }
        
        # Check for compliance-related content
        compliance_keywords = ['audit', 'regulatory', 'compliance', 'sox', 'basel', 'aml', 'kyc']
        for idx, row in banking_df.iterrows():
            subject = str(row.get('subject', '')).lower()
            
            if any(kw in subject for kw in compliance_keywords):
                if 'external' in str(row.get('recipient_domains', '')):
                    risks['compliance_risks'].append({
                        'email_index': idx,
                        'concern': 'Compliance content sent externally',
                        'subject': row.get('subject', '')
                    })
        
        return risks
    
    def _assess_attachment_ip_risk(self, attachments_str):
        """Assess IP risk in attachments"""
        if pd.isna(attachments_str):
            return {'score': 0, 'factors': []}
        
        risk_score = 0
        risk_factors = []
        
        # High-risk file types for IP
        high_risk_types = ['.doc', '.docx', '.xls', '.xlsx', '.pdf', '.ppt', '.pptx', '.zip', '.rar']
        sensitive_patterns = ['confidential', 'internal', 'proprietary', 'strategy', 'plan']
        
        attachments_lower = attachments_str.lower()
        
        for file_type in high_risk_types:
            if file_type in attachments_lower:
                risk_score += 1
        
        for pattern in sensitive_patterns:
            if pattern in attachments_lower:
                risk_score += 2
                risk_factors.append(f"Sensitive filename pattern: {pattern}")
        
        return {'score': risk_score, 'factors': risk_factors}
    
    def _assess_domain_risk_banking(self, domains_str):
        """Assess domain risk for banking content"""
        if pd.isna(domains_str):
            return 0
        
        # Simple risk scoring for external domains with banking content
        external_indicators = ['gmail', 'yahoo', 'hotmail', 'outlook']
        domains_lower = str(domains_str).lower()
        
        return sum(2 for indicator in external_indicators if indicator in domains_lower)
    
    def _detect_attachment_anomalies(self, df):
        """Detect unusual attachment patterns in low-risk emails"""
        anomalies = []
        
        if 'attachments' in df.columns:
            # Emails with many attachments
            df['attachment_count'] = df['attachments'].str.count(r'\.[a-zA-Z]+').fillna(0)
            high_attachment_threshold = df['attachment_count'].quantile(0.95)
            
            high_attachment_emails = df[df['attachment_count'] > high_attachment_threshold]
            
            for idx, row in high_attachment_emails.iterrows():
                anomalies.append({
                    'type': 'High Attachment Count',
                    'email_index': idx,
                    'sender': row.get('sender', ''),
                    'attachment_count': row['attachment_count'],
                    'description': f'Low-risk email with unusually high attachment count: {row["attachment_count"]}',
                    'severity': 'Medium'
                })
        
        return anomalies
    
    def _extract_common_keywords(self, text_series):
        """Extract common keywords from text"""
        if text_series.empty:
            return []
        
        # Simple keyword extraction
        all_text = ' '.join(text_series.astype(str).str.lower())
        words = re.findall(r'\b\w+\b', all_text)
        
        # Filter out common stop words
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should'}
        filtered_words = [word for word in words if word not in stop_words and len(word) > 2]
        
        return [word for word, count in Counter(filtered_words).most_common(50)]
    
    def _analyze_domain_patterns(self, df):
        """Analyze domain communication patterns"""
        domain_patterns = {}
        
        if 'recipient_domains' in df.columns:
            # Extract all domains
            all_domains = []
            for domains_str in df['recipient_domains'].dropna():
                if isinstance(domains_str, str):
                    all_domains.extend(domains_str.split(','))
            
            domain_counts = Counter([d.strip() for d in all_domains if d.strip()])
            
            domain_patterns = {
                'most_common_domains': dict(domain_counts.most_common(10)),
                'total_unique_domains': len(domain_counts),
                'domain_distribution': {
                    'internal': sum(1 for d in domain_counts if self._is_likely_internal(d)),
                    'external': sum(1 for d in domain_counts if not self._is_likely_internal(d))
                }
            }
        
        return domain_patterns
    
    def _is_likely_internal(self, domain):
        """Simple heuristic to identify internal domains"""
        internal_indicators = ['.local', '.internal', '.corp', '.company']
        return any(indicator in domain.lower() for indicator in internal_indicators)
    
    def _generate_recommendations(self, df):
        """Generate recommendations based on analysis"""
        recommendations = []
        
        # Business hours compliance
        if 'is_business_hours' in df.columns:
            off_hours_pct = (1 - df['is_business_hours'].mean()) * 100
            if off_hours_pct > 20:
                recommendations.append({
                    'category': 'Operational Security',
                    'priority': 'Medium',
                    'recommendation': f'Monitor off-hours activity: {off_hours_pct:.1f}% of low-risk emails sent outside business hours',
                    'action': 'Review after-hours email policies and monitoring'
                })
        
        # Banking content recommendations
        banking_emails = self._identify_banking_emails(df)
        if not banking_emails.empty:
            recommendations.append({
                'category': 'Financial Data Protection',
                'priority': 'High',
                'recommendation': f'Found {len(banking_emails)} banking-related emails in low-risk category',
                'action': 'Implement enhanced monitoring for financial content'
            })
        
        # IP content recommendations
        ip_risks = self._detect_hidden_ip_risks(df)
        if not ip_risks.empty:
            recommendations.append({
                'category': 'Intellectual Property',
                'priority': 'High',
                'recommendation': f'Detected {len(ip_risks)} potentially sensitive emails in low-risk category',
                'action': 'Review classification rules and implement content-based risk scoring'
            })
        
        return recommendations

    def create_bau_dashboard_charts(self, analysis_results):
        """Create visualizations for BAU analysis dashboard"""
        charts = {}
        
        # BAU Patterns Overview
        if analysis_results.get('bau_patterns', {}).get('temporal'):
            temporal = analysis_results['bau_patterns']['temporal']
            
            # Business hours compliance chart
            fig_hours = go.Figure(data=[
                go.Bar(
                    x=['Business Hours', 'Off Hours'],
                    y=[temporal['business_hours_percentage'], 100 - temporal['business_hours_percentage']],
                    marker_color=['green', 'orange']
                )
            ])
            fig_hours.update_layout(
                title='Email Activity: Business Hours vs Off Hours',
                yaxis_title='Percentage',
                showlegend=False
            )
            charts['business_hours'] = fig_hours
            
            # Weekly pattern chart
            if 'weekly_pattern' in temporal:
                days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
                weekly_data = [temporal['weekly_pattern'].get(i, 0) for i in range(7)]
                
                fig_weekly = go.Figure(data=[
                    go.Bar(x=days, y=weekly_data, marker_color='lightblue')
                ])
                fig_weekly.update_layout(
                    title='Weekly Email Pattern',
                    xaxis_title='Day of Week',
                    yaxis_title='Email Count'
                )
                charts['weekly_pattern'] = fig_weekly
        
        # Banking Analysis Chart
        if analysis_results.get('banking_analysis', {}).get('overview'):
            banking = analysis_results['banking_analysis']['overview']
            
            fig_banking = go.Figure(data=[
                go.Pie(
                    labels=['Banking Related', 'Other Low Risk'],
                    values=[banking['total_banking_emails'], 
                           banking.get('total_low_risk', 100) - banking['total_banking_emails']],
                    hole=0.3
                )
            ])
            fig_banking.update_layout(title='Banking Content in Low Risk Emails')
            charts['banking_distribution'] = fig_banking
        
        # IP Risk Heatmap
        if not analysis_results.get('ip_risks', pd.DataFrame()).empty:
            ip_risks = analysis_results['ip_risks']
            
            # Create risk score distribution
            fig_ip = px.histogram(
                ip_risks, 
                x='risk_score', 
                title='Distribution of Hidden IP Risk Scores',
                labels={'risk_score': 'Risk Score', 'count': 'Number of Emails'}
            )
            charts['ip_risk_distribution'] = fig_ip
        
        return charts