import pandas as pd
import re
import string
from typing import List, Dict, Set

class KeywordDetector:
    """Detects sensitive keywords (IP) in email content for data exfiltration prevention"""
    
    def __init__(self):
        # Intellectual Property and sensitive keywords
        self.ip_keywords = {
            # Confidentiality levels
            'confidential', 'proprietary', 'trade secret', 'internal only',
            'restricted', 'sensitive', 'classified', 'private', 'secret',
            'top secret', 'eyes only', 'need to know',
            
            # Financial information
            'financial', 'budget', 'salary', 'compensation', 'payroll',
            'revenue', 'profit', 'loss', 'earnings', 'invoice', 'payment',
            'banking', 'account number', 'routing number', 'credit card',
            'ssn', 'social security', 'tax id', 'ein',
            
            # Legal and contracts
            'contract', 'agreement', 'legal', 'lawsuit', 'litigation',
            'settlement', 'nda', 'non-disclosure', 'non-compete',
            'intellectual property', 'patent', 'copyright', 'trademark',
            'license', 'licensing', 'royalty',
            
            # Technical and development
            'source code', 'algorithm', 'database', 'schema', 'api key',
            'password', 'credentials', 'access token', 'private key',
            'encryption key', 'certificate', 'vulnerability', 'exploit',
            'backdoor', 'security flaw',
            
            # Business intelligence
            'customer list', 'client list', 'prospect list', 'pricing',
            'strategy', 'roadmap', 'business plan', 'market research',
            'competitive analysis', 'merger', 'acquisition', 'due diligence',
            
            # Personal data
            'personal data', 'pii', 'personally identifiable', 'gdpr',
            'ccpa', 'hipaa', 'medical record', 'health information',
            'date of birth', 'drivers license', 'passport',
            
            # Project and product information
            'unreleased', 'unannounced', 'upcoming', 'beta', 'alpha',
            'prototype', 'experimental', 'research', 'development',
            'pre-launch', 'embargo', 'insider information'
        }
        
        # File types that commonly contain sensitive information
        self.sensitive_file_types = {
            'doc', 'docx', 'pdf', 'xls', 'xlsx', 'ppt', 'pptx',
            'txt', 'rtf', 'csv', 'sql', 'db', 'mdb', 'accdb',
            'zip', 'rar', '7z', 'tar', 'gz'
        }
        
        # Patterns for detecting structured sensitive data
        self.sensitive_patterns = {
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b',
            'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            'phone': r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'api_key': r'\b[A-Za-z0-9]{32,}\b',
            'guid': r'\b[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\b'
        }
        
        # Industry-specific keywords
        self.industry_keywords = {
            'healthcare': ['patient', 'medical', 'diagnosis', 'treatment', 'prescription', 'phi'],
            'finance': ['account', 'balance', 'transaction', 'investment', 'portfolio', 'trading'],
            'legal': ['attorney', 'lawyer', 'court', 'judge', 'case', 'evidence', 'witness'],
            'hr': ['employee', 'performance', 'review', 'termination', 'hiring', 'benefits']
        }
    
    def detect_keywords(self, df):
        """Detect sensitive keywords in email data"""
        df_copy = df.copy()
        
        # Initialize keyword detection columns
        df_copy['has_ip_keywords'] = False
        df_copy['ip_keyword_count'] = 0
        df_copy['detected_keywords'] = ''
        df_copy['sensitive_patterns_found'] = ''
        df_copy['sensitivity_score'] = 0
        
        for idx, row in df_copy.iterrows():
            # Combine all text fields for analysis
            text_content = self._extract_text_content(row)
            
            # Detect keywords
            keyword_results = self._detect_keywords_in_text(text_content)
            
            # Detect patterns
            pattern_results = self._detect_sensitive_patterns(text_content)
            
            # Analyze attachments
            attachment_results = self._analyze_attachments(row.get('attachments', ''))
            
            # Calculate overall sensitivity
            sensitivity_score = self._calculate_sensitivity_score(
                keyword_results, pattern_results, attachment_results
            )
            
            # Update dataframe
            df_copy.at[idx, 'has_ip_keywords'] = len(keyword_results['keywords']) > 0
            df_copy.at[idx, 'ip_keyword_count'] = len(keyword_results['keywords'])
            df_copy.at[idx, 'detected_keywords'] = ', '.join(keyword_results['keywords'])
            df_copy.at[idx, 'sensitive_patterns_found'] = ', '.join(pattern_results['patterns'])
            df_copy.at[idx, 'sensitivity_score'] = sensitivity_score
        
        return df_copy
    
    def _extract_text_content(self, email_row):
        """Extract all text content from email for analysis"""
        text_parts = []
        
        # Subject line
        subject = str(email_row.get('subject', ''))
        if subject and subject != 'nan':
            text_parts.append(subject)
        
        # Word list matches (if available)
        word_matches = str(email_row.get('word_list_match', ''))
        if word_matches and word_matches != 'nan':
            text_parts.append(word_matches)
        
        # Attachment descriptions
        attachments = str(email_row.get('attachments', ''))
        if attachments and attachments != 'nan':
            text_parts.append(attachments)
        
        # Combine all text
        combined_text = ' '.join(text_parts).lower()
        
        return combined_text
    
    def _detect_keywords_in_text(self, text):
        """Detect IP keywords in text content"""
        if not text:
            return {'keywords': [], 'categories': []}
        
        # Clean text for analysis
        cleaned_text = self._clean_text(text)
        
        detected_keywords = []
        categories = set()
        
        # Check for IP keywords
        for keyword in self.ip_keywords:
            if self._keyword_match(keyword, cleaned_text):
                detected_keywords.append(keyword)
                categories.add(self._categorize_keyword(keyword))
        
        # Check industry-specific keywords
        for industry, keywords in self.industry_keywords.items():
            for keyword in keywords:
                if self._keyword_match(keyword, cleaned_text):
                    detected_keywords.append(f"{industry}:{keyword}")
                    categories.add(industry)
        
        return {
            'keywords': list(set(detected_keywords)),
            'categories': list(categories)
        }
    
    def _detect_sensitive_patterns(self, text):
        """Detect structured sensitive data patterns"""
        if not text:
            return {'patterns': [], 'matches': {}}
        
        detected_patterns = []
        pattern_matches = {}
        
        for pattern_name, pattern_regex in self.sensitive_patterns.items():
            matches = re.findall(pattern_regex, text, re.IGNORECASE)
            if matches:
                detected_patterns.append(pattern_name)
                pattern_matches[pattern_name] = len(matches)
        
        return {
            'patterns': detected_patterns,
            'matches': pattern_matches
        }
    
    def _analyze_attachments(self, attachments_str):
        """Analyze attachments for sensitive content indicators"""
        if not attachments_str or pd.isna(attachments_str):
            return {'risk_score': 0, 'factors': []}
        
        attachments_str = str(attachments_str).lower()
        risk_score = 0
        risk_factors = []
        
        # Check for sensitive file types
        for file_type in self.sensitive_file_types:
            if f'.{file_type}' in attachments_str:
                risk_score += 5
                risk_factors.append(f'sensitive_file_type:{file_type}')
        
        # Check for size indicators (large files might be data dumps)
        size_indicators = ['large', 'mb', 'gb', 'big', 'huge']
        for indicator in size_indicators:
            if indicator in attachments_str:
                risk_score += 3
                risk_factors.append(f'large_attachment:{indicator}')
        
        # Check for multiple attachments
        attachment_count = attachments_str.count('.')  # Simple heuristic
        if attachment_count > 3:
            risk_score += 5
            risk_factors.append(f'multiple_attachments:{attachment_count}')
        
        # Check for compressed files (potential data exfiltration)
        compressed_types = ['zip', 'rar', '7z', 'tar', 'gz']
        for comp_type in compressed_types:
            if comp_type in attachments_str:
                risk_score += 8
                risk_factors.append(f'compressed_file:{comp_type}')
        
        return {
            'risk_score': risk_score,
            'factors': risk_factors
        }
    
    def _calculate_sensitivity_score(self, keyword_results, pattern_results, attachment_results):
        """Calculate overall sensitivity score"""
        score = 0
        
        # Keyword-based scoring
        score += len(keyword_results['keywords']) * 5
        
        # Pattern-based scoring
        for pattern_name, count in pattern_results['matches'].items():
            if pattern_name in ['ssn', 'credit_card']:
                score += count * 15  # High sensitivity
            elif pattern_name in ['api_key', 'guid']:
                score += count * 10  # Medium-high sensitivity
            else:
                score += count * 5   # Medium sensitivity
        
        # Attachment-based scoring
        score += attachment_results['risk_score']
        
        # Category bonuses
        sensitive_categories = ['financial', 'legal', 'healthcare']
        for category in keyword_results['categories']:
            if category in sensitive_categories:
                score += 10
        
        return min(score, 100)  # Cap at 100
    
    def _clean_text(self, text):
        """Clean text for keyword detection"""
        if not text:
            return ''
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        # Remove punctuation but keep spaces
        text = text.translate(str.maketrans(string.punctuation, ' ' * len(string.punctuation)))
        
        return text
    
    def _keyword_match(self, keyword, text):
        """Check if keyword matches in text with word boundaries"""
        # Use word boundaries to avoid partial matches
        pattern = r'\b' + re.escape(keyword) + r'\b'
        return bool(re.search(pattern, text, re.IGNORECASE))
    
    def _categorize_keyword(self, keyword):
        """Categorize a keyword into sensitivity type"""
        financial_keywords = {
            'financial', 'budget', 'salary', 'compensation', 'payroll',
            'revenue', 'profit', 'banking', 'account number'
        }
        
        legal_keywords = {
            'contract', 'agreement', 'legal', 'patent', 'copyright',
            'trademark', 'nda', 'non-disclosure'
        }
        
        technical_keywords = {
            'source code', 'algorithm', 'database', 'api key',
            'password', 'credentials', 'encryption key'
        }
        
        business_keywords = {
            'customer list', 'pricing', 'strategy', 'roadmap',
            'business plan', 'competitive analysis'
        }
        
        if keyword in financial_keywords:
            return 'financial'
        elif keyword in legal_keywords:
            return 'legal'
        elif keyword in technical_keywords:
            return 'technical'
        elif keyword in business_keywords:
            return 'business'
        else:
            return 'general'
    
    def get_keyword_statistics(self, df):
        """Get statistics about keyword detection results"""
        if 'has_ip_keywords' not in df.columns:
            return {}
        
        stats = {}
        
        # Overall detection rates
        total_emails = len(df)
        flagged_emails = df['has_ip_keywords'].sum()
        
        stats['detection_summary'] = {
            'total_emails': total_emails,
            'flagged_emails': int(flagged_emails),
            'detection_rate': f"{(flagged_emails/total_emails)*100:.1f}%" if total_emails > 0 else "0%"
        }
        
        # Top detected keywords
        if 'detected_keywords' in df.columns:
            all_keywords = []
            for keywords_str in df['detected_keywords']:
                if keywords_str and str(keywords_str) != 'nan':
                    keywords = [k.strip() for k in str(keywords_str).split(',') if k.strip()]
                    all_keywords.extend(keywords)
            
            if all_keywords:
                keyword_counts = pd.Series(all_keywords).value_counts()
                stats['top_keywords'] = keyword_counts.head(10).to_dict()
        
        # Sensitivity score distribution
        if 'sensitivity_score' in df.columns:
            stats['sensitivity_distribution'] = {
                'mean': df['sensitivity_score'].mean(),
                'median': df['sensitivity_score'].median(),
                'max': df['sensitivity_score'].max(),
                'high_sensitivity_count': len(df[df['sensitivity_score'] >= 50])
            }
        
        return stats
    
    def identify_high_risk_content(self, df, sensitivity_threshold=30):
        """Identify emails with high-risk content"""
        if 'sensitivity_score' not in df.columns:
            return pd.DataFrame()
        
        high_risk_emails = df[df['sensitivity_score'] >= sensitivity_threshold].copy()
        
        if high_risk_emails.empty:
            return high_risk_emails
        
        # Sort by sensitivity score
        high_risk_emails = high_risk_emails.sort_values('sensitivity_score', ascending=False)
        
        # Add risk category
        high_risk_emails['content_risk_level'] = high_risk_emails['sensitivity_score'].apply(
            lambda x: 'Critical' if x >= 70 else 'High' if x >= 50 else 'Medium'
        )
        
        return high_risk_emails
    
    def generate_keyword_report(self, df):
        """Generate comprehensive keyword detection report"""
        report = {
            'generated_at': pd.Timestamp.now().isoformat(),
            'summary': self.get_keyword_statistics(df)
        }
        
        # High-risk content analysis
        high_risk_content = self.identify_high_risk_content(df)
        report['high_risk_analysis'] = {
            'count': len(high_risk_content),
            'percentage': f"{(len(high_risk_content)/len(df))*100:.1f}%" if len(df) > 0 else "0%"
        }
        
        # Pattern detection summary
        if 'sensitive_patterns_found' in df.columns:
            all_patterns = []
            for patterns_str in df['sensitive_patterns_found']:
                if patterns_str and str(patterns_str) != 'nan':
                    patterns = [p.strip() for p in str(patterns_str).split(',') if p.strip()]
                    all_patterns.extend(patterns)
            
            if all_patterns:
                pattern_counts = pd.Series(all_patterns).value_counts()
                report['pattern_analysis'] = pattern_counts.head(5).to_dict()
        
        return report
    
    def add_custom_keywords(self, keywords):
        """Add custom keywords to the detection list"""
        if isinstance(keywords, str):
            keywords = [keywords]
        
        for keyword in keywords:
            self.ip_keywords.add(keyword.lower().strip())
    
    def remove_keywords(self, keywords):
        """Remove keywords from the detection list"""
        if isinstance(keywords, str):
            keywords = [keywords]
        
        for keyword in keywords:
            self.ip_keywords.discard(keyword.lower().strip())
    
    def export_keyword_analysis(self, df):
        """Export keyword analysis results to DataFrame"""
        if 'has_ip_keywords' not in df.columns:
            return pd.DataFrame()
        
        # Select relevant columns for export
        export_columns = [
            'time', 'sender', 'recipients', 'subject',
            'has_ip_keywords', 'ip_keyword_count', 'detected_keywords',
            'sensitive_patterns_found', 'sensitivity_score'
        ]
        
        # Only include columns that exist
        available_columns = [col for col in export_columns if col in df.columns]
        
        export_df = df[available_columns].copy()
        
        # Add risk categorization
        if 'sensitivity_score' in export_df.columns:
            export_df['content_risk_category'] = export_df['sensitivity_score'].apply(
                lambda x: 'Critical' if x >= 70 else 'High' if x >= 50 else 'Medium' if x >= 30 else 'Low'
            )
        
        return export_df
