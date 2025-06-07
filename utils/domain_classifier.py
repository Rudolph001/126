import pandas as pd
import re

class DomainClassifier:
    """Classifies email domains as internal, business, or public/free"""
    
    def __init__(self):
        # Common free email providers
        self.free_email_domains = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
            'icloud.com', 'me.com', 'mail.com', 'gmx.com', 'yandex.com',
            'protonmail.com', 'tutanota.com', 'zoho.com', 'fastmail.com',
            'live.com', 'msn.com', 'yahoo.co.uk', 'gmail.co.uk', 'bt.com',
            'sky.com', 'virginmedia.com', 'tiscali.co.uk', 'talktalk.net'
        }
        
        # Common business domain patterns
        self.business_domain_indicators = {
            '.co.', '.com.', '.org.', '.net.', '.edu.', '.gov.',
            'corp.', 'company.', 'group.', 'ltd.', 'inc.', 'llc.'
        }
        
        # TLDs that are commonly used by businesses
        self.business_tlds = {
            '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int',
            '.co.uk', '.co.jp', '.co.au', '.co.nz', '.co.za',
            '.com.au', '.com.br', '.com.cn', '.com.de', '.com.fr'
        }
    
    def classify_domains(self, df):
        """Classify domains in the email dataframe"""
        df_copy = df.copy()
        
        # Extract domains from sender and recipients
        df_copy['sender_domain'] = df_copy['sender'].apply(self._extract_domain)
        
        # Classify sender domains
        df_copy['sender_domain_type'] = df_copy['sender_domain'].apply(self._classify_single_domain)
        
        # Classify recipient domains (if recipient_domains column exists)
        if 'recipient_domains' in df_copy.columns:
            df_copy['recipient_domain_types'] = df_copy['recipient_domains'].apply(
                self._classify_domain_list
            )
            
            # Also create a single domain_type column for primary classification
            df_copy['domain_type'] = df_copy['recipient_domain_types'].apply(
                self._get_primary_domain_type
            )
        else:
            # Use sender domain as fallback
            df_copy['domain_type'] = df_copy['sender_domain_type']
        
        return df_copy
    
    def _extract_domain(self, email):
        """Extract domain from email address"""
        if pd.isna(email) or '@' not in str(email):
            return ''
        
        try:
            domain = str(email).split('@')[-1].lower().strip()
            return domain
        except:
            return ''
    
    def _classify_single_domain(self, domain):
        """Classify a single domain"""
        if not domain:
            return 'unknown'
        
        domain = domain.lower().strip()
        
        # Check if it's a free email provider
        if domain in self.free_email_domains:
            return 'free'
        
        # Check for internal domain patterns (basic heuristics)
        if self._is_internal_domain(domain):
            return 'internal'
        
        # Check for business domain patterns
        if self._is_business_domain(domain):
            return 'business'
        
        # Default to business if it has business-like characteristics
        if self._has_business_characteristics(domain):
            return 'business'
        
        return 'public'
    
    def _classify_domain_list(self, domain_list):
        """Classify a list of domains"""
        if not isinstance(domain_list, list):
            return []
        
        classifications = []
        for domain in domain_list:
            classification = self._classify_single_domain(domain)
            classifications.append(classification)
        
        return classifications
    
    def _get_primary_domain_type(self, domain_type_list):
        """Get primary domain type from list of classifications"""
        if not isinstance(domain_type_list, list) or len(domain_type_list) == 0:
            return 'unknown'
        
        # Priority: internal > business > free > public > unknown
        priority_order = ['internal', 'business', 'free', 'public', 'unknown']
        
        for domain_type in priority_order:
            if domain_type in domain_type_list:
                return domain_type
        
        return domain_type_list[0]  # Fallback to first item
    
    def _is_internal_domain(self, domain):
        """Check if domain appears to be internal"""
        # Simple heuristics for internal domains
        internal_indicators = [
            '.local', '.internal', '.corp', '.company',
            'localhost', '192.168.', '10.', '172.'
        ]
        
        return any(indicator in domain for indicator in internal_indicators)
    
    def _is_business_domain(self, domain):
        """Check if domain has business characteristics"""
        # Check for business domain indicators
        for indicator in self.business_domain_indicators:
            if indicator in domain:
                return True
        
        # Check for business TLDs
        for tld in self.business_tlds:
            if domain.endswith(tld):
                return True
        
        return False
    
    def _has_business_characteristics(self, domain):
        """Check if domain has business-like characteristics"""
        # Length-based heuristics
        if len(domain) > 15:  # Very long domains often business
            return True
        
        # Pattern-based heuristics
        business_patterns = [
            r'\d+',  # Contains numbers
            r'-',    # Contains hyphens
            r'[a-z]{2,}\.[a-z]{2,}\.[a-z]{2,}'  # Multiple subdomains
        ]
        
        for pattern in business_patterns:
            if re.search(pattern, domain):
                return True
        
        return False
    
    def get_domain_statistics(self, df):
        """Get statistics about domain classifications"""
        if 'domain_type' not in df.columns:
            return {}
        
        stats = {}
        
        # Overall distribution
        domain_counts = df['domain_type'].value_counts()
        stats['distribution'] = domain_counts.to_dict()
        
        # Percentages
        total_emails = len(df)
        stats['percentages'] = {
            domain_type: (count / total_emails * 100)
            for domain_type, count in domain_counts.items()
        }
        
        # Top domains by type
        if 'sender_domain' in df.columns:
            stats['top_domains_by_type'] = {}
            
            for domain_type in domain_counts.index:
                type_domains = df[df['domain_type'] == domain_type]['sender_domain']
                top_domains = type_domains.value_counts().head(5)
                stats['top_domains_by_type'][domain_type] = top_domains.to_dict()
        
        return stats
    
    def identify_suspicious_domains(self, df):
        """Identify potentially suspicious domains"""
        suspicious_domains = []
        
        if 'sender_domain' not in df.columns:
            return suspicious_domains
        
        domain_counts = df['sender_domain'].value_counts()
        
        for domain, count in domain_counts.items():
            if self._is_suspicious_domain(domain, count, len(df)):
                suspicious_domains.append({
                    'domain': domain,
                    'email_count': count,
                    'suspicion_reasons': self._get_suspicion_reasons(domain)
                })
        
        return suspicious_domains
    
    def _is_suspicious_domain(self, domain, count, total_emails):
        """Check if a domain appears suspicious"""
        if not domain:
            return False
        
        # High volume from single domain
        if count > total_emails * 0.1:  # More than 10% of all emails
            return True
        
        # Suspicious domain patterns
        suspicious_patterns = [
            r'\d{4,}',  # Many consecutive numbers
            r'[a-z]{20,}',  # Very long string without separators
            r'\.tk$|\.ml$|\.ga$|\.cf$',  # Suspicious TLDs
            r'temp|test|fake|spam|dummy',  # Suspicious keywords
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, domain.lower()):
                return True
        
        return False
    
    def _get_suspicion_reasons(self, domain):
        """Get reasons why a domain is suspicious"""
        reasons = []
        
        if re.search(r'\d{4,}', domain):
            reasons.append('Contains many consecutive numbers')
        
        if re.search(r'[a-z]{20,}', domain):
            reasons.append('Very long string without separators')
        
        if re.search(r'\.tk$|\.ml$|\.ga$|\.cf$', domain):
            reasons.append('Uses suspicious TLD')
        
        if re.search(r'temp|test|fake|spam|dummy', domain.lower()):
            reasons.append('Contains suspicious keywords')
        
        return reasons
    
    def update_free_domains(self, new_domains):
        """Update the list of free email domains"""
        if isinstance(new_domains, (list, set)):
            self.free_email_domains.update(new_domains)
        elif isinstance(new_domains, str):
            self.free_email_domains.add(new_domains.lower())
    
    def classify_new_domain(self, domain, classification):
        """Manually classify a domain (for learning/updating)"""
        # Store manual classifications for future use
        if not hasattr(self, 'manual_classifications'):
            self.manual_classifications = {}
        
        self.manual_classifications[domain.lower()] = classification
    
    def get_manual_classification(self, domain):
        """Get manual classification if available"""
        if hasattr(self, 'manual_classifications'):
            return self.manual_classifications.get(domain.lower())
        return None
    
    def _classify_single_domain_with_manual(self, domain):
        """Classify domain considering manual overrides first"""
        if not domain:
            return 'unknown'
        
        # Check for manual classification first
        manual_class = self.get_manual_classification(domain)
        if manual_class:
            return manual_class
        
        # Fall back to automatic classification
        return self._classify_single_domain(domain)
