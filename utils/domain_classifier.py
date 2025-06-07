import pandas as pd
import re
from typing import Dict, List, Set, Tuple, Optional

class DomainClassifier:
    """Enhanced email domain classifier with comprehensive categorization"""

    def __init__(self):
        self._initialize_domain_databases()
        self._initialize_classification_rules()

    def _initialize_domain_databases(self):
        """Initialize comprehensive domain databases"""

        # Major free email providers (most common)
        self.major_free_providers = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
            'icloud.com', 'me.com', 'live.com', 'msn.com', 'mail.com'
        }

        # Microsoft ecosystem
        self.microsoft_domains = {
            'hotmail.com', 'hotmail.co.uk', 'hotmail.fr', 'hotmail.de', 'hotmail.it', 'hotmail.es',
            'live.com', 'live.co.uk', 'live.fr', 'live.de', 'live.it', 'live.es',
            'outlook.com', 'outlook.co.uk', 'outlook.fr', 'outlook.de', 'outlook.it', 'outlook.es',
            'windowslive.com', 'passport.com', 'msn.com'
        }

        # Google ecosystem
        self.google_domains = {
            'gmail.com', 'googlemail.com', 'gmail.co.uk', 'gmail.com.au', 'gmail.fr',
            'gmail.de', 'gmail.it', 'gmail.es', 'gmail.ca'
        }

        # Yahoo ecosystem
        self.yahoo_domains = {
            'yahoo.com', 'yahoo.co.uk', 'yahoo.fr', 'yahoo.de', 'yahoo.it', 'yahoo.es',
            'yahoo.ca', 'yahoo.com.au', 'yahoo.co.jp', 'yahoo.com.br',
            'yahoo.in', 'yahoo.com.mx', 'yahoo.com.ar', 'ymail.com',
            'rocketmail.com', 'yahoomail.com'
        }

        # European providers
        self.european_providers = {
            'gmx.com', 'gmx.de', 'gmx.at', 'gmx.ch', 'gmx.net', 'gmx.org',
            'web.de', 't-online.de', 'freenet.de', 'arcor.de',
            'orange.fr', 'laposte.net', 'sfr.fr', 'free.fr', 'wanadoo.fr',
            'libero.it', 'virgilio.it', 'tiscali.it', 'alice.it',
            'terra.es', 'telefonica.net', 'ya.com',
            'mail.ru', 'yandex.ru', 'yandex.com', 'rambler.ru', 'inbox.ru'
        }

        # Asian providers
        self.asian_providers = {
            'qq.com', '163.com', '126.com', 'sina.com', 'sohu.com',
            'naver.com', 'daum.net', 'hanmail.net',
            'rediffmail.com', 'sify.com', 'indiatimes.com'
        }

        # Privacy-focused providers
        self.privacy_providers = {
            'protonmail.com', 'protonmail.ch', 'pm.me',
            'tutanota.com', 'tutanota.de', 'tuta.io',
            'hushmail.com', 'countermail.com', 'startmail.com',
            'mailfence.com', 'posteo.de', 'disroot.org', 'riseup.net'
        }

        # Temporary/disposable providers
        self.disposable_providers = {
            'temp-mail.org', 'tempmail.net', 'throwaway.email', '10minutemail.com',
            'mailinator.com', 'guerrillamail.com', 'guerrillamail.de',
            'guerrillamail.net', 'guerrillamail.org', 'guerrillamail.biz',
            'maildrop.cc', 'getairmail.com', 'sharklasers.com'
        }

        # Educational free providers
        self.educational_free = {
            'student.com', 'alumni.com', 'grad.com'
        }

        # All free domains combined
        self.all_free_domains = (
            self.major_free_providers | self.microsoft_domains | self.google_domains |
            self.yahoo_domains | self.european_providers | self.asian_providers |
            self.privacy_providers | self.disposable_providers | self.educational_free
        )

        # Business industry patterns
        self.industry_patterns = {
            'banking': {
                'domains': {
                    'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com', 'citi.com',
                    'jpmorgan.com', 'jpmorganchase.com', 'usbank.com', 'truist.com', 'pnc.com',
                    'hsbc.com', 'barclays.com', 'santander.com', 'goldmansachs.com', 'gs.com'
                },
                'keywords': ['bank', 'credit', 'financial', 'trust', 'savings', 'federal']
            },
            'technology': {
                'domains': {
                    'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'meta.com',
                    'facebook.com', 'netflix.com', 'tesla.com', 'salesforce.com', 'oracle.com',
                    'ibm.com', 'intel.com', 'cisco.com', 'adobe.com', 'vmware.com'
                },
                'keywords': ['tech', 'software', 'systems', 'solutions', 'digital', 'cyber']
            },
            'healthcare': {
                'domains': {
                    'mayoclinic.org', 'clevelandclinic.org', 'johnshopkins.org',
                    'kaiserpermanente.org', 'sutterhealth.org'
                },
                'keywords': ['medical', 'health', 'hospital', 'clinic', 'care']
            },
            'education': {
                'domains': {
                    'harvard.edu', 'mit.edu', 'stanford.edu', 'berkeley.edu', 'yale.edu'
                },
                'keywords': ['university', 'college', 'school', 'academy', 'institute']
            },
            'government': {
                'domains': {
                    'irs.gov', 'treasury.gov', 'sec.gov', 'fdic.gov'
                },
                'keywords': ['gov', 'government', 'agency', 'department']
            }
        }

    def _initialize_classification_rules(self):
        """Initialize classification rules and patterns"""
        self.business_tlds = {
            '.com', '.org', '.net', '.edu', '.gov', '.mil',
            '.co.uk', '.co.jp', '.co.au', '.com.au', '.com.br'
        }

        self.internal_indicators = {
            '.local', 'localhost', 'intranet', 'internal'
        }

    def classify_domains(self, df: pd.DataFrame) -> pd.DataFrame:
        """Main method to classify all domains in the dataframe"""
        df_copy = df.copy()

        # Step 1: Extract basic domain information
        df_copy = self._extract_domain_fields(df_copy)

        # Step 2: Classify sender domains
        df_copy['email_domain_type'] = df_copy.apply(self._classify_sender_domain, axis=1)

        # Step 3: Add detailed categorization
        df_copy['email_domain_category'] = df_copy['sender_domain'].apply(self._get_detailed_category)

        # Step 4: Industry classification for business domains
        df_copy['email_domain_industry'] = df_copy['sender_domain'].apply(self._classify_industry)

        # Step 5: Recipient analysis
        df_copy = self._analyze_recipients(df_copy)

        # Step 6: Internal communication detection
        df_copy['is_internal_communication'] = df_copy.apply(self._detect_internal_communication, axis=1)

        return df_copy

    def _extract_domain_fields(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract and normalize domain fields"""
        # Extract sender domain
        if 'sender_domain' not in df.columns:
            df['sender_domain'] = df['sender'].apply(self._extract_domain)

        # Create email_domain for backward compatibility
        if 'email_domain' not in df.columns:
            df['email_domain'] = df['sender_domain']

        # Extract recipient domain
        if 'recipient_domain' not in df.columns:
            df['recipient_domain'] = df['recipients'].apply(self._extract_first_recipient_domain)

        # Extract all recipient domains
        df['recipient_domains'] = df['recipients'].apply(self._extract_all_recipient_domains)

        return df

    def _extract_domain(self, email: str) -> str:
        """Extract domain from email address"""
        if pd.isna(email) or '@' not in str(email):
            return ''

        try:
            domain = str(email).split('@')[-1].lower().strip()
            # Remove any trailing spaces or special characters
            domain = re.sub(r'[^\w\.-]', '', domain)
            return domain
        except:
            return ''

    def _extract_first_recipient_domain(self, recipients: str) -> str:
        """Extract first recipient domain"""
        if pd.isna(recipients) or str(recipients).strip() == '':
            return ''

        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, str(recipients))

        if emails:
            return self._extract_domain(emails[0])
        return ''

    def _extract_all_recipient_domains(self, recipients: str) -> List[str]:
        """Extract all unique recipient domains"""
        if pd.isna(recipients) or str(recipients).strip() == '':
            return []

        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, str(recipients))

        domains = []
        for email in emails:
            domain = self._extract_domain(email)
            if domain and domain not in domains:
                domains.append(domain)

        return domains

    def _classify_sender_domain(self, row) -> str:
        """Classify sender domain with internal detection"""
        sender_domain = row.get('sender_domain', '')
        recipient_domain = row.get('recipient_domain', '')

        if not sender_domain:
            return 'unknown'

        sender_clean = sender_domain.lower().strip()

        # Check for internal communication first
        if self._is_internal_communication(sender_domain, recipient_domain):
            return 'internal'

        # Check if it's a free email provider
        if sender_clean in self.all_free_domains:
            return 'free'

        # Check for obviously internal domains
        if self._is_internal_domain(sender_clean):
            return 'internal'

        # Everything else is business
        return 'business'

    def _is_internal_communication(self, sender_domain: str, recipient_domain: str) -> bool:
        """Detect internal communication based on domain matching"""
        if not sender_domain or not recipient_domain:
            return False

        sender_clean = sender_domain.lower().strip()
        recipient_clean = recipient_domain.lower().strip()

        # Exact match and both are business domains
        if (sender_clean == recipient_clean and 
            sender_clean not in self.all_free_domains and 
            recipient_clean not in self.all_free_domains):
            return True

        return False

    def _is_internal_domain(self, domain: str) -> bool:
        """Check if domain is clearly internal infrastructure"""
        if not domain:
            return False

        # Check for private IP ranges and local domains
        internal_patterns = [
            r'^localhost$',
            r'^.*\.local$',
            r'^.*\.internal$',
            r'^10\.',
            r'^192\.168\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'
        ]

        for pattern in internal_patterns:
            if re.match(pattern, domain):
                return True

        return False

    def _get_detailed_category(self, domain: str) -> str:
        """Get detailed category for free email domains"""
        if not domain:
            return 'unknown'

        domain = domain.lower().strip()

        if domain in self.major_free_providers:
            return 'Major Email Providers'
        elif domain in self.microsoft_domains:
            return 'Microsoft Email Services'
        elif domain in self.google_domains:
            return 'Google Email Services'
        elif domain in self.yahoo_domains:
            return 'Yahoo Email Services'
        elif domain in self.european_providers:
            return 'European Email Providers'
        elif domain in self.asian_providers:
            return 'Asian Email Providers'
        elif domain in self.privacy_providers:
            return 'Privacy-Focused Email'
        elif domain in self.disposable_providers:
            return 'Temporary/Disposable Email'
        elif domain in self.educational_free:
            return 'Educational (Free)'
        elif domain in self.all_free_domains:
            return 'Other Free Email Providers'
        else:
            return 'Business Domain'

    def _classify_industry(self, domain: str) -> str:
        """Classify business domain by industry"""
        if not domain or domain in self.all_free_domains:
            return 'not_business'

        domain = domain.lower().strip()

        # Check direct domain matches first
        for industry, patterns in self.industry_patterns.items():
            if domain in patterns['domains']:
                return industry

        # Check keyword patterns
        for industry, patterns in self.industry_patterns.items():
            for keyword in patterns['keywords']:
                if keyword in domain:
                    return industry

        return 'business_other'

    def _analyze_recipients(self, df: pd.DataFrame) -> pd.DataFrame:
        """Analyze recipient patterns"""
        df['recipient_domain_types'] = df['recipient_domains'].apply(self._classify_domain_list)
        df['external_recipient_count'] = df.apply(self._count_external_recipients, axis=1)
        return df

    def _classify_domain_list(self, domain_list: List[str]) -> List[str]:
        """Classify a list of domains"""
        if not isinstance(domain_list, list):
            return []

        classifications = []
        for domain in domain_list:
            if domain in self.all_free_domains:
                classifications.append('free')
            else:
                classifications.append('business')

        return classifications

    def _count_external_recipients(self, row) -> int:
        """Count external recipients (different domain from sender)"""
        sender_domain = row.get('sender_domain', '')
        recipient_domains = row.get('recipient_domains', [])

        if not sender_domain or not isinstance(recipient_domains, list):
            return 0

        external_count = 0
        for domain in recipient_domains:
            if domain.lower() != sender_domain.lower():
                external_count += 1

        return external_count

    def _detect_internal_communication(self, row) -> bool:
        """Enhanced internal communication detection"""
        sender_domain = row.get('sender_domain', '')
        recipient_domains = row.get('recipient_domains', [])

        if not sender_domain or not isinstance(recipient_domains, list):
            return False

        # Check if any recipient domain matches sender domain
        sender_clean = sender_domain.lower().strip()
        for recipient_domain in recipient_domains:
            if recipient_domain.lower().strip() == sender_clean:
                # Both must be business domains for true internal communication
                if (sender_clean not in self.all_free_domains and 
                    recipient_domain.lower() not in self.all_free_domains):
                    return True

        return False

    def get_classification_summary(self, df: pd.DataFrame) -> Dict:
        """Get comprehensive classification summary"""
        if 'email_domain_type' not in df.columns:
            return {}

        summary = {
            'total_emails': len(df),
            'domain_type_distribution': df['email_domain_type'].value_counts().to_dict(),
            'category_distribution': df['email_domain_category'].value_counts().to_dict() if 'email_domain_category' in df.columns else {},
            'industry_distribution': df['email_domain_industry'].value_counts().to_dict() if 'email_domain_industry' in df.columns else {},
            'internal_communication_count': df['is_internal_communication'].sum() if 'is_internal_communication' in df.columns else 0
        }

        # Calculate percentages
        total = summary['total_emails']
        if total > 0:
            summary['percentages'] = {
                domain_type: (count / total * 100)
                for domain_type, count in summary['domain_type_distribution'].items()
            }

        return summary

    def identify_anomalous_domains(self, df: pd.DataFrame) -> List[Dict]:
        """Identify potentially anomalous domain patterns"""
        anomalies = []

        if 'sender_domain' not in df.columns:
            return anomalies

        domain_counts = df['sender_domain'].value_counts()
        total_emails = len(df)

        for domain, count in domain_counts.items():
            # High volume single domain
            if count > total_emails * 0.15:  # More than 15% from single domain
                anomalies.append({
                    'domain': domain,
                    'type': 'high_volume',
                    'count': count,
                    'percentage': (count / total_emails * 100),
                    'risk_level': 'high'
                })

            # Suspicious domain patterns
            if self._is_suspicious_domain(domain):
                anomalies.append({
                    'domain': domain,
                    'type': 'suspicious_pattern',
                    'count': count,
                    'reasons': self._get_suspicion_reasons(domain),
                    'risk_level': 'medium'
                })

        return anomalies

    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check for suspicious domain characteristics"""
        if not domain:
            return False

        suspicious_patterns = [
            r'\d{4,}',  # Many consecutive numbers
            r'[a-z]{25,}',  # Very long strings
            r'\.tk$|\.ml$|\.ga$|\.cf$',  # Suspicious TLDs
            r'temp|test|fake|spam|dummy',  # Suspicious keywords
            r'^[a-z]{1,3}\d+\.',  # Short prefix with numbers
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, domain.lower()):
                return True

        return False

    def _get_suspicion_reasons(self, domain: str) -> List[str]:
        """Get specific reasons why domain is suspicious"""
        reasons = []

        if re.search(r'\d{4,}', domain):
            reasons.append('Contains many consecutive numbers')
        if re.search(r'[a-z]{25,}', domain):
            reasons.append('Unusually long domain name')
        if re.search(r'\.tk$|\.ml$|\.ga$|\.cf$', domain):
            reasons.append('Uses suspicious TLD')
        if re.search(r'temp|test|fake|spam|dummy', domain.lower()):
            reasons.append('Contains suspicious keywords')
        if re.search(r'^[a-z]{1,3}\d+\.', domain):
            reasons.append('Unusual naming pattern')

        return reasons

    def export_domain_analysis(self, df: pd.DataFrame, filepath: str = None) -> str:
        """Export detailed domain analysis to CSV"""
        if 'sender_domain' not in df.columns:
            return "No domain data available"

        # Create detailed analysis
        domain_analysis = []
        domain_counts = df['sender_domain'].value_counts()

        for domain, count in domain_counts.items():
            if domain:
                category = self._get_detailed_category(domain)
                industry = self._classify_industry(domain)
                is_suspicious = self._is_suspicious_domain(domain)

                domain_analysis.append({
                    'domain': domain,
                    'email_count': count,
                    'percentage': (count / len(df) * 100),
                    'category': category,
                    'industry': industry,
                    'is_free': domain in self.all_free_domains,
                    'is_suspicious': is_suspicious,
                    'suspicion_reasons': '; '.join(self._get_suspicion_reasons(domain)) if is_suspicious else ''
                })

        # Convert to DataFrame and sort by count
        analysis_df = pd.DataFrame(domain_analysis)
        analysis_df = analysis_df.sort_values('email_count', ascending=False)

        if filepath:
            analysis_df.to_csv(filepath, index=False)
            return f"Domain analysis exported to {filepath}"

        return analysis_df.to_csv(index=False)