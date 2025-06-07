import pandas as pd
import re

class DomainClassifier:
    """Classifies email domains as internal, business, or public/free"""

    def __init__(self):
        # Comprehensive free email providers list
        self.free_email_domains = {
            # Major providers
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
            'icloud.com', 'me.com', 'mail.com', 'gmx.com', 'yandex.com',
            'protonmail.com', 'tutanota.com', 'zoho.com', 'fastmail.com',
            'live.com', 'msn.com', 'yahoo.co.uk', 'gmail.co.uk',

            # Microsoft domains
            'hotmail.co.uk', 'hotmail.fr', 'hotmail.de', 'hotmail.it', 'hotmail.es',
            'live.co.uk', 'live.fr', 'live.de', 'live.it', 'live.es',
            'outlook.co.uk', 'outlook.fr', 'outlook.de', 'outlook.it', 'outlook.es',
            'windowslive.com', 'passport.com',

            # Yahoo domains
            'yahoo.co.uk', 'yahoo.fr', 'yahoo.de', 'yahoo.it', 'yahoo.es',
            'yahoo.ca', 'yahoo.com.au', 'yahoo.co.jp', 'yahoo.com.br',
            'yahoo.in', 'yahoo.com.mx', 'yahoo.com.ar', 'ymail.com',
            'rocketmail.com', 'yahoomail.com',

            # Google domains
            'googlemail.com', 'gmail.co.uk', 'gmail.com.au', 'gmail.fr',
            'gmail.de', 'gmail.it', 'gmail.es', 'gmail.ca', 'google.com',

            # AOL domains
            'aol.co.uk', 'aol.fr', 'aol.de', 'aol.it', 'aol.es',
            'aim.com', 'netscape.net', 'netscape.com', 'compuserve.com',

            # Apple domains
            'mac.com', 'icloud.com', 'me.com',

            # European providers
            'gmx.de', 'gmx.at', 'gmx.ch', 'gmx.net', 'gmx.org',
            'web.de', 't-online.de', 'freenet.de', 'arcor.de',
            'orange.fr', 'laposte.net', 'sfr.fr', 'free.fr', 'wanadoo.fr',
            'libero.it', 'virgilio.it', 'tiscali.it', 'alice.it',
            'terra.es', 'telefonica.net', 'ya.com',
            'mail.ru', 'yandex.ru', 'rambler.ru', 'inbox.ru',

            # UK providers
            'bt.com', 'btinternet.com', 'sky.com', 'virginmedia.com',
            'tiscali.co.uk', 'talktalk.net', 'ntlworld.com', 'blueyonder.co.uk',
            'freeserve.co.uk', 'fsmail.net', 'plusnet.com',

            # Asian providers
            'qq.com', '163.com', '126.com', 'sina.com', 'sohu.com',
            'naver.com', 'daum.net', 'hanmail.net',
            'rediffmail.com', 'sify.com', 'indiatimes.com',

            # Other international
            'terra.com.br', 'bol.com.br', 'ig.com.br', 'globo.com',
            'sympatico.ca', 'rogers.com', 'shaw.ca', 'telus.net',
            'bigpond.com', 'optusnet.com.au', 'iinet.net.au',
            'telstra.com', 'adam.com.au',

            # Privacy-focused
            'protonmail.ch', 'pm.me', 'tutanota.de', 'tuta.io',
            'guerrillamail.com', 'temp-mail.org', 'tempmail.net',
            'mailinator.com', '10minutemail.com', 'guerrillamail.de',
            'guerrillamail.net', 'guerrillamail.org', 'guerrillamail.biz',

            # Disposable email services
            'temp-mail.org', 'tempmail.net', 'throwaway.email',
            'mailnesia.com', 'maildrop.cc', 'getairmail.com',
            'sharklasers.com', 'guerrillamail.info', 'grr.la',
            'guerrillamail.biz', 'guerrillamail.com', 'guerrillamail.de',
            'guerrillamail.net', 'guerrillamail.org', 'spam4.me',

            # Generic providers
            'mail.com', 'email.com', 'usa.com', 'myself.com',
            'consultant.com', 'techie.com', 'engineer.com',
            'lawyer.com', 'doctor.com', 'workmail.com',
            'europe.com', 'asia.com', 'africamail.com',
            'americamail.com', 'australiamail.com',

            # Older/legacy providers
            'excite.com', 'lycos.com', 'altavista.com', 'rediff.com',
            'mailcity.com', 'mail2world.com', 'angelfire.com',
            'geocities.com', 'tripod.com', 'juno.com',
            'netzero.net', 'earthlink.net', 'mindspring.com',

            # Regional/Country specific
            'post.com', 'bigfoot.com', 'cool.co.za', 'webmail.co.za',
            'mweb.co.za', 'iafrica.com', 'vodamail.co.za',
            'lantic.net', 'eastlink.ca', 'cogeco.ca',
            'teksavvy.com', 'bell.net', 'sympatico.ca',

            # Educational (but free)
            'student.com', 'alumni.com', 'grad.com',

            # Business-style but free
            'contractor.net', 'freelancer.com', 'consultant.com',
            'techie.com', 'engineer.com', 'programmer.net',

            # Other notable free providers
            'inbox.com', 'safe-mail.net', 'anonymous.to',
            'hushmail.com', 'countermail.com', 'startmail.com',
            'mailfence.com', 'posteo.de', 'kolab.com',
            'disroot.org', 'riseup.net', 'autistici.org',
            'openmailbox.org', 'cock.li', 'aaathats3as.com',
            'abv.bg', 'centrum.cz', 'seznam.cz', 'atlas.cz',
            'email.cz', 'quick.cz', 'volny.cz', 'tlen.pl',
            'gazeta.pl', 'interia.pl', 'wp.pl', 'o2.pl'
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

        # Industry-specific domain patterns
        self.banking_domains = {
            # Major Banks
            'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com', 'citi.com',
            'jpmorgan.com', 'jpmorganchase.com', 'usbank.com', 'truist.com', 'pnc.com',
            'capitalone.com', 'tdbank.com', 'regions.com', 'fifththird.com', 'huntington.com',
            'keybank.com', 'comerica.com', 'zions.com', 'firstrepublic.com', 'svb.com',

            # International Banks
            'hsbc.com', 'hsbc.co.uk', 'santander.com', 'santander.co.uk', 'barclays.com',
            'barclays.co.uk', 'lloyds.com', 'rbs.com', 'natwest.com', 'standardchartered.com',
            'db.com', 'deutschebank.com', 'commerzbank.com', 'bnpparibas.com', 'societegenerale.com',
            'credit-agricole.com', 'ing.com', 'abn-amro.com', 'rabobank.com', 'ubs.com',
            'credit-suisse.com', 'swissbank.com', 'unicredit.com', 'intesasanpaolo.com',
            'mitsubishiufj.com', 'mizuho.com', 'smbc.co.jp', 'bmo.com', 'rbc.com',
            'td.com', 'scotiabank.com', 'cibc.com', 'anz.com', 'westpac.com.au',
            'nab.com.au', 'cba.com.au', 'icbc.com', 'boc.com', 'ccb.com',

            # Investment Banks & Financial Services
            'goldmansachs.com', 'gs.com', 'morganstanley.com', 'merrilllynch.com',
            'ml.com', 'blackrock.com', 'vanguard.com', 'fidelity.com', 'schwab.com',
            'ameritrade.com', 'etrade.com', 'robinhood.com', 'interactivebrokers.com',

            # Credit Unions & Regional Banks
            'navyfederal.org', 'penfed.org', 'secu.org', 'becu.org', 'alliantcu.org',
            'dccu.org', 'suncoastcu.org', 'schoolsfirst.org', 'golden1.com',

            # Financial Technology
            'paypal.com', 'square.com', 'stripe.com', 'affirm.com', 'klarna.com',
            'sofi.com', 'chime.com', 'ally.com', 'marcus.com', 'discover.com',

            # Generic banking patterns
            'bank', 'credit', 'financial', 'trust', 'savings', 'federal',
            'mutual', 'community', 'first', 'national', 'state', 'peoples',
            'citizens', 'republic', 'union', 'central', 'security'
        }

        self.education_domains = {
            # Major Universities
            'harvard.edu', 'mit.edu', 'stanford.edu', 'berkeley.edu', 'ucla.edu',
            'yale.edu', 'princeton.edu', 'columbia.edu', 'upenn.edu', 'brown.edu',
            'dartmouth.edu', 'cornell.edu', 'chicago.edu', 'northwestern.edu',
            'duke.edu', 'johns-hopkins.edu', 'jhu.edu', 'georgetown.edu', 'nyu.edu',
            'usc.edu', 'vanderbilt.edu', 'rice.edu', 'emory.edu', 'carnegiemellon.edu',
            'cmu.edu', 'gatech.edu', 'umich.edu', 'uva.edu', 'unc.edu',

            # State Universities
            'psu.edu', 'osu.edu', 'msu.edu', 'asu.edu', 'fsu.edu', 'uf.edu',
            'ufl.edu', 'ucf.edu', 'usf.edu', 'fiu.edu', 'tamu.edu', 'utexas.edu',
            'ou.edu', 'ku.edu', 'ksu.edu', 'unl.edu', 'iastate.edu', 'uiowa.edu',
            'wisc.edu', 'umn.edu', 'purdue.edu', 'indiana.edu', 'illinois.edu',

            # Community Colleges
            'valenciacollege.edu', 'broward.edu', 'mdc.edu', 'hccs.edu', 'cpcc.edu',
            'nhti.edu', 'ccm.edu', 'ocean.edu', 'brookdalecc.edu', 'middlesexcc.edu',

            # International Universities
            'ox.ac.uk', 'cam.ac.uk', 'imperial.ac.uk', 'ucl.ac.uk', 'kcl.ac.uk',
            'lse.ac.uk', 'ed.ac.uk', 'manchester.ac.uk', 'bristol.ac.uk', 'warwick.ac.uk',
            'utoronto.ca', 'ubc.ca', 'mcgill.ca', 'queensu.ca', 'uwaterloo.ca',
            'anu.edu.au', 'sydney.edu.au', 'unsw.edu.au', 'monash.edu', 'unimelb.edu.au',
            'ethz.ch', 'epfl.ch', 'tum.de', 'uni-heidelberg.de', 'lmu.de',
            'sorbonne-universite.fr', 'ens.fr', 'polytechnique.edu', 'u-tokyo.ac.jp',
            'kyoto-u.ac.jp', 'nus.edu.sg', 'ntu.edu.sg', 'hku.hk', 'cuhk.edu.hk',

            # K-12 Schools
            'k12.', 'schooldistrict', 'schools.', 'isd.', 'usd.', 'csd.',

            # Generic education patterns
            'university', 'college', 'school', 'academy', 'institute',
            'education', 'learning', 'campus', 'student'
        }

        self.healthcare_domains = {
            # Major Hospital Systems
            'mayoclinic.org', 'clevelandclinic.org', 'johnshopkins.org', 'mgh.harvard.edu',
            'mountsinai.org', 'nyp.org', 'cedars-sinai.org', 'kp.org', 'kaiserpermanente.org',
            'intermountainhealth.org', 'sutterhealth.org', 'adventhealth.com',
            'commonspirit.org', 'ascension.org', 'hca.com', 'tenethealth.com',

            # Medical Centers
            'ucsf.edu', 'ucla.edu', 'med.', 'health.', 'hospital.', 'clinic.',
            'medical', 'healthcare', 'mercy', 'baptist', 'methodist', 'presbyterian'
        }

        self.government_domains = {
            # Federal Government
            'irs.gov', 'treasury.gov', 'sec.gov', 'fdic.gov', 'occ.gov',
            'federalreserve.gov', 'fed.', 'state.gov', 'defense.gov', 'dhs.gov',
            'fbi.gov', 'cia.gov', 'nsa.gov', 'doe.gov', 'epa.gov',

            # State & Local
            '.gov', '.state.', 'county.', 'city.', 'municipal',
            'government', 'agency', 'department'
        }

        self.technology_domains = {
            # Major Tech Companies
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'meta.com',
            'facebook.com', 'netflix.com', 'tesla.com', 'salesforce.com', 'oracle.com',
            'ibm.com', 'intel.com', 'cisco.com', 'adobe.com', 'vmware.com',
            'dell.com', 'hp.com', 'nvidia.com', 'amd.com', 'qualcomm.com',
            'uber.com', 'lyft.com', 'airbnb.com', 'spotify.com', 'zoom.us',
            'slack.com', 'dropbox.com', 'atlassian.com', 'github.com', 'gitlab.com',

            # Generic tech patterns
            'tech', 'software', 'systems', 'solutions', 'digital', 'cyber'
        }

    def classify_domains(self, df):
        """Classify domains in the email dataframe using email_domain consistently"""
        df_copy = df.copy()

        # Use email_domain if it exists, otherwise extract from sender
        if 'email_domain' not in df_copy.columns:
            df_copy['email_domain'] = df_copy['sender'].apply(self._extract_domain)

        # Use sender_domain from data if available, otherwise use email_domain
        if 'sender_domain' not in df_copy.columns:
            df_copy['sender_domain'] = df_copy['email_domain']

        # Ensure recipient_domain field exists for internal classification
        if 'recipient_domain' not in df_copy.columns:
            if 'recipients' in df_copy.columns:
                df_copy['recipient_domain'] = df_copy['recipients'].apply(self._extract_first_recipient_domain)
            else:
                df_copy['recipient_domain'] = ''

        # Extract recipient domains list for analysis
        if 'recipient_domains' not in df_copy.columns:
            if 'recipients' in df_copy.columns:
                df_copy['recipient_domains'] = df_copy['recipients'].apply(self._extract_recipient_domains)
            elif 'recipient_domain' in df_copy.columns:
                df_copy['recipient_domains'] = df_copy['recipient_domain'].apply(lambda x: [x] if pd.notna(x) and x != '' else [])

        # Classify email domains with internal domain detection
        df_copy['email_domain_type'] = df_copy.apply(self._classify_domain_with_internal_check, axis=1)
        df_copy['sender_domain_type'] = df_copy['email_domain_type']  # For compatibility

        # Add internal communication flag for dashboard visibility
        df_copy['is_internal_communication'] = df_copy.apply(self._check_internal_communication, axis=1)
        df_copy['sender_recipient_match'] = df_copy.apply(self._analyze_sender_recipient_match, axis=1)

        # Add industry classification for business domains
        df_copy['email_domain_industry'] = df_copy['email_domain'].apply(self.classify_business_industry)
        df_copy['sender_domain_industry'] = df_copy['email_domain_industry']  # For compatibility

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
            # Use email_domain classification as fallback
            df_copy['domain_type'] = df_copy['email_domain_type']

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

    def _extract_recipient_domains(self, recipients):
        """Extract unique domains from recipients string"""
        if pd.isna(recipients) or recipients == '':
            return []

        import re
        domains = []
        # Find all email addresses in the recipients string
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', str(recipients))
        for email in emails:
            domain = self._extract_domain(email)
            if domain:
                domains.append(domain)
        return list(set(domains))  # Remove duplicates

    def _extract_first_recipient_domain(self, recipients):
        """Extract first recipient domain from recipients string"""
        if pd.isna(recipients) or recipients == '':
            return ''

        import re
        # Find first email address in the recipients string
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', str(recipients))
        if emails:
            return self._extract_domain(emails[0])
        return ''

    def _classify_domain_with_internal_check(self, row):
        """Classify domain considering sender-recipient domain matching for internal detection"""
        # Get sender domain from multiple possible sources
        sender_domain = row.get('sender_domain', '') or row.get('email_domain', '')
        
        # Get recipient domain from the data
        recipient_domain = row.get('recipient_domain', '')
        
        if not sender_domain:
            return 'unknown'

        sender_clean = sender_domain.lower().strip()
        
        # CRITICAL: Check if sender domain is a free email domain - these are NEVER internal
        if sender_clean in self.free_email_domains:
            return 'free'
        
        # Check for internal communication: sender_domain == recipient_domain
        if recipient_domain and pd.notna(recipient_domain) and str(recipient_domain).strip() != '':
            recipient_clean = str(recipient_domain).lower().strip()
            
            # CRITICAL: If recipient domain is also a free email domain, this is NOT internal
            if recipient_clean in self.free_email_domains:
                return 'free'
            
            # Only classify as internal if both domains are non-free and match
            if sender_clean == recipient_clean:
                return 'internal'
        
        # For external domains, classify as business or public based on characteristics
        return self._classify_single_domain_strict(sender_clean)

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

    def _classify_single_domain_strict(self, domain):
        """Classify a single domain without internal heuristics - only use actual sender-recipient matching"""
        if not domain:
            return 'unknown'

        domain = domain.lower().strip()

        # Check if it's a free email provider
        if domain in self.free_email_domains:
            return 'free'

        # Skip internal domain pattern checking - only use actual sender-recipient matching
        # Check for business domain patterns
        if self._is_business_domain(domain):
            return 'business'

        # Default to business if it has business-like characteristics
        if self._has_business_characteristics(domain):
            return 'business'

        return 'public'

    def _check_internal_communication(self, row):
        """Check if email represents internal communication based on sender-recipient domain matching"""
        sender_domain = row.get('email_domain', '')
        recipient_domain = row.get('recipient_domain', '')  # Use the new recipient_domain field
        recipient_domains = row.get('recipient_domains', [])

        # Primary check: Use recipient_domain field
        if sender_domain and recipient_domain:
            sender_clean = sender_domain.lower().strip()
            recipient_clean = recipient_domain.lower().strip()
            return sender_clean == recipient_clean

        # Fallback: Use recipient_domains list
        if not sender_domain or not isinstance(recipient_domains, list):
            return False

        # Check for exact domain match (case-insensitive)
        sender_clean = sender_domain.lower().strip()
        recipient_clean = [rd.lower().strip() for rd in recipient_domains if rd]
        return sender_clean in recipient_clean

    def _analyze_sender_recipient_match(self, row):
        """Analyze sender-recipient domain matching details"""
        sender_domain = row.get('email_domain', '')
        recipient_domain = row.get('recipient_domain', '')  # Use the new recipient_domain field
        recipient_domains = row.get('recipient_domains', [])

        if not sender_domain:
            return 'no_sender_domain'

        # Primary check: Use recipient_domain field
        if recipient_domain:
            sender_clean = sender_domain.lower().strip()
            recipient_clean = recipient_domain.lower().strip()
            if sender_clean == recipient_clean:
                return f'internal_match_{sender_domain}'
            else:
                return f'external_to_{recipient_domain}'

        # Fallback: Use recipient_domains list
        if not isinstance(recipient_domains, list):
            return 'no_match_data'

        # Check for exact domain match (case-insensitive)
        sender_clean = sender_domain.lower().strip()
        recipient_clean = [rd.lower().strip() for rd in recipient_domains if rd]
        if sender_clean in recipient_clean:
            return f'internal_match_{sender_domain}'
        elif len(recipient_domains) > 0:
            return f'external_to_{",".join(recipient_domains[:3])}'  # Show up to 3 domains
        else:
            return 'no_recipients'

    def classify_business_industry(self, domain):
        """Classify business domains by industry sector"""
        if not domain:
            return 'unknown'

        domain = domain.lower().strip()

        # Only classify if it's a business domain
        domain_type = self._classify_single_domain(domain)
        if domain_type not in ['business', 'internal']:
            return 'not_business'

        # Check for banking/financial
        if self._is_industry_domain(domain, self.banking_domains):
            return 'banking'

        # Check for education
        if self._is_industry_domain(domain, self.education_domains):
            return 'education'

        # Check for healthcare
        if self._is_industry_domain(domain, self.healthcare_domains):
            return 'healthcare'

        # Check for government
        if self._is_industry_domain(domain, self.government_domains):
            return 'government'

        # Check for technology
        if self._is_industry_domain(domain, self.technology_domains):
            return 'technology'

        return 'business_other'

    def _is_industry_domain(self, domain, industry_domains):
        """Check if domain belongs to specific industry"""
        # Direct match
        if domain in industry_domains:
            return True

        # Pattern matching for partial matches
        for pattern in industry_domains:
            if isinstance(pattern, str):
                if len(pattern) > 3 and pattern in domain:
                    return True

        return False

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
        """Check if domain appears to be internal - very restrictive to avoid false positives"""
        # Only classify as internal if it's clearly an internal infrastructure domain
        # Domains with "internal" in the name but with public TLDs are likely business domains
        strict_internal_indicators = [
            '.local',           # True local domains
            'localhost',        # Localhost
            '192.168.',         # Private IP ranges
            '10.',              # Private IP ranges  
            '172.16.',          # Private IP ranges (more specific)
            '172.17.',          # Private IP ranges (more specific)
            '172.18.',          # Private IP ranges (more specific)
            '172.19.',          # Private IP ranges (more specific)
            '172.20.',          # Private IP ranges (more specific)
            '172.21.',          # Private IP ranges (more specific)
            '172.22.',          # Private IP ranges (more specific)
            '172.23.',          # Private IP ranges (more specific)
            '172.24.',          # Private IP ranges (more specific)
            '172.25.',          # Private IP ranges (more specific)
            '172.26.',          # Private IP ranges (more specific)
            '172.27.',          # Private IP ranges (more specific)
            '172.28.',          # Private IP ranges (more specific)
            '172.29.',          # Private IP ranges (more specific)
            '172.30.',          # Private IP ranges (more specific)
            '172.31.',          # Private IP ranges (more specific)
        ]

        # Check for exact matches only - don't classify domains like "internal.company.com" as internal
        # unless they actually match sender-recipient domains
        return any(domain.startswith(indicator) or domain == indicator.rstrip('.') for indicator in strict_internal_indicators)

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

        # Top domains by type - use email_domain consistently
        if 'email_domain' in df.columns:
            stats['top_domains_by_type'] = {}

            for domain_type in domain_counts.index:
                type_domains = df[df['domain_type'] == domain_type]['email_domain']
                top_domains = type_domains.value_counts().head(5)
                stats['top_domains_by_type'][domain_type] = top_domains.to_dict()
        elif 'sender_domain' in df.columns:
            # Fallback to sender_domain for backward compatibility
            stats['top_domains_by_type'] = {}

            for domain_type in domain_counts.index:
                type_domains = df[df['domain_type'] == domain_type]['sender_domain']
                top_domains = type_domains.value_counts().head(5)
                stats['top_domains_by_type'][domain_type] = top_domains.to_dict()

        return stats

    def identify_suspicious_domains(self, df):
        """Identify potentially suspicious domains using email_domain consistently"""
        suspicious_domains = []

        # Use email_domain if available, fallback to sender_domain
        domain_column = 'email_domain' if 'email_domain' in df.columns else 'sender_domain'

        if domain_column not in df.columns:
            return suspicious_domains

        domain_counts = df[domain_column].value_counts()

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