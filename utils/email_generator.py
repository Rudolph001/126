import pandas as pd
from datetime import datetime

class EmailGenerator:
    """Generates polite follow-up emails for flagged security incidents"""
    
    def __init__(self):
        self.templates = {
            'Security Inquiry': {
                'subject': 'Security Review Required: Email Activity Alert',
                'body': """Dear [SENDER_NAME],

I hope this message finds you well. As part of our ongoing commitment to data security, we have identified some email activity that requires review.

Details:
- Email sent on: [EMAIL_DATE]
- Recipients: [RECIPIENTS]
- Risk Score: [RISK_SCORE]
- Reason for Review: [RISK_FACTORS]

This is a routine security measure to ensure compliance with our data protection policies. Please reply to this email with:

1. Confirmation that the email was sent intentionally
2. Brief description of the business purpose
3. Any additional context you feel is relevant

If you have any questions or concerns, please don't hesitate to contact our IT Security team.

Best regards,
IT Security Team
Email: security@company.com
Phone: (555) 123-4567"""
            },
            
            'Data Classification Review': {
                'subject': 'Data Classification Review Required: [EMAIL_SUBJECT]',
                'body': """Dear [SENDER_NAME],

We are conducting a routine review of email communications that may contain sensitive information.

Email Details:
- Date: [EMAIL_DATE]
- Subject: [EMAIL_SUBJECT]
- Recipients: [RECIPIENTS]
- Risk Assessment: [RISK_LEVEL]

As part of our data governance procedures, we need to verify:

1. The classification level of the information shared
2. Whether recipients are authorized to receive this information
3. If any additional security measures should be applied

Please respond within 2 business days with:
- Confirmation of data sensitivity level (Public, Internal, Confidential, Restricted)
- Justification for sharing with external recipients (if applicable)
- Any remedial actions you recommend

Thank you for your cooperation in maintaining our security standards.

Best regards,
Data Governance Team
Email: datagovernance@company.com"""
            },
            
            'Policy Reminder': {
                'subject': 'Reminder: Email Security Best Practices',
                'body': """Dear [SENDER_NAME],

This is a friendly reminder about our email security policies following recent activity that triggered our monitoring systems.

Recent Activity Summary:
- Date: [EMAIL_DATE]
- Risk Indicators: [RISK_FACTORS]

Please remember these key email security practices:

1. Verify recipient email addresses before sending sensitive information
2. Use secure file sharing services for large or confidential documents
3. Be cautious when emailing personal email addresses or free email providers
4. Consider email encryption for highly sensitive communications
5. Report any suspicious email activity immediately

For questions about appropriate email usage or security tools, please contact:
- IT Security Team: security@company.com
- Help Desk: (555) 123-4567

Thank you for helping us maintain a secure email environment.

Best regards,
IT Security Team"""
            }
        }
    
    def get_template(self, email_type):
        """Get email template by type"""
        template = self.templates.get(email_type, self.templates['Security Inquiry'])
        return template['subject'], template['body']
    
    def generate_email(self, email_data, subject_template, body_template):
        """Generate a follow-up email based on template and email data"""
        # Extract data for template replacement
        sender = email_data.get('sender', 'Unknown')
        sender_name = self._extract_name_from_email(sender)
        email_date = self._format_date(email_data.get('time'))
        recipients = str(email_data.get('recipients', 'Unknown'))
        subject = str(email_data.get('subject', 'No Subject'))
        risk_score = email_data.get('risk_score', 0)
        risk_level = email_data.get('risk_level', 'Unknown')
        
        # Generate risk factors description
        risk_factors = self._generate_risk_factors_description(email_data)
        
        # Replace placeholders in subject
        generated_subject = subject_template
        replacements = {
            '[SENDER_NAME]': sender_name,
            '[EMAIL_DATE]': email_date,
            '[EMAIL_SUBJECT]': subject,
            '[RISK_SCORE]': f"{risk_score:.1f}",
            '[RISK_LEVEL]': risk_level
        }
        
        for placeholder, value in replacements.items():
            generated_subject = generated_subject.replace(placeholder, value)
        
        # Replace placeholders in body
        generated_body = body_template
        body_replacements = {
            '[SENDER_NAME]': sender_name,
            '[EMAIL_DATE]': email_date,
            '[RECIPIENTS]': recipients,
            '[EMAIL_SUBJECT]': subject,
            '[RISK_SCORE]': f"{risk_score:.1f}",
            '[RISK_LEVEL]': risk_level,
            '[RISK_FACTORS]': risk_factors
        }
        
        for placeholder, value in body_replacements.items():
            generated_body = generated_body.replace(placeholder, value)
        
        return {
            'to': sender,
            'subject': generated_subject,
            'body': generated_body,
            'generated_at': datetime.now().isoformat(),
            'original_email_data': {
                'date': email_date,
                'subject': subject,
                'risk_score': risk_score,
                'risk_level': risk_level
            }
        }
    
    def _extract_name_from_email(self, email):
        """Extract name from email address"""
        if pd.isna(email) or '@' not in str(email):
            return 'Colleague'
        
        # Extract username part and clean it up
        username = str(email).split('@')[0]
        
        # Handle common name patterns
        if '.' in username:
            parts = username.split('.')
            # Assume firstname.lastname pattern
            if len(parts) >= 2:
                first_name = parts[0].capitalize()
                last_name = parts[1].capitalize()
                return f"{first_name} {last_name}"
        
        # Just capitalize the username
        return username.capitalize()
    
    def _format_date(self, date_value):
        """Format date for email template"""
        if pd.isna(date_value):
            return 'Unknown Date'
        
        try:
            if isinstance(date_value, str):
                date_obj = pd.to_datetime(date_value)
            else:
                date_obj = date_value
            
            return date_obj.strftime('%B %d, %Y at %I:%M %p')
        except:
            return str(date_value)
    
    def _generate_risk_factors_description(self, email_data):
        """Generate human-readable description of risk factors"""
        factors = []
        
        # Check various risk indicators
        if email_data.get('is_after_hours', False):
            factors.append("Email sent outside business hours")
        
        if email_data.get('is_leaver', False):
            factors.append("Sent within 7 days of employee's last working day")
        
        if email_data.get('has_attachments', False):
            factors.append("Contains attachments")
        
        if email_data.get('has_new_domain', False):
            factors.append("Sent to new external domain")
        
        if email_data.get('has_burst_pattern', False):
            factors.append("Part of high-volume email burst")
        
        # Domain type risk
        domain_type = email_data.get('domain_type', '')
        if domain_type == 'free':
            factors.append("Sent to free email provider")
        elif domain_type == 'public':
            factors.append("Sent to external domain")
        
        # Risk score based factors
        risk_score = email_data.get('risk_score', 0)
        if risk_score >= 61:
            factors.append("High risk score calculated")
        elif risk_score >= 31:
            factors.append("Medium risk score calculated")
        
        # Recipient count
        recipient_count = email_data.get('recipient_count', 0)
        if recipient_count > 10:
            factors.append(f"Large number of recipients ({recipient_count})")
        
        if not factors:
            return "General security review"
        
        return "; ".join(factors)
    
    def generate_bulk_emails(self, email_list, email_type='Security Inquiry'):
        """Generate multiple follow-up emails"""
        subject_template, body_template = self.get_template(email_type)
        
        generated_emails = []
        
        for email_data in email_list:
            try:
                email = self.generate_email(email_data, subject_template, body_template)
                generated_emails.append(email)
            except Exception as e:
                # Log error and continue with other emails
                error_email = {
                    'to': email_data.get('sender', 'Unknown'),
                    'subject': 'Error generating follow-up email',
                    'body': f'Error occurred while generating follow-up email: {str(e)}',
                    'generated_at': datetime.now().isoformat(),
                    'error': str(e)
                }
                generated_emails.append(error_email)
        
        return generated_emails
    
    def create_summary_report(self, generated_emails):
        """Create summary report of generated follow-up emails"""
        if not generated_emails:
            return {
                'total_emails': 0,
                'successful': 0,
                'errors': 0,
                'summary': 'No emails generated'
            }
        
        total_emails = len(generated_emails)
        errors = len([email for email in generated_emails if 'error' in email])
        successful = total_emails - errors
        
        # Risk level breakdown
        risk_levels = {}
        for email in generated_emails:
            if 'original_email_data' in email:
                risk_level = email['original_email_data'].get('risk_level', 'Unknown')
                risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1
        
        summary = {
            'total_emails': total_emails,
            'successful': successful,
            'errors': errors,
            'success_rate': f"{(successful/total_emails)*100:.1f}%" if total_emails > 0 else "0%",
            'risk_level_breakdown': risk_levels,
            'generated_at': datetime.now().isoformat()
        }
        
        return summary
    
    def export_emails_to_csv(self, generated_emails):
        """Export generated emails to CSV format"""
        if not generated_emails:
            return pd.DataFrame()
        
        email_records = []
        
        for email in generated_emails:
            record = {
                'recipient': email.get('to', ''),
                'subject': email.get('subject', ''),
                'body': email.get('body', ''),
                'generated_at': email.get('generated_at', ''),
                'has_error': 'error' in email
            }
            
            # Add original email data if available
            if 'original_email_data' in email:
                original_data = email['original_email_data']
                record.update({
                    'original_date': original_data.get('date', ''),
                    'original_subject': original_data.get('subject', ''),
                    'risk_score': original_data.get('risk_score', 0),
                    'risk_level': original_data.get('risk_level', '')
                })
            
            email_records.append(record)
        
        return pd.DataFrame(email_records)
    
    def validate_email_template(self, subject_template, body_template):
        """Validate email template for required placeholders"""
        required_placeholders = ['[SENDER_NAME]', '[EMAIL_DATE]']
        optional_placeholders = [
            '[RECIPIENTS]', '[EMAIL_SUBJECT]', '[RISK_SCORE]', 
            '[RISK_LEVEL]', '[RISK_FACTORS]'
        ]
        
        validation_result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'placeholders_found': []
        }
        
        combined_template = f"{subject_template} {body_template}"
        
        # Check for required placeholders
        for placeholder in required_placeholders:
            if placeholder in combined_template:
                validation_result['placeholders_found'].append(placeholder)
            else:
                validation_result['valid'] = False
                validation_result['errors'].append(f"Required placeholder missing: {placeholder}")
        
        # Check for optional placeholders
        for placeholder in optional_placeholders:
            if placeholder in combined_template:
                validation_result['placeholders_found'].append(placeholder)
        
        # Check for unknown placeholders
        import re
        all_placeholders = re.findall(r'\[([A-Z_]+)\]', combined_template)
        known_placeholders = [p[1:-1] for p in required_placeholders + optional_placeholders]
        
        for placeholder in all_placeholders:
            if placeholder not in known_placeholders:
                validation_result['warnings'].append(f"Unknown placeholder: [{placeholder}]")
        
        return validation_result
