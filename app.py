import streamlit as st
import pandas as pd
import os
from datetime import datetime, timedelta
import io

# Import utility modules
from utils.data_processor import DataProcessor
from utils.risk_engine import RiskEngine
from utils.anomaly_detector import AnomalyDetector
from utils.domain_classifier import DomainClassifier
from utils.visualization import Visualizer
from utils.email_generator import EmailGenerator
from utils.keyword_detector import KeywordDetector

# Page configuration
st.set_page_config(
    page_title="ExfilEye - DLP Email Monitor",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'email_data' not in st.session_state:
    st.session_state.email_data = None
if 'whitelist_data' not in st.session_state:
    st.session_state.whitelist_data = pd.DataFrame(columns=['email_address', 'domain'])
if 'processed_data' not in st.session_state:
    st.session_state.processed_data = None
if 'risk_scores' not in st.session_state:
    st.session_state.risk_scores = None

def main():
    st.title("🔍 ExfilEye - DLP Email Monitor")

    # Initialize components
    data_processor = DataProcessor()
    risk_engine = RiskEngine()
    anomaly_detector = AnomalyDetector()
    domain_classifier = DomainClassifier()
    visualizer = Visualizer()
    email_generator = EmailGenerator()
    keyword_detector = KeywordDetector()

    # Sidebar navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.radio(
        "Select Page",
        ["📁 Data Upload", "📊 Dashboard", "📈 Analytics", "📊 Email Volume Metrics: Mimecast vs Tessian", "🏢 Enhanced Domain Analysis", "📧 Follow-up Actions", "🔄 App Flow Dashboard"]
    )

    if page == "📁 Data Upload":
        data_upload_page(data_processor, domain_classifier, keyword_detector)
    elif page == "📊 Dashboard":
        dashboard_page(risk_engine, anomaly_detector, visualizer)
    elif page == "📈 Analytics":
        analytics_page(visualizer, anomaly_detector)
    elif page == "📊 Email Volume Metrics: Mimecast vs Tessian":
        security_coverage_page()
    elif page == "🏢 Enhanced Domain Analysis":
        enhanced_domain_analysis_page(domain_classifier)
    elif page == "🔄 App Flow Dashboard":
        app_flow_dashboard_page()
    elif page == "📧 Follow-up Actions":
        follow_up_actions_page(email_generator)

def security_coverage_page():
    st.header("📊 Email Volume Metrics: Mimecast vs Tessian")
    
    if st.session_state.processed_data is None:
        st.warning("Please upload email data first in the Data Upload page.")
        return
    
    df = st.session_state.processed_data.copy()
    
    # Add explanatory note about security tool coverage
    st.info("""
    📋 **Security Tool Coverage Information**
    
    This analysis shows email security coverage based on two key protection systems:
    - **Tessian**: Email security solution for threat detection and data loss prevention
    - **Mimecast**: Email security platform providing comprehensive email protection
    
    The coverage categories are:
    - **Full Coverage**: Protected by both Tessian and Mimecast
    - **Partial Coverage**: Protected by either Tessian or Mimecast (but not both)
    - **No Coverage**: Not protected by either security tool
    """)
    
    # Security Tool Coverage Analysis
    def get_security_coverage(row):
        """Determine security coverage based on Tessian and Mimecast columns"""
        tessian = str(row.get('tessian', '')).strip().lower() if pd.notna(row.get('tessian', '')) else ''
        mimecast = str(row.get('mimecast', '')).strip().lower() if pd.notna(row.get('mimecast', '')) else ''
        
        has_tessian = tessian not in ['', '0', 'false', 'none', 'null']
        has_mimecast = mimecast not in ['', '0', 'false', 'none', 'null']
        
        if has_tessian and has_mimecast:
            return "Full Coverage"
        elif has_tessian or has_mimecast:
            if has_tessian:
                return "Missing Mimecast"
            else:
                return "Missing Tessian"
        else:
            return "No Coverage"
    
    # Add security coverage analysis
    df['security_coverage'] = df.apply(get_security_coverage, axis=1)
    
    # Coverage Statistics
    st.subheader("📊 Security Coverage Overview")
    
    coverage_counts = df['security_coverage'].value_counts()
    total_emails = len(df)
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        full_coverage = coverage_counts.get('Full Coverage', 0)
        full_pct = (full_coverage / total_emails * 100) if total_emails > 0 else 0
        st.metric(
            "🟢 Full Coverage", 
            f"{full_coverage:,}",
            f"{full_pct:.1f}% of total"
        )
    
    with col2:
        missing_mimecast = coverage_counts.get('Missing Mimecast', 0)
        missing_mimecast_pct = (missing_mimecast / total_emails * 100) if total_emails > 0 else 0
        st.metric(
            "🟡 Missing Mimecast", 
            f"{missing_mimecast:,}",
            f"{missing_mimecast_pct:.1f}% of total"
        )
    
    with col3:
        missing_tessian = coverage_counts.get('Missing Tessian', 0)
        missing_tessian_pct = (missing_tessian / total_emails * 100) if total_emails > 0 else 0
        st.metric(
            "🟡 Missing Tessian", 
            f"{missing_tessian:,}",
            f"{missing_tessian_pct:.1f}% of total"
        )
    
    with col4:
        no_coverage = coverage_counts.get('No Coverage', 0)
        no_coverage_pct = (no_coverage / total_emails * 100) if total_emails > 0 else 0
        st.metric(
            "🔴 No Coverage", 
            f"{no_coverage:,}",
            f"{no_coverage_pct:.1f}% of total"
        )
    
    # Visual representation
    st.subheader("📈 Coverage Distribution")
    
    import plotly.express as px
    
    # Create pie chart for coverage distribution
    coverage_df = pd.DataFrame({
        'Coverage Type': coverage_counts.index,
        'Count': coverage_counts.values,
        'Percentage': (coverage_counts.values / total_emails * 100)
    })
    
    colors = {
        'Full Coverage': '#28a745',
        'Missing Mimecast': '#ffc107', 
        'Missing Tessian': '#fd7e14',
        'No Coverage': '#dc3545'
    }
    
    fig = px.pie(
        coverage_df, 
        values='Count', 
        names='Coverage Type',
        title='Security Tool Coverage Distribution',
        color='Coverage Type',
        color_discrete_map=colors
    )
    
    fig.update_traces(
        textposition='inside', 
        textinfo='percent+label',
        hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Detailed Analysis by Coverage Type
    st.subheader("🔍 Detailed Coverage Analysis")
    
    coverage_tabs = st.tabs(["🔴 No Coverage", "🟡 Partial Coverage", "🟢 Full Coverage"])
    
    with coverage_tabs[0]:  # No Coverage
        no_coverage_emails = df[df['security_coverage'] == 'No Coverage']
        if not no_coverage_emails.empty:
            st.write(f"**{len(no_coverage_emails):,} emails with no security tool coverage**")
            st.warning("⚠️ These emails are not protected by either Tessian or Mimecast")
            
            # Show sample of unprotected emails
            display_cols = ['sender', 'subject', 'time', 'recipients']
            available_cols = [col for col in display_cols if col in no_coverage_emails.columns]
            if available_cols:
                st.dataframe(no_coverage_emails[available_cols].head(20), use_container_width=True)
            
            # Domain analysis for unprotected emails
            if 'email_domain' in no_coverage_emails.columns:
                st.write("**Top domains without coverage:**")
                domain_counts = no_coverage_emails['email_domain'].value_counts().head(10)
                for domain, count in domain_counts.items():
                    pct = (count / len(no_coverage_emails) * 100)
                    st.write(f"• **{domain}**: {count:,} emails ({pct:.1f}%)")
        else:
            st.success("✅ All emails have at least partial security coverage")
    
    with coverage_tabs[1]:  # Partial Coverage
        partial_coverage = df[df['security_coverage'].isin(['Missing Mimecast', 'Missing Tessian'])]
        if not partial_coverage.empty:
            st.write(f"**{len(partial_coverage):,} emails with partial security coverage**")
            
            # Break down by missing tool
            missing_breakdown = partial_coverage['security_coverage'].value_counts()
            
            col_a, col_b = st.columns(2)
            with col_a:
                missing_tessian_count = missing_breakdown.get('Missing Tessian', 0)
                st.metric("Missing Tessian Only", f"{missing_tessian_count:,}")
            
            with col_b:
                missing_mimecast_count = missing_breakdown.get('Missing Mimecast', 0)
                st.metric("Missing Mimecast Only", f"{missing_mimecast_count:,}")
            
            # Show sample
            display_cols = ['sender', 'subject', 'time', 'security_coverage']
            available_cols = [col for col in display_cols if col in partial_coverage.columns]
            if available_cols:
                st.dataframe(partial_coverage[available_cols].head(20), use_container_width=True)
        else:
            st.info("No emails with partial coverage found")
    
    with coverage_tabs[2]:  # Full Coverage
        full_coverage_emails = df[df['security_coverage'] == 'Full Coverage']
        if not full_coverage_emails.empty:
            st.write(f"**{len(full_coverage_emails):,} emails with full security coverage**")
            st.success("✅ These emails are protected by both Tessian and Mimecast")
            
            # Show sample
            display_cols = ['sender', 'subject', 'time', 'recipients']
            available_cols = [col for col in display_cols if col in full_coverage_emails.columns]
            if available_cols:
                st.dataframe(full_coverage_emails[available_cols].head(10), use_container_width=True)
            
            # Domain analysis for protected emails
            if 'email_domain' in full_coverage_emails.columns:
                st.write("**Top protected domains:**")
                domain_counts = full_coverage_emails['email_domain'].value_counts().head(10)
                for domain, count in domain_counts.items():
                    pct = (count / len(full_coverage_emails) * 100)
                    st.write(f"• **{domain}**: {count:,} emails ({pct:.1f}%)")
        else:
            st.warning("No emails with full coverage found")
    
    # Recommendations
    st.subheader("📋 Security Recommendations")
    
    if no_coverage > 0:
        st.error(f"🚨 **Priority Action Required**: {no_coverage:,} emails lack any security tool protection")
        st.write("**Immediate Actions:**")
        st.write("• Review and configure Tessian/Mimecast for unprotected domains")
        st.write("• Implement additional monitoring for unprotected email traffic")
        st.write("• Consider policy enforcement for high-risk unprotected communications")
    
    if missing_tessian > 0 or missing_mimecast > 0:
        st.warning(f"⚠️ **Configuration Gap**: {missing_tessian + missing_mimecast:,} emails have partial protection")
        st.write("**Optimization Actions:**")
        st.write("• Ensure both Tessian and Mimecast are properly configured for all domains")
        st.write("• Review security tool licensing and coverage scope")
        st.write("• Implement consistent protection policies across all email communications")
    
    if full_coverage >= (total_emails * 0.8):
        st.success("✅ **Good Security Posture**: Majority of emails have comprehensive protection")
    
def reports_page():
    st.header("📋 Reports")
    
    if st.session_state.processed_data is None:
        st.warning("Please upload email data first in the Data Upload page.")
        return
    
    df = st.session_state.processed_data.copy()
    
    st.subheader("Generate Reports")
    
    # Report type selection
    report_type = st.selectbox(
        "Select Report Type",
        ["Executive Summary", "Detailed Risk Analysis", "Domain Analysis", "Security Coverage Report"]
    )
    
    if st.button("Generate Report"):
        if report_type == "Executive Summary":
            st.subheader("Executive Summary Report")
            
            total_emails = len(df)
            high_risk = len(df[df['risk_level'] == 'High']) if 'risk_level' in df.columns else 0
            
            st.write(f"**Total Emails Analyzed:** {total_emails:,}")
            st.write(f"**High Risk Emails:** {high_risk:,}")
            st.write(f"**Risk Percentage:** {(high_risk/total_emails*100):.1f}%" if total_emails > 0 else "0%")
            
        elif report_type == "Detailed Risk Analysis":
            st.subheader("Detailed Risk Analysis Report")
            
            if 'risk_score' in df.columns:
                st.write("**Risk Score Distribution:**")
                risk_summary = df['risk_score'].describe()
                st.dataframe(risk_summary)
            else:
                st.info("Risk scores not available")
                
        elif report_type == "Domain Analysis":
            st.subheader("Domain Analysis Report")
            
            if 'email_domain' in df.columns:
                domain_counts = df['email_domain'].value_counts().head(20)
                st.write("**Top 20 Email Domains:**")
                st.dataframe(domain_counts)
            else:
                st.info("Domain data not available")
                
        elif report_type == "Security Coverage Report":
            st.subheader("Security Coverage Report")
            
            if 'security_coverage' in df.columns:
                coverage_counts = df['security_coverage'].value_counts()
                st.write("**Security Tool Coverage:**")
                st.dataframe(coverage_counts)
            else:
                st.info("Security coverage data not available")

def data_upload_page(data_processor, domain_classifier, keyword_detector):
    st.header("📁 Data Upload")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Email Data Upload")
        uploaded_file = st.file_uploader(
            "Upload Email Data (CSV)",
            type=['csv'],
            help="Required fields: time, sender, sender_domain, recipients, recipient_domain, email_domain, word_list_match, recipient_status, subject, attachments, act, delivered, deliveryErrors, direction, eventtype, aggreatedid, tessian, tessian_response, mimecast, tessian_outcome, tessian_policy, last_working_day, bunit, department, businessPillar"
        )

        if uploaded_file is not None:
            try:
                # Load and validate data
                df = pd.read_csv(uploaded_file)

                # Check required fields
                required_fields = [
                    'time', 'sender', 'sender_domain', 'recipients', 'recipient_domain', 'email_domain', 'word_list_match',
                    'recipient_status', 'subject', 'attachments', 'act', 'delivered',
                    'deliveryErrors', 'direction', 'eventtype', 'aggreatedid', 'tessian',
                    'tessian_response', 'mimecast', 'tessian_outcome', 'tessian_policy',
                    'last_working_day', 'bunit', 'department', 'businessPillar'
                ]

                missing_fields = [field for field in required_fields if field not in df.columns]

                if missing_fields:
                    st.error(f"Missing required fields: {', '.join(missing_fields)}")
                else:
                    # Process the data
                    processed_df = data_processor.process_email_data(df)

                    # Apply domain classification
                    processed_df = domain_classifier.classify_domains(processed_df)

                    # Apply keyword detection
                    processed_df = keyword_detector.detect_keywords(processed_df)

                    # Store in session state
                    st.session_state.email_data = df
                    st.session_state.processed_data = processed_df

                    st.success(f"Successfully loaded {len(df)} email records")
                    st.info(f"Data shape: {df.shape}")

                    # Show preview
                    st.subheader("Data Preview")
                    st.dataframe(processed_df.head())

            except Exception as e:
                st.error(f"Error processing file: {str(e)}")

    with col2:
        st.subheader("BAU Whitelist Upload")
        whitelist_file = st.file_uploader(
            "Upload Whitelist (CSV)",
            type=['csv'],
            key="whitelist_upload",
            help="Fields: email_address, domain"
        )

        if whitelist_file is not None:
            try:
                whitelist_df = pd.read_csv(whitelist_file)

                # Validate whitelist fields
                if 'email_address' in whitelist_df.columns and 'domain' in whitelist_df.columns:
                    st.session_state.whitelist_data = whitelist_df
                    st.success(f"Successfully loaded {len(whitelist_df)} whitelist entries")
                    st.dataframe(whitelist_df.head())
                else:
                    st.error("Whitelist CSV must contain 'email_address' and 'domain' columns")

            except Exception as e:
                st.error(f"Error processing whitelist file: {str(e)}")

def whitelist_management_page():
    st.header("⚙️ BAU Whitelist Management")

    # Display current whitelist
    st.subheader("Current Whitelist Entries")

    if not st.session_state.whitelist_data.empty:
        # Make the dataframe editable
        edited_df = st.data_editor(
            st.session_state.whitelist_data,
            num_rows="dynamic",
            use_container_width=True,
            key="whitelist_editor",
            column_config={
                "email_address": "Email Address",
                "domain": "Domain"
            }
        )

        # Update session state with edits
        st.session_state.whitelist_data = edited_df

        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button("💾 Save Changes"):
                st.success("Whitelist updated successfully!")
                st.rerun()

        with col2:
            # Download whitelist
            csv_buffer = io.StringIO()
            edited_df.to_csv(csv_buffer, index=False)
            st.download_button(
                label="📥 Download Whitelist",
                data=csv_buffer.getvalue(),
                file_name=f"whitelist_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )

        with col3:
            if st.button("🗑️ Clear All", type="secondary"):
                st.session_state.whitelist_data = pd.DataFrame(columns=['email_address', 'domain'])
                st.rerun()
    else:
        st.info("No whitelist entries found. Add entries using the editor below or upload a CSV file.")

        # Create new whitelist entry form
        st.subheader("Add New Entry")
        new_entry_df = pd.DataFrame(columns=['email_address', 'domain'])
        new_entry_df = st.data_editor(
            new_entry_df,
            num_rows="dynamic",
            use_container_width=True,
            key="new_whitelist_editor",
            column_config={
                "email_address": "Email Address",
                "domain": "Domain"
            }
        )

        if st.button("➕ Add Entries"):
            if not new_entry_df.empty:
                st.session_state.whitelist_data = pd.concat([st.session_state.whitelist_data, new_entry_df], ignore_index=True)
                st.success(f"Added {len(new_entry_df)} new entries!")
                st.rerun()

def follow_up_actions_page(email_generator):
    st.header("📧 Follow-up Actions")
    
    if st.session_state.processed_data is None:
        st.warning("Please upload email data first in the Data Upload page.")
        return
    
    df = st.session_state.processed_data.copy()
    
    if st.session_state.risk_scores is not None:
        df['risk_score'] = st.session_state.risk_scores
        df['risk_level'] = df['risk_score'].apply(lambda x: 
            'High' if x >= 61 else 'Medium' if x >= 31 else 'Low'
        )
        
        # Filter high-risk emails for follow-up
        high_risk_emails = df[df['risk_level'] == 'High']
        
        if not high_risk_emails.empty:
            st.subheader("High-Risk Emails Requiring Follow-up")
            
            # Show high-risk emails table
            display_columns = ['sender', 'subject', 'time', 'recipients', 'risk_score', 'risk_level']
            available_columns = [col for col in display_columns if col in high_risk_emails.columns]
            st.dataframe(high_risk_emails[available_columns], use_container_width=True)
            
            # Email generation options
            st.subheader("Generate Follow-up Emails")
            
            email_type = st.selectbox(
                "Select Email Type",
                ["Security Inquiry", "Data Review Request", "Policy Reminder"]
            )
            
            if st.button("Generate Follow-up Emails"):
                with st.spinner("Generating follow-up emails..."):
                    generated_emails = email_generator.generate_bulk_emails(
                        high_risk_emails.to_dict('records'),
                        email_type
                    )
                    
                    if generated_emails:
                        st.success(f"Generated {len(generated_emails)} follow-up emails")
                        
                        # Display generated emails
                        for i, email in enumerate(generated_emails):
                            recipient = email.get('recipient', email.get('to', 'Unknown Recipient'))
                            with st.expander(f"Email {i+1}: {recipient}"):
                                st.text_area("Subject", value=email.get('subject', ''), height=50)
                                st.text_area("Body", value=email.get('body', ''), height=200)
                        
                        # Export option
                        if st.button("Export Emails to CSV"):
                            csv_data = email_generator.export_emails_to_csv(generated_emails)
                            st.download_button(
                                label="Download Email Templates",
                                data=csv_data,
                                file_name=f"follow_up_emails_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                                mime="text/csv"
                            )
        else:
            st.info("No high-risk emails found that require follow-up actions.")
    else:
        st.warning("Risk scores not calculated. Please visit the Dashboard page first to calculate risk scores.")

def dashboard_page(risk_engine, anomaly_detector, visualizer):
    # Professional header with custom styling
    st.markdown("""
    <div style="background: linear-gradient(90deg, #1f4e79 0%, #2c5aa0 100%); padding: 2rem; border-radius: 10px; margin-bottom: 2rem;">
        <h1 style="color: white; margin: 0; font-size: 2.5rem; font-weight: 600;">
            🔐 Security Dashboard
        </h1>
        <p style="color: #e8f4fd; margin: 0.5rem 0 0 0; font-size: 1.1rem;">
            Real-time Email Security Monitoring & Risk Analysis
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Add explanatory note about security tool coverage
    st.info("""
    ℹ️ **Security Tool Coverage Note:** 
    Tessian operates on policy-driven detection and selectively monitors email events based on configured security policies. 
    It targets communications containing sensitive information patterns, suspicious attachments, and potential data loss scenarios. 
    Not all emails will show Tessian coverage as it focuses resources on emails matching specific security criteria and 
    organizational risk policies, rather than monitoring every email event.
    """)

    if st.session_state.processed_data is None:
        st.markdown("""
        <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; padding: 1rem; margin: 1rem 0;">
            <div style="color: #856404; font-weight: 500;">
                ⚠️ Data Required
            </div>
            <div style="color: #856404; margin-top: 0.5rem;">
                Please upload email data first in the Data Upload page to view security analytics.
            </div>
        </div>
        """, unsafe_allow_html=True)
        return

    # Calculate risk scores
    if st.session_state.risk_scores is None:
        with st.spinner("🔄 Calculating risk scores..."):
            risk_scores = risk_engine.calculate_risk_scores(
                st.session_state.processed_data,
                st.session_state.whitelist_data
            )
            st.session_state.risk_scores = risk_scores

    df = st.session_state.processed_data.copy()
    risk_scores = st.session_state.risk_scores

    # Add risk scores to dataframe
    df['risk_score'] = risk_scores
    df['risk_level'] = df['risk_score'].apply(lambda x: 
        'High Risk' if x >= 61 else 'Medium Risk' if x >= 31 else 'Normal'
    )
    
    # Apply domain classification if not already done
    from utils.domain_classifier import DomainClassifier
    domain_classifier = DomainClassifier()
    if 'email_domain_type' not in df.columns:
        df = domain_classifier.classify_domains(df)

    # Professional KPI Cards
    st.markdown("""
    <style>
    .metric-card {
        background: white;
        padding: 1.5rem;
        border-radius: 12px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        border-left: 4px solid;
        margin-bottom: 1rem;
        transition: transform 0.2s;
        height: 120px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 16px rgba(0,0,0,0.15);
    }
    .metric-value {
        font-size: 2.2rem;
        font-weight: 700;
        margin: 0;
    }
    .metric-label {
        font-size: 0.9rem;
        color: #666;
        margin: 0;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .metric-delta {
        font-size: 0.8rem;
        margin-top: 0.5rem;
        font-weight: 500;
    }
    </style>
    """, unsafe_allow_html=True)

    # Prepare email data with attachment status first
    df['has_attachments_bool'] = df['attachments'].notna() & (df['attachments'] != '') & (df['attachments'].astype(str) != '0')
    df['has_last_working_day'] = df['last_working_day'].notna()
    
    # Add security tool coverage analysis
    def get_security_coverage(row):
        has_tessian = pd.notna(row.get('tessian_policy')) and str(row.get('tessian_policy')).strip() not in ['', '0', 'nan', 'None']
        has_mimecast = pd.notna(row.get('mimecast')) and str(row.get('mimecast')).strip() not in ['', '0', 'nan', 'None']
        
        if has_tessian and has_mimecast:
            return "Both"
        elif has_tessian and not has_mimecast:
            return "Missing Mimecast"
        elif not has_tessian and has_mimecast:
            return "Missing Tessian"
        else:
            return "No Coverage"
    
    df['security_coverage'] = df.apply(get_security_coverage, axis=1)

    # Calculate metrics
    total_emails = len(df)
    high_risk = len(df[df['risk_level'] == 'High Risk'])
    medium_risk = len(df[df['risk_level'] == 'Medium Risk'])
    low_risk = len(df[df['risk_level'] == 'Normal'])
    avg_risk = df['risk_score'].mean()

    # KPI Cards - now with 5 equal columns
    col1, col2, col3, col4, col5 = st.columns([1, 1, 1, 1, 1])

    with col1:
        st.markdown(f"""
        <div class="metric-card" style="border-left-color: #3498db;">
            <p class="metric-label">Total Emails</p>
            <p class="metric-value" style="color: #3498db;">{total_emails:,}</p>
            <p class="metric-delta" style="color: #666;">📊 Dataset Overview</p>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        # Calculate critical alerts based on new criteria
        critical_alerts = len(df[
            (df['last_working_day'].notna()) &
            (df['attachments'].notna()) &
            (df['attachments'] != '') &
            (df['attachments'].astype(str) != '0') &
            (df['word_list_match'].notna()) &
            (df['word_list_match'] != '') &
            (df['email_domain'].str.contains('gmail|yahoo|hotmail|outlook|aol|icloud|protonmail|tutanota', case=False, na=False))
        ])
        critical_pct = (critical_alerts/total_emails*100) if total_emails > 0 else 0
        st.markdown(f"""
        <div class="metric-card" style="border-left-color: #dc3545; background-color: #fff5f5;">
            <p class="metric-label">Critical</p>
            <p class="metric-value" style="color: #dc3545;">{critical_alerts}</p>
            <p class="metric-delta" style="color: #dc3545;">🚨 {critical_pct:.1f}% of total</p>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        # Calculate high security alerts based on new criteria
        high_security_alerts = len(df[
            (df['last_working_day'].notna()) &
            (df['attachments'].notna()) &
            (df['attachments'] != '') &
            (df['attachments'].astype(str) != '0')
        ])
        # Exclude critical alerts to avoid double counting
        critical_emails_mask = (
            (df['last_working_day'].notna()) &
            (df['attachments'].notna()) &
            (df['attachments'] != '') &
            (df['attachments'].astype(str) != '0') &
            (df['word_list_match'].notna()) &
            (df['word_list_match'] != '') &
            (df['email_domain'].str.contains('gmail|yahoo|hotmail|outlook|aol|icloud|protonmail|tutanota', case=False, na=False))
        )
        high_security_alerts = high_security_alerts - critical_alerts
        high_security_pct = (high_security_alerts/total_emails*100) if total_emails > 0 else 0
        st.markdown(f"""
        <div class="metric-card" style="border-left-color: #ff8c00; background-color: #fff8f0;">
            <p class="metric-label">High</p>
            <p class="metric-value" style="color: #ff8c00;">{high_security_alerts}</p>
            <p class="metric-delta" style="color: #cc5500;">🟠 {high_security_pct:.1f}% of total</p>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        # Calculate medium risk based on new criteria
        medium_risk_count = len(df[
            (df['has_attachments_bool']) &  # Has attachments
            (df['word_list_match'].notna()) &  # Has word_list_match value
            (df['word_list_match'] != '') &    # word_list_match is not empty
            (~df['has_last_working_day']) &    # No last working day
            (~df['email_domain'].str.contains('gmail|yahoo|hotmail|outlook|aol|icloud|protonmail|tutanota', case=False, na=False))  # Not free email domains
        ])
        medium_risk_pct = (medium_risk_count/total_emails*100) if total_emails > 0 else 0
        st.markdown(f"""
        <div class="metric-card" style="border-left-color: #ffc107; background-color: #fffbf0;">
            <p class="metric-label">Medium</p>
            <p class="metric-value" style="color: #856404;">{medium_risk_count}</p>
            <p class="metric-delta" style="color: #856404;">⚠️ {medium_risk_pct:.1f}% of total</p>
        </div>
        """, unsafe_allow_html=True)

    with col5:
        # Calculate low risk based on new criteria - all emails not in critical, high, or medium
        critical_alerts = len(df[
            (df['last_working_day'].notna()) &
            (df['attachments'].notna()) &
            (df['attachments'] != '') &
            (df['attachments'].astype(str) != '0') &
            (df['word_list_match'].notna()) &
            (df['word_list_match'] != '') &
            (df['email_domain'].str.contains('gmail|yahoo|hotmail|outlook|aol|icloud|protonmail|tutanota', case=False, na=False))
        ])

        high_security_alerts = len(df[
            (df['last_working_day'].notna()) &
            (df['attachments'].notna()) &
            (df['attachments'] != '') &
            (df['attachments'].astype(str) != '0')
        ]) - critical_alerts

        medium_risk_count = len(df[
            (df['has_attachments_bool']) &
            (df['word_list_match'].notna()) &
            (df['word_list_match'] != '') &
            (~df['has_last_working_day']) &
            (~df['email_domain'].str.contains('gmail|yahoo|hotmail|outlook|aol|icloud|protonmail|tutanota', case=False, na=False))
        ])

        low_risk_count = total_emails - critical_alerts - high_security_alerts - medium_risk_count
        low_risk_pct = (low_risk_count/total_emails*100) if total_emails > 0 else 0
        st.markdown(f"""
        <div class="metric-card" style="border-left-color: #28a745; background-color: #f0fff4;">
            <p class="metric-label">Low</p>
            <p class="metric-value" style="color: #155724;">{low_risk_count}</p>
            <p class="metric-delta" style="color: #155724;">✅ {low_risk_pct:.1f}% of total</p>
        </div>
        """, unsafe_allow_html=True)

    # Spacing
    st.markdown("<br>", unsafe_allow_html=True)

    

    # Professional section header
    st.markdown("""
    <div style="background: linear-gradient(90deg, #f8f9fa 0%, #e9ecef 100%); padding: 1.5rem; border-radius: 10px; margin: 2rem 0 1rem 0; border-left: 5px solid #495057;">
        <h2 style="margin: 0; color: #495057; font-size: 1.8rem; font-weight: 600;">
            📧 Email Security Analysis Overview
        </h2>
        <p style="margin: 0.5rem 0 0 0; color: #6c757d; font-size: 1rem;">
            Categorized threat intelligence and risk assessment results
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Create word list match scores (simplified scoring based on content)
    def get_word_match_score(word_match):
        if pd.isna(word_match) or word_match == '':
            return 0
        # Simple scoring based on presence of keywords
        word_match_str = str(word_match).lower()
        if any(keyword in word_match_str for keyword in ['confidential', 'sensitive', 'restricted', 'private']):
            return 3  # High score
        elif any(keyword in word_match_str for keyword in ['internal', 'company', 'business']):
            return 2  # Medium score
        elif word_match_str.strip():
            return 1  # Low score
        return 0

    df['word_match_score'] = df['word_list_match'].apply(get_word_match_score)

    # Custom CSS for professional section cards
    st.markdown("""
    <style>
    .analysis-card {
        background: white;
        border-radius: 12px;
        padding: 1.5rem;
        margin: 1rem 0;
        box-shadow: 0 2px 12px rgba(0,0,0,0.08);
        border: 1px solid #e9ecef;
    }
    .analysis-header {
        display: flex;
        align-items: center;
        margin-bottom: 1rem;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid #f8f9fa;
    }
    .analysis-icon {
        font-size: 1.5rem;
        margin-right: 0.75rem;
    }
    .analysis-title {
        font-size: 1.3rem;
        font-weight: 600;
        color: #2c3e50;
        margin: 0;
    }
    .count-badge {
        background: #e9ecef;
        color: #495057;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.9rem;
        margin-left: auto;
    }
    .high-risk .count-badge { background: #fee; color: #dc3545; }
    .medium-risk .count-badge { background: #fff3cd; color: #856404; }
    .low-risk .count-badge { background: #d4edda; color: #155724; }
    .normal .count-badge { background: #d1ecf1; color: #0c5460; }
    </style>
    """, unsafe_allow_html=True)

    # View 1: Critical Security Alerts - Must have all four conditions
    high_risk_emails = df[
        (df['last_working_day'].notna()) &  # Must have last_working_day value
        (df['attachments'].notna()) &       # Must have attachments value
        (df['attachments'] != '') &         # Attachments must not be empty
        (df['attachments'].astype(str) != '0') &  # Attachments must not be '0'
        (df['word_list_match'].notna()) &   # Must have word_list_match value
        (df['word_list_match'] != '') &     # word_list_match must not be empty
        (df['email_domain'].str.contains('gmail|yahoo|hotmail|outlook|aol|icloud|protonmail|tutanota', case=False, na=False))  # Must be free email domain
    ]
    # Sort to show emails with last_working_day values at top
    high_risk_emails = high_risk_emails.copy()
    high_risk_emails['has_last_working_day_sort'] = high_risk_emails['last_working_day'].notna()
    high_risk_emails = high_risk_emails.sort_values(['has_last_working_day_sort', 'risk_score', 'time'], ascending=[False, False, False])

    st.markdown(f"""
    <div class="analysis-card" style="background: #fff5f5; border: 2px solid #dc3545;">
        <div class="analysis-header">
            <span class="analysis-icon">🚨</span>
            <h3 class="analysis-title" style="color: #dc3545;">Critical Risk Indicators</h3>
            <span class="count-badge" style="background: #f8d7da; color: #721c24;">{len(high_risk_emails)} emails</span>
        </div>
        <p style="color: #6c757d; margin-bottom: 1rem;">
            Emails that meet high-risk criteria, including:<br>
            • Messages with file attachments<br>
            • Keywords matches indicating sensitive content<br>
            • Emails sent by departing employees to free/public email domains
        </p>
    </div>
    """, unsafe_allow_html=True)

    if len(high_risk_emails) > 0:
        # Display with highlighting - include email_domain to show free email detection and security coverage
        display_cols = ['time', 'sender', 'recipients', 'email_domain', 'subject', 'risk_score', 'security_coverage', 'last_working_day', 'word_list_match', 'attachments']
        available_cols = [col for col in display_cols if col in high_risk_emails.columns]

        def highlight_high_risk(row):
            styles = [''] * len(row)
            # Highlight last_working_day (critical indicator)
            if 'last_working_day' in row.index and pd.notna(row['last_working_day']):
                last_working_idx = row.index.get_loc('last_working_day')
                styles[last_working_idx] = 'background-color: #ffcccc; color: #000000; font-weight: bold'
            # Highlight word_list_match (sensitive content indicator)
            if 'word_list_match' in row.index and pd.notna(row['word_list_match']) and str(row['word_list_match']).strip():
                word_match_idx = row.index.get_loc('word_list_match')
                styles[word_match_idx] = 'background-color: #ffcccc; color: #000000; font-weight: bold'
            # Highlight email_domain (free email indicator)
            if 'email_domain' in row.index:
                domain_idx = row.index.get_loc('email_domain')
                styles[domain_idx] = 'background-color: #fff3cd; color: #856404; font-weight: bold'
            # Highlight attachments (data exfiltration vector)
            if 'attachments' in row.index and pd.notna(row['attachments']) and str(row['attachments']).strip():
                attachments_idx = row.index.get_loc('attachments')
                styles[attachments_idx] = 'background-color: #f8d7da; color: #721c24; font-weight: bold'
            # Highlight security coverage based on status
            if 'security_coverage' in row.index:
                coverage_idx = row.index.get_loc('security_coverage')
                coverage_value = str(row['security_coverage'])
                if coverage_value == 'Both':
                    styles[coverage_idx] = 'background-color: #d4edda; color: #155724; font-weight: bold'  # Green for full coverage
                elif coverage_value == 'No Coverage':
                    styles[coverage_idx] = 'background-color: #f8d7da; color: #721c24; font-weight: bold'  # Red for no coverage
                else:  # Missing Tessian or Missing Mimecast
                    styles[coverage_idx] = 'background-color: #fff3cd; color: #856404; font-weight: bold'  # Yellow for partial coverage
            return styles

        styled_high_risk = high_risk_emails[available_cols].style.apply(highlight_high_risk, axis=1)
        st.dataframe(styled_high_risk, use_container_width=True, height=400)
    else:
        st.success("✅ No critical security threats detected.")

    # View 2: High Security Alerts - Require both last_working_day and attachments
    high_security_emails = df[
        (df['last_working_day'].notna()) &  # Must have last_working_day value
        (df['attachments'].notna()) &       # Must have attachments value
        (df['attachments'] != '') &         # Attachments must not be empty
        (df['attachments'].astype(str) != '0') &  # Attachments must not be '0'
        (~df.index.isin(high_risk_emails.index))  # Exclude already classified as critical
    ]
    # Sort to show emails with last_working_day values at top
    high_security_emails = high_security_emails.copy()
    high_security_emails['has_last_working_day_sort'] = high_security_emails['last_working_day'].notna()
    high_security_emails = high_security_emails.sort_values(['has_last_working_day_sort', 'risk_score', 'time'], ascending=[False, False, False])

    st.markdown(f"""
    <div class="analysis-card" style="background: #fff8f0; border: 2px solid #ff8c00;">
        <div class="analysis-header">
            <span class="analysis-icon">🟠</span>
            <h3 class="analysis-title" style="color: #cc5500;">High Risk Indicators</h3>
            <span class="count-badge" style="background: #ffe4cc; color: #cc5500;">{len(high_security_emails)} emails</span>
        </div>
        <p style="color: #6c757d; margin-bottom: 1rem;">
            High-Risk Indicators:<br>
            • Messages with file attachments<br>
            • Emails sent by departing employees to free/public email domains
        </p>
    </div>
    """, unsafe_allow_html=True)

    if len(high_security_emails) > 0:
        # Display with highlighting
        display_cols = ['time', 'sender', 'recipients', 'email_domain', 'subject', 'risk_score', 'security_coverage', 'last_working_day', 'word_list_match', 'attachments']
        available_cols = [col for col in display_cols if col in high_security_emails.columns]

        def highlight_high_security(row):
            styles = [''] * len(row)
            # Highlight last_working_day (key indicator)
            if 'last_working_day' in row.index and pd.notna(row['last_working_day']):
                last_working_idx = row.index.get_loc('last_working_day')
                styles[last_working_idx] = 'background-color: #fed7d7; color: #c53030; font-weight: bold'
            # Highlight attachments (data exfiltration vector)
            if 'attachments' in row.index and pd.notna(row['attachments']) and str(row['attachments']).strip():
                attachments_idx = row.index.get_loc('attachments')
                styles[attachments_idx] = 'background-color: #fed7d7; color: #c53030; font-weight: bold'
            # Highlight security coverage based on status
            if 'security_coverage' in row.index:
                coverage_idx = row.index.get_loc('security_coverage')
                coverage_value = str(row['security_coverage'])
                if coverage_value == 'Both':
                    styles[coverage_idx] = 'background-color: #d4edda; color: #155724; font-weight: bold'  # Green for full coverage
                elif coverage_value == 'No Coverage':
                    styles[coverage_idx] = 'background-color: #f8d7da; color: #721c24; font-weight: bold'  # Red for no coverage
                else:  # Missing Tessian or Missing Mimecast
                    styles[coverage_idx] = 'background-color: #fff3cd; color: #856404; font-weight: bold'  # Yellow for partial coverage
            return styles

        styled_high_security = high_security_emails[available_cols].style.apply(highlight_high_security, axis=1)
        st.dataframe(styled_high_security, use_container_width=True, height=400)
    else:
        st.success("✅ No high security alerts detected.")

    # View 3: Medium-Risk Emails
    medium_risk_emails = df[
        (df['has_attachments_bool']) &  # Has attachments
        (df['word_list_match'].notna()) &  # Has word_list_match value
        (df['word_list_match'] != '') &    # word_list_match is not empty
        (~df['has_last_working_day']) &    # No last working day
        (~df['email_domain'].str.contains('gmail|yahoo|hotmail|outlook|aol|icloud|protonmail|tutanota', case=False, na=False)) &  # Not free email domains
        (~df.index.isin(high_risk_emails.index)) &  # Exclude critical alerts
        (~df.index.isin(high_security_emails.index))  # Exclude high security alerts
    ]
    # Sort to show emails with last_working_day values at top
    medium_risk_emails = medium_risk_emails.copy()
    medium_risk_emails['has_last_working_day_sort'] = medium_risk_emails['last_working_day'].notna()
    medium_risk_emails = medium_risk_emails.sort_values(['has_last_working_day_sort', 'risk_score', 'time'], ascending=[False, False, False])

    st.markdown(f"""
    <div class="analysis-card" style="background: #fffbf0; border: 2px solid #ffc107;">
        <div class="analysis-header">
            <span class="analysis-icon">⚠️</span>
            <h3 class="analysis-title" style="color: #856404;">Medium Risk Indicators</h3>
            <span class="count-badge" style="background: #fff3cd; color: #856404;">{len(medium_risk_emails)} emails</span>
        </div>
        <p style="color: #6c757d; margin-bottom: 1rem;">
            Medium Alerts: Emails containing attachments and sensitive keywords<br>
            • Sent to external domains<br>
            • Sender is not marked as a leaver
        </p>
    </div>
    """, unsafe_allow_html=True)

    if len(medium_risk_emails) > 0:
        # Display with highlighting
        display_cols = ['time', 'sender', 'recipients', 'subject', 'risk_score', 'security_coverage', 'last_working_day', 'word_list_match', 'attachments']
        available_cols = [col for col in display_cols if col in medium_risk_emails.columns]

        def highlight_medium_risk(row):
            styles = [''] * len(row)
            # Highlight last_working_day if present (red)
            if 'last_working_day' in row.index and pd.notna(row['last_working_day']):
                last_working_idx = row.index.get_loc('last_working_day')
                styles[last_working_idx] = 'background-color: #ffcccc; color: #000000; font-weight: bold'
            # Highlight word_list_match if medium score (yellow)
            if 'word_list_match' in row.index:
                word_match_idx = row.index.get_loc('word_list_match')
                if pd.notna(row['word_list_match']) and str(row['word_list_match']).strip():
                    original_idx = row.name
                    if original_idx in df.index:
                        score = df.loc[original_idx, 'word_match_score']
                        if score == 2:
                            styles[word_match_idx] = 'background-color: #ffff99; color: #000000; font-weight: bold'
            # Highlight security coverage based on status
            if 'security_coverage' in row.index:
                coverage_idx = row.index.get_loc('security_coverage')
                coverage_value = str(row['security_coverage'])
                if coverage_value == 'Both':
                    styles[coverage_idx] = 'background-color: #d4edda; color: #155724; font-weight: bold'  # Green for full coverage
                elif coverage_value == 'No Coverage':
                    styles[coverage_idx] = 'background-color: #f8d7da; color: #721c24; font-weight: bold'  # Red for no coverage
                else:  # Missing Tessian or Missing Mimecast
                    styles[coverage_idx] = 'background-color: #fff3cd; color: #856404; font-weight: bold'  # Yellow for partial coverage
            return styles

        styled_medium_risk = medium_risk_emails[available_cols].style.apply(highlight_medium_risk, axis=1)
        st.dataframe(styled_medium_risk, use_container_width=True, height=400)
    else:
        st.success("✅ No moderate risk indicators found.")

    # View 4: Low-Risk Emails - All emails not classified as critical, high, or medium risk
    low_risk_emails = df[
        (~df.index.isin(high_risk_emails.index)) &  # Exclude critical alerts
        (~df.index.isin(high_security_emails.index)) &  # Exclude high security alerts
        (~df.index.isin(medium_risk_emails.index))  # Exclude medium risk
    ]
    # Sort to show emails with last_working_day values at top
    low_risk_emails = low_risk_emails.copy()
    low_risk_emails['has_last_working_day_sort'] = low_risk_emails['last_working_day'].notna()
    low_risk_emails = low_risk_emails.sort_values(['has_last_working_day_sort', 'risk_score', 'time'], ascending=[False, True, False])

    st.markdown(f"""
    <div class="analysis-card" style="background: #f0fff4; border: 2px solid #28a745;">
        <div class="analysis-header">
            <span class="analysis-icon">✅</span>
            <h3 class="analysis-title" style="color: #155724;">Low Risk Indicators</h3>
            <span class="count-badge" style="background: #d4edda; color: #155724;">{len(low_risk_emails)} emails</span>
        </div>
        <p style="color: #6c757d; margin-bottom: 1rem;">
            All other email communications that do not meet critical, high, or medium risk criteria
        </p>
    </div>
    """, unsafe_allow_html=True)

    if len(low_risk_emails) > 0:
        # Display with minimal highlighting
        display_cols = ['time', 'sender', 'recipients', 'subject', 'risk_score', 'security_coverage', 'attachments', 'last_working_day', 'word_list_match']
        available_cols = [col for col in display_cols if col in low_risk_emails.columns]

        def highlight_low_risk(row):
            styles = [''] * len(row)
            # Light green highlighting for low risk scores
            if 'risk_score' in row.index:
                risk_score_idx = row.index.get_loc('risk_score')
                styles[risk_score_idx] = 'background-color: #e8f5e8; color: #2e7d32; font-weight: bold'
            # Highlight last_working_day in red if present
            if 'last_working_day' in row.index and pd.notna(row['last_working_day']):
                last_working_idx = row.index.get_loc('last_working_day')
                styles[last_working_idx] = 'background-color: #ffcccc; color: #000000; font-weight: bold'
            # Highlight security coverage based on status
            if 'security_coverage' in row.index:
                coverage_idx = row.index.get_loc('security_coverage')
                coverage_value = str(row['security_coverage'])
                if coverage_value == 'Both':
                    styles[coverage_idx] = 'background-color: #d4edda; color: #155724; font-weight: bold'  # Green for full coverage
                elif coverage_value == 'No Coverage':
                    styles[coverage_idx] = 'background-color: #f8d7da; color: #721c24; font-weight: bold'  # Red for no coverage
                else:  # Missing Tessian or Missing Mimecast
                    styles[coverage_idx] = 'background-color: #fff3cd; color: #856404; font-weight: bold'  # Yellow for partial coverage
            return styles

        styled_low_risk = low_risk_emails[available_cols].style.apply(highlight_low_risk, axis=1)
        st.dataframe(styled_low_risk, use_container_width=True, height=400)
    else:
        st.info("No low-risk emails found.")



def analytics_page(visualizer, anomaly_detector):
    st.header("📈 Advanced Analytics")

    if st.session_state.processed_data is None:
        st.warning("Please upload email data first in the Data Upload page.")
        return

    df = st.session_state.processed_data.copy()

    if st.session_state.risk_scores is not None:
        df['risk_score'] = st.session_state.risk_scores
        df['risk_level'] = df['risk_score'].apply(lambda x: 
            'High' if x >= 61 else 'Medium' if x >= 31 else 'Low'
        )

    # Analytics options
    analysis_type = st.selectbox(
        "Select Analysis Type",
        ["Overview", "Anomaly Detection", "Risk Analysis", "Advanced Analytics - Low Risk BAU"]
    )

    if analysis_type == "Overview":
        # Anomaly detection
        st.subheader("🔍 Anomaly Detection")

        with st.spinner("Running anomaly detection..."):
            anomalies = anomaly_detector.detect_anomalies(df)

        col1, col2 = st.columns(2)

        with col1:
            anomaly_fig = visualizer.create_anomaly_chart(df, anomalies)
            st.plotly_chart(anomaly_fig, use_container_width=True)

        with col2:
            behavior_fig = visualizer.create_behavior_analysis_chart(df)
            st.plotly_chart(behavior_fig, use_container_width=True)

        # Trend analysis
        st.subheader("📊 Trend Analysis")

        volume_fig = visualizer.create_volume_trend_chart(df)
        st.plotly_chart(volume_fig, use_container_width=True)

        # Top risk factors
        st.subheader("⚠️ Top Risk Factors")

        if 'risk_score' in df.columns:
            risk_factors_fig = visualizer.create_risk_factors_chart(df)
            st.plotly_chart(risk_factors_fig, use_container_width=True)

    elif analysis_type == "Anomaly Detection":
        st.subheader("Anomaly Detection Results")

        # Detect anomalies
        anomalies = anomaly_detector.detect_anomalies(df)

        if anomalies is not None and len(anomalies) > 0:
            st.write(f"**Found {len(anomalies)} anomalous emails**")

            # Anomaly chart
            anomaly_chart = visualizer.create_anomaly_chart(df, anomalies)
            st.plotly_chart(anomaly_chart, use_container_width=True)

            # Anomaly details
            st.subheader("Anomaly Details")
            
            # Get anomaly explanations from the detector
            if hasattr(anomaly_detector, 'last_analyzed_df'):
                anomaly_df_with_reasons = anomaly_detector.last_analyzed_df[anomaly_detector.last_analyzed_df['is_anomaly']].copy()
                
                if not anomaly_df_with_reasons.empty:
                    # Sort by anomaly score (most anomalous first)
                    if 'anomaly_score' in anomaly_df_with_reasons.columns:
                        anomaly_df_with_reasons = anomaly_df_with_reasons.sort_values('anomaly_score', ascending=True)
                    
                    st.write(f"**{len(anomaly_df_with_reasons)} Anomalous Emails Found**")
                    
                    # Create a clean table for display
                    display_data = []
                    for idx, (_, row) in enumerate(anomaly_df_with_reasons.head(20).iterrows()):
                        # Format time
                        time_str = str(row.get('time', 'N/A'))
                        if 'T' in time_str:
                            time_str = time_str.split('T')[0] + ' ' + time_str.split('T')[1][:8]
                        
                        # Get anomaly reasons
                        reasons = "Statistical outlier"
                        if 'anomaly_reasons' in row and row['anomaly_reasons']:
                            reasons = str(row['anomaly_reasons']).replace(' | ', ' • ')
                        
                        # Format risk score
                        risk_score = row.get('risk_score', 0)
                        risk_display = f"{risk_score:.1f}/100" if risk_score else "N/A"
                        
                        # Format anomaly score
                        anomaly_score = row.get('anomaly_score', 0)
                        anomaly_display = f"{anomaly_score:.3f}" if anomaly_score else "N/A"
                        
                        display_data.append({
                            'Priority': f"#{idx+1}",
                            'Date/Time': time_str,
                            'Sender': str(row.get('sender', 'Unknown'))[:30] + ('...' if len(str(row.get('sender', ''))) > 30 else ''),
                            'Subject': str(row.get('subject', 'No Subject'))[:40] + ('...' if len(str(row.get('subject', ''))) > 40 else ''),
                            'Recipients': str(row.get('recipient_count', 'N/A')),
                            'Risk Score': risk_display,
                            'Anomaly Score': anomaly_display,
                            'Anomaly Reasons': reasons[:80] + ('...' if len(reasons) > 80 else '')
                        })
                    
                    # Display as dataframe with better formatting
                    anomaly_display_df = pd.DataFrame(display_data)
                    
                    # Color code based on risk score
                    def highlight_anomalies(val):
                        if 'Risk Score' in str(val) and val != 'N/A':
                            try:
                                score = float(str(val).split('/')[0])
                                if score >= 80:
                                    return 'background-color: #ffebee; color: #c62828'
                                elif score >= 60:
                                    return 'background-color: #fff3e0; color: #ef6c00'
                                elif score >= 40:
                                    return 'background-color: #fffde7; color: #f57f17'
                            except:
                                pass
                        return ''
                    
                    # Apply styling and display
                    styled_df = anomaly_display_df.style.map(highlight_anomalies)
                    st.dataframe(styled_df, use_container_width=True, height=400)
                    
                    # Add summary statistics
                    st.subheader("Anomaly Summary")
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        high_risk_anomalies = len([d for d in display_data if 'Risk Score' in d and d['Risk Score'] != 'N/A' and float(d['Risk Score'].split('/')[0]) >= 70])
                        st.metric("High Risk Anomalies", high_risk_anomalies)
                    
                    with col2:
                        risk_scores = [float(d['Risk Score'].split('/')[0]) for d in display_data if d['Risk Score'] != 'N/A']
                        avg_risk = sum(risk_scores) / len(risk_scores) if len(risk_scores) > 0 else 0
                        st.metric("Avg Risk Score", f"{avg_risk:.1f}/100")
                    
                    with col3:
                        unique_senders = len(set([d['Sender'] for d in display_data]))
                        st.metric("Unique Senders", unique_senders)
                    
                    with col4:
                        total_recipients = sum([int(d['Recipients']) for d in display_data if d['Recipients'].isdigit()])
                        st.metric("Total Recipients", total_recipients)
                    
                    # Detailed view option
                    st.subheader("Detailed View")
                    selected_anomaly = st.selectbox(
                        "Select an anomaly for detailed analysis:",
                        options=range(len(display_data)),
                        format_func=lambda x: f"#{x+1}: {display_data[x]['Sender']} - {display_data[x]['Subject']}"
                    )
                    
                    if selected_anomaly is not None:
                        selected_row = anomaly_df_with_reasons.iloc[selected_anomaly]
                        
                        col1, col2 = st.columns([1, 1])
                        
                        with col1:
                            st.write("**Complete Email Details:**")
                            st.write(f"**Time:** {selected_row.get('time', 'N/A')}")
                            st.write(f"**Sender:** {selected_row.get('sender', 'N/A')}")
                            st.write(f"**Subject:** {selected_row.get('subject', 'N/A')}")
                            st.write(f"**Recipients:** {selected_row.get('recipient_count', 'N/A')}")
                            st.write(f"**Attachments:** {selected_row.get('attachments', 'None')}")
                            st.write(f"**File Types:** {selected_row.get('file_types', 'None')}")
                            st.write(f"**Email Domain:** {selected_row.get('email_domain', 'N/A')}")
                            
                        with col2:
                            st.write("**Risk Assessment:**")
                            risk_score = selected_row.get('risk_score', 'N/A')
                            if isinstance(risk_score, (int, float)):
                                st.write(f"**Risk Score:** {risk_score:.1f}/100")
                            else:
                                st.write(f"**Risk Score:** {risk_score}")
                            st.write(f"**Risk Level:** {selected_row.get('risk_level', 'N/A')}")
                            if 'anomaly_score' in selected_row:
                                st.write(f"**Anomaly Score:** {selected_row['anomaly_score']:.3f}")
                            st.write(f"**Keywords Found:** {selected_row.get('word_list_match', 'None')}")
                            
                            st.write("**Complete Anomaly Analysis:**")
                            if 'anomaly_reasons' in selected_row and selected_row['anomaly_reasons']:
                                reasons = str(selected_row['anomaly_reasons']).split(' | ')
                                for reason in reasons:
                                    st.write(f"• {reason}")
                            else:
                                st.write("• Detected as statistical outlier based on behavioral patterns")
                
                else:
                    st.info("No anomaly details available.")
            else:
                st.info("Anomaly detection analysis not available.")
        else:
            st.info("No significant anomalies detected in the data.")

    elif analysis_type == "Risk Analysis":
        st.subheader("Risk Factor Analysis")

        if 'risk_score' in df.columns:
            # Risk factors chart
            risk_factors_chart = visualizer.create_risk_factors_chart(df)
            st.plotly_chart(risk_factors_chart, use_container_width=True)

            # High risk emails
            st.subheader("High Risk Emails")
            high_risk = df[df['risk_level'] == 'High'] if 'risk_level' in df.columns else pd.DataFrame()
            
            if not high_risk.empty:
                st.write(f"**{len(high_risk)} High-Risk Emails Detected**")
                st.write("These emails have been flagged as high-risk based on multiple security indicators including:")
                st.write("• IP-sensitive keywords in content • Free email domains • Large attachments • Unusual timing • Volume spikes")
                
                # Create enhanced display for high-risk emails
                high_risk_display = []
                for idx, (_, row) in enumerate(high_risk.iterrows()):
                    # Format time
                    time_str = str(row.get('time', 'N/A'))
                    if 'T' in time_str:
                        time_str = time_str.split('T')[0] + ' ' + time_str.split('T')[1][:8]
                    
                    # Get risk factors
                    risk_factors = []
                    if row.get('word_list_match') and str(row.get('word_list_match')) not in ['0', 'nan', '']:
                        risk_factors.append("IP Keywords")
                    if row.get('email_domain') and any(domain in str(row.get('email_domain')).lower() for domain in ['gmail', 'yahoo', 'hotmail']):
                        risk_factors.append("Free Email Domain")
                    if row.get('attachments') and str(row.get('attachments')) not in ['0', '']:
                        risk_factors.append("Has Attachments")
                    recipient_count = row.get('recipient_count', 0)
                    if recipient_count and recipient_count > 5:
                        risk_factors.append("Multiple Recipients")
                    
                    high_risk_display.append({
                        'Priority': f"#{idx+1}",
                        'Date/Time': time_str,
                        'Sender': str(row.get('sender', 'Unknown'))[:35] + ('...' if len(str(row.get('sender', ''))) > 35 else ''),
                        'Subject': str(row.get('subject', 'No Subject'))[:45] + ('...' if len(str(row.get('subject', ''))) > 45 else ''),
                        'Risk Score': f"{row.get('risk_score', 0):.1f}/100",
                        'Recipients': str(row.get('recipient_count', 'N/A')),
                        'Risk Factors': ' • '.join(risk_factors) if risk_factors else 'General Risk Indicators',
                        'Keywords Found': str(row.get('word_list_match', 'None'))[:30] + ('...' if len(str(row.get('word_list_match', ''))) > 30 else '')
                    })
                
                # Display enhanced high-risk table
                high_risk_df = pd.DataFrame(high_risk_display)
                
                # Color coding for high-risk emails
                def highlight_high_risk(val):
                    if 'Risk Score' in str(val):
                        try:
                            score = float(str(val).split('/')[0])
                            if score >= 90:
                                return 'background-color: #ffcdd2; color: #b71c1c; font-weight: bold'
                            elif score >= 80:
                                return 'background-color: #ffebee; color: #c62828'
                        except:
                            pass
                    return ''
                
                styled_high_risk = high_risk_df.style.map(highlight_high_risk)
                st.dataframe(styled_high_risk, use_container_width=True, height=400)
                
                # High-risk summary statistics
                st.subheader("High-Risk Email Summary")
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    critical_risk = len([d for d in high_risk_display if float(d['Risk Score'].split('/')[0]) >= 90])
                    st.metric("Critical Risk (90+)", critical_risk)
                
                with col2:
                    ip_keywords = len([d for d in high_risk_display if 'IP Keywords' in d['Risk Factors']])
                    st.metric("With IP Keywords", ip_keywords)
                
                with col3:
                    free_domains = len([d for d in high_risk_display if 'Free Email Domain' in d['Risk Factors']])
                    st.metric("Free Email Domains", free_domains)
                
                with col4:
                    with_attachments = len([d for d in high_risk_display if 'Has Attachments' in d['Risk Factors']])
                    st.metric("With Attachments", with_attachments)
                
                # Detailed view for high-risk emails
                st.subheader("Detailed Risk Analysis")
                selected_high_risk = st.selectbox(
                    "Select a high-risk email for detailed analysis:",
                    options=range(len(high_risk_display)),
                    format_func=lambda x: f"#{x+1}: {high_risk_display[x]['Sender']} - Score: {high_risk_display[x]['Risk Score']}"
                )
                
                if selected_high_risk is not None:
                    selected_row = high_risk.iloc[selected_high_risk]
                    
                    col1, col2 = st.columns([1, 1])
                    
                    with col1:
                        st.write("**Email Information:**")
                        st.write(f"**Sender:** {selected_row.get('sender', 'N/A')}")
                        st.write(f"**Subject:** {selected_row.get('subject', 'N/A')}")
                        st.write(f"**Time:** {selected_row.get('time', 'N/A')}")
                        st.write(f"**Recipients:** {selected_row.get('recipient_count', 'N/A')}")
                        st.write(f"**Email Domain:** {selected_row.get('email_domain', 'N/A')}")
                        st.write(f"**External Domains:** {selected_row.get('external_domains', 'None')}")
                        
                    with col2:
                        st.write("**Risk Assessment:**")
                        st.write(f"**Risk Score:** {selected_row.get('risk_score', 0):.1f}/100")
                        st.write(f"**Risk Level:** {selected_row.get('risk_level', 'N/A')}")
                        st.write(f"**IP Keywords:** {selected_row.get('word_list_match', 'None')}")
                        st.write(f"**Attachments:** {selected_row.get('attachments', 'None')}")
                        st.write(f"**File Types:** {selected_row.get('file_types', 'None')}")
                        
                        st.write("**Security Recommendations:**")
                        if selected_row.get('word_list_match') and str(selected_row.get('word_list_match')) not in ['0', 'nan', '']:
                            st.write("⚠️ Review content for IP data leakage")
                        if selected_row.get('email_domain') and any(domain in str(selected_row.get('email_domain')).lower() for domain in ['gmail', 'yahoo', 'hotmail']):
                            st.write("⚠️ Verify sender identity - using free email")
                        if selected_row.get('attachments'):
                            st.write("⚠️ Scan attachments before opening")
                        st.write("⚠️ Consider blocking or monitoring this sender")
                
            else:
                st.info("No high-risk emails found in the current dataset.")
        else:
            st.warning("Risk analysis not available. Please ensure risk scores are calculated.")

    elif analysis_type == "Advanced Analytics - Low Risk BAU":
        from utils.bau_analyzer import BAUAnalyzer

        st.subheader("🔍 Advanced Analytics Dashboard")
        st.info("Comprehensive email analysis with threat detection and pattern recognition across ALL email events")

        # Use complete dataset for analysis (no filtering)
        filtered_df = df.copy()
        filter_label = "all email events"

        # Initialize BAU analyzer
        bau_analyzer = BAUAnalyzer()

        # Perform analysis on complete dataset
        with st.spinner(f"Analyzing complete dataset patterns..."):
            analysis_results = bau_analyzer.analyze_low_risk_patterns(filtered_df)

        # Display results in tabs
        tab1, tab2, tab3, tab4 = st.tabs([
            "Pattern Overview", 
            "Word Frequencies Analysis", 
            "Anomalies", 
            "Business Unit Analytics"
        ])

        with tab1:
            st.subheader("Communication Patterns - Complete Dataset")

            bau_patterns = analysis_results.get('bau_patterns', {})

            # Complete dataset metrics
            alert_count = len(filtered_df)
            total_count = len(df)

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Complete Dataset Count", alert_count)
            with col2:
                st.metric("Coverage", "100%" if alert_count == total_count else f"{(alert_count/total_count)*100:.1f}%")
            with col3:
                if bau_patterns.get('temporal', {}).get('business_hours_percentage'):
                    st.metric("Business Hours %", f"{bau_patterns['temporal']['business_hours_percentage']:.1f}%")

            # Temporal patterns
            if bau_patterns.get('temporal'):
                temporal = bau_patterns['temporal']
                st.subheader("Temporal Patterns")

                col1, col2 = st.columns(2)
                with col1:
                    if 'peak_hours' in temporal and temporal['peak_hours'] is not None:
                        st.write(f"**Peak Activity Hour:** {temporal['peak_hours']}:00")
                    if 'daily_volume' in temporal:
                        st.write(f"**Daily Volume Stats:**")
                        st.write(f"- Average: {temporal['daily_volume'].get('mean', 0):.1f} emails/day")
                        st.write(f"- Max: {temporal['daily_volume'].get('max', 0):.0f} emails/day")

                with col2:
                    if 'weekly_pattern' in temporal:
                        st.write("**Weekly Distribution:**")
                        days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
                        for i, day in enumerate(days):
                            count = temporal['weekly_pattern'].get(i, 0)
                            st.write(f"- {day}: {count} emails")

            # Communication patterns
            if bau_patterns.get('communication'):
                comm = bau_patterns['communication']
                st.subheader("Communication Patterns")

                col1, col2 = st.columns(2)
                with col1:
                    st.write("**Top Regular Senders:**")
                    for sender, count in list(comm.get('regular_senders', {}).items())[:5]:
                        st.write(f"- {sender}: {count} emails")

                with col2:
                    dist = comm.get('sender_distribution', {})
                    st.write("**Sender Statistics:**")
                    st.write(f"- Unique Senders: {dist.get('total_unique_senders', 0)}")
                    st.write(f"- Avg Emails/Sender: {dist.get('avg_emails_per_sender', 0):.1f}")
                    st.write(f"- Top Sender Dominance: {dist.get('top_sender_dominance', 0):.1f}%")

        with tab2:
            st.subheader("📊 Word Frequencies Analysis")
            st.info("Analysis of all words/phrases found in the word_list_match field across the complete dataset")

            # Extract and analyze word_list_match content
            word_list_data = []
            total_matches = 0
            
            for idx, row in filtered_df.iterrows():
                word_match = row.get('word_list_match', '')
                if pd.notna(word_match) and str(word_match).strip() and str(word_match) != '0':
                    # Split by common delimiters and clean
                    words = str(word_match).replace(',', ' ').replace(';', ' ').replace('|', ' ').split()
                    for word in words:
                        clean_word = word.strip().lower()
                        if clean_word and len(clean_word) > 2:  # Filter out very short words
                            word_list_data.append({
                                'word': clean_word,
                                'sender': row.get('sender', 'Unknown'),
                                'time': row.get('time', ''),
                                'bunit': row.get('bunit', 'Unknown'),
                                'department': row.get('department', 'Unknown')
                            })
                            total_matches += 1

            if word_list_data:
                word_df = pd.DataFrame(word_list_data)
                
                # Calculate word frequencies
                word_frequencies = word_df['word'].value_counts()
                
                # Display overview metrics
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total Word Matches", total_matches)
                with col2:
                    st.metric("Unique Words", len(word_frequencies))
                with col3:
                    emails_with_matches = len(filtered_df[
                        (filtered_df['word_list_match'].notna()) & 
                        (filtered_df['word_list_match'] != '') & 
                        (filtered_df['word_list_match'].astype(str) != '0')
                    ])
                    st.metric("Emails with Matches", emails_with_matches)
                with col4:
                    unique_senders_with_matches = word_df['sender'].nunique()
                    st.metric("Unique Senders", unique_senders_with_matches)

                # Top 20 Word Frequencies Table
                st.subheader("🔍 Top 20 Word Frequencies")
                
                top_words = word_frequencies.head(20)
                word_freq_display = []
                
                for rank, (word, count) in enumerate(top_words.items(), 1):
                    # Calculate percentage
                    percentage = (count / total_matches * 100) if total_matches > 0 else 0
                    
                    # Get unique senders for this word
                    word_senders = word_df[word_df['word'] == word]['sender'].nunique()
                    
                    # Get business units for this word
                    word_bunits = word_df[word_df['word'] == word]['bunit'].nunique()
                    
                    word_freq_display.append({
                        'Rank': f"#{rank}",
                        'Word/Phrase': word.title(),
                        'Frequency': f"{count:,}",
                        'Percentage': f"{percentage:.1f}%",
                        'Unique Senders': word_senders,
                        'Business Units': word_bunits
                    })
                
                # Create styled dataframe
                freq_df = pd.DataFrame(word_freq_display)
                
                # Style the dataframe with color coding
                def highlight_frequency(row):
                    styles = [''] * len(row)
                    try:
                        freq = int(str(row['Frequency']).replace(',', ''))
                        if freq >= 100:
                            styles[2] = 'background-color: #ffebee; color: #c62828; font-weight: bold'  # High frequency - red
                        elif freq >= 50:
                            styles[2] = 'background-color: #fff3e0; color: #ef6c00; font-weight: bold'  # Medium frequency - orange
                        elif freq >= 20:
                            styles[2] = 'background-color: #fffde7; color: #f57f17; font-weight: bold'  # Low-medium frequency - yellow
                    except:
                        pass
                    return styles
                
                styled_freq_df = freq_df.style.apply(highlight_frequency, axis=1)
                st.dataframe(styled_freq_df, use_container_width=True, height=600)
                
                # Word Distribution Analysis
                st.subheader("📈 Word Distribution Insights")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**Frequency Distribution:**")
                    high_freq_words = len(word_frequencies[word_frequencies >= 50])
                    medium_freq_words = len(word_frequencies[(word_frequencies >= 20) & (word_frequencies < 50)])
                    low_freq_words = len(word_frequencies[word_frequencies < 20])
                    
                    st.write(f"• High Frequency (50+): **{high_freq_words}** words")
                    st.write(f"• Medium Frequency (20-49): **{medium_freq_words}** words")
                    st.write(f"• Low Frequency (<20): **{low_freq_words}** words")
                
                with col2:
                    st.write("**Top Word Categories:**")
                    # Categorize words (simple keyword matching)
                    categories = {
                        'Financial': ['financial', 'bank', 'money', 'payment', 'account', 'transaction'],
                        'Legal': ['legal', 'contract', 'agreement', 'compliance', 'audit'],
                        'Technical': ['system', 'data', 'network', 'security', 'access'],
                        'Business': ['business', 'client', 'customer', 'project', 'meeting']
                    }
                    
                    category_counts = {}
                    for category, keywords in categories.items():
                        count = 0
                        for word in word_frequencies.index:
                            if any(keyword in word.lower() for keyword in keywords):
                                count += word_frequencies[word]
                        if count > 0:
                            category_counts[category] = count
                    
                    for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
                        st.write(f"• {category}: **{count}** occurrences")

                # Detailed word analysis option
                st.subheader("🔎 Detailed Word Analysis")
                selected_word = st.selectbox(
                    "Select a word for detailed analysis:",
                    options=word_frequencies.head(10).index.tolist(),
                    help="Choose from the top 10 most frequent words"
                )
                
                if selected_word:
                    word_details = word_df[word_df['word'] == selected_word]
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Total Occurrences", len(word_details))
                    with col2:
                        st.metric("Unique Senders", word_details['sender'].nunique())
                    with col3:
                        st.metric("Business Units", word_details['bunit'].nunique())
                    
                    # Show breakdown by business unit
                    st.write(f"**'{selected_word.title()}' by Business Unit:**")
                    bunit_breakdown = word_details['bunit'].value_counts()
                    for bunit, count in bunit_breakdown.head(5).items():
                        percentage = (count / len(word_details) * 100)
                        st.write(f"• {bunit}: {count} occurrences ({percentage:.1f}%)")
                    
                    # Show breakdown by department
                    st.write(f"**'{selected_word.title()}' by Department:**")
                    dept_breakdown = word_details['department'].value_counts()
                    for dept, count in dept_breakdown.head(5).items():
                        percentage = (count / len(word_details) * 100)
                        st.write(f"• {dept}: {count} occurrences ({percentage:.1f}%)")

            else:
                st.info("No word matches found in the word_list_match field for the current dataset")
                st.write("**Possible reasons:**")
                st.write("• No emails contain matches in the word_list_match field")
                st.write("• The word_list_match field is empty or contains only zeros/null values")
                st.write("• The filtering criteria may have excluded emails with word matches")

        with tab3:
            st.subheader("Anomaly Detection - Complete Dataset")

            anomalies_df = analysis_results.get('anomalies', pd.DataFrame())

            if not anomalies_df.empty:
                st.write(f"**Found {len(anomalies_df)} anomalies in complete dataset**")

                # Group by type
                anomaly_types = anomalies_df['type'].value_counts()

                col1, col2 = st.columns(2)
                with col1:
                    st.write("**Anomaly Types:**")
                    for anom_type, count in anomaly_types.items():
                        st.write(f"• {anom_type}: {count}")

                with col2:
                    severity_counts = anomalies_df['severity'].value_counts()
                    st.write("**Severity Distribution:**")
                    for severity, count in severity_counts.items():
                        st.write(f"• {severity}: {count}")

                # Anomaly Detection Results with Reasoning
                st.subheader("📋 Anomaly Detection Results")
                st.info("Below are the detailed explanations for why each pattern was identified as an anomaly:")

                # Detailed reasoning for each anomaly type
                for idx, anomaly in anomalies_df.iterrows():
                    anomaly_type = anomaly.get('type', 'Unknown')
                    severity = anomaly.get('severity', 'Medium')
                    description = anomaly.get('description', 'No description available')

                    # Color coding based on severity
                    if severity == 'High':
                        severity_color = "🔴"
                        bg_color = "#fff5f5"
                        border_color = "#dc3545"
                    elif severity == 'Medium':
                        severity_color = "🟡"
                        bg_color = "#fffbf0"
                        border_color = "#ffc107"
                    else:
                        severity_color = "🟢"
                        bg_color = "#f0fff4"
                        border_color = "#28a745"

                    # Create reasoning explanation based on anomaly type
                    reasoning = ""
                    if anomaly_type == "Volume Spike":
                        reasoning = """
                        **Why this is an anomaly:**
                        - Unusual spike in email volume compared to normal patterns
                        - Could indicate data exfiltration attempts or compromised accounts
                        - Sudden increases in activity warrant investigation

                        **Risk Indicators:**
                        • Volume significantly exceeds baseline patterns
                        • Pattern deviates from sender's normal behavior
                        • Could suggest automated or bulk data transfer
                        """
                    elif anomaly_type == "Off-Hours Activity":
                        reasoning = """
                        **Why this is an anomaly:**
                        - Email activity occurring outside normal business hours
                        - Unusual timing patterns may indicate unauthorized access
                        - Late-night or weekend activity requires scrutiny

                        **Risk Indicators:**
                        • Communications sent during non-business hours
                        • Deviates from typical organizational patterns
                        • Could indicate compromised accounts or insider threats
                        """
                    elif anomaly_type == "Attachment Pattern":
                        reasoning = """
                        **Why this is an anomaly:**
                        - Unusual attachment behavior detected
                        - Pattern differs significantly from sender's normal habits
                        - Attachments can be vectors for data exfiltration

                        **Risk Indicators:**
                        • Sender rarely sends attachments but suddenly does
                        • Attachment types or sizes are unusual
                        • Could indicate data packaging for exfiltration
                        """
                    elif anomaly_type == "Recipient Pattern":
                        reasoning = """
                        **Why this is an anomaly:**
                        - Unusual recipient communication patterns
                        - Emails sent to new or uncommon domains
                        - Deviates from normal communication networks

                        **Risk Indicators:**
                        • Communications to previously unused domains
                        • Sudden changes in recipient patterns
                        • Could indicate data sharing with unauthorized parties
                        """
                    elif anomaly_type == "Content Anomaly":
                        reasoning = """
                        **Why this is an anomaly:**
                        - Email content differs from normal patterns
                        - Unusual keywords or content structure detected
                        - Content analysis reveals atypical communication

                        **Risk Indicators:**
                        • Content contains sensitive keywords unexpectedly
                        • Communication style deviates from normal patterns
                        • Could indicate sensitive information sharing
                        """
                    elif anomaly_type == "Frequency Anomaly":
                        reasoning = """
                        **Why this is an anomaly:**
                        - Communication frequency significantly changed
                        - Burst patterns or unusual timing intervals
                        - Deviates from established communication rhythms

                        **Risk Indicators:**
                        • Sudden increase or decrease in email frequency
                        • Irregular timing patterns
                        • Could indicate urgent or suspicious activity
                        """
                    else:
                        reasoning = """
                        **Why this is an anomaly:**
                        - Pattern deviates significantly from normal behavior
                        - Statistical analysis identified unusual characteristics
                        - Requires further investigation to determine risk level

                        **Risk Indicators:**
                        • Behavior outside normal parameters
                        • Pattern not typically observed in the dataset
                        • Warrants security team review
                        """

                    # Display anomaly with reasoning in an expandable section
                    with st.expander(f"{severity_color} {anomaly_type} - {severity} Severity", expanded=False):
                        st.markdown(f"""
                        <div style="background: {bg_color}; border-left: 4px solid {border_color}; padding: 1rem; border-radius: 8px; margin: 0.5rem 0;">
                            <h4 style="color: {border_color}; margin-top: 0;">Anomaly Details</h4>
                            <p><strong>Description:</strong> {description}</p>
                            <p><strong>Severity Level:</strong> {severity}</p>
                        </div>
                        """, unsafe_allow_html=True)

                        st.markdown("#### 🔍 Detailed Analysis")
                        st.markdown(reasoning)

                        # Additional context if available
                        if hasattr(anomaly, 'value') and anomaly.get('value') is not None:
                            st.markdown(f"**📊 Metric Value:** {anomaly['value']}")

                        if hasattr(anomaly, 'count') and anomaly.get('count') is not None:
                            st.markdown(f"**📈 Count:** {anomaly['count']}")

                        if hasattr(anomaly, 'percentage') and anomaly.get('percentage') is not None:
                            st.markdown(f"**📋 Percentage:** {anomaly['percentage']:.1f}%")

                        # Recommended actions
                        st.markdown("#### 🎯 Recommended Actions")
                        if severity == 'High':
                            st.markdown("""
                            - **Immediate Investigation Required**
                            - Review the sender's recent activities
                            - Check for signs of account compromise
                            - Verify if emails contain sensitive information
                            - Consider temporary access restrictions if needed
                            """)
                        elif severity == 'Medium':
                            st.markdown("""
                            - **Monitor and Review**
                            - Document the anomaly for trend analysis
                            - Review sender's typical patterns
                            - Consider reaching out to verify legitimate activity
                            - Track for recurring patterns
                            """)
                        else:
                            st.markdown("""
                            - **Log and Monitor**
                            - Record anomaly for baseline adjustment
                            - Continue monitoring for pattern changes
                            - No immediate action required unless part of larger trend
                            """)

                # Summary of anomaly reasoning
                st.subheader("🎯 Anomaly Detection Summary")
                st.markdown("""
                **How anomalies are identified:**

                1. **Statistical Analysis**: Emails are compared against established baseline patterns using machine learning algorithms
                2. **Behavioral Profiling**: Individual sender patterns are analyzed for deviations from their normal behavior
                3. **Temporal Analysis**: Time-based patterns are examined for unusual activity outside normal business hours
                4. **Volume Analysis**: Email volumes are checked for spikes or unusual distribution patterns
                5. **Content Analysis**: Email content and attachments are analyzed for unusual characteristics

                **Risk Assessment Methodology:**
                - **High Severity**: Anomalies that pose immediate security risks or indicate potential data breaches
                - **Medium Severity**: Patterns that deviate significantly but may have legitimate explanations
                - **Low Severity**: Minor deviations that should be monitored but don't require immediate action
                """)

            else:
                st.info("No anomalies detected in complete dataset")
                st.success("✅ All email patterns appear normal based on statistical analysis")

                # Explain what this means
                st.markdown("""
                **What this means:**
                - All emails in the complete dataset follow expected patterns
                - No significant deviations from normal behavior detected
                - Communication volumes and timing are within normal ranges
                - No suspicious content or recipient patterns identified

                **This indicates:**
                - Normal business operations across the organization
                - No immediate security concerns in the complete dataset
                - Established communication patterns are being followed
                """)

        with tab4:
            st.subheader("🏢 Business Unit Analytics")
            st.info("Comprehensive analysis of email activity breakdown by business unit and department")

            # Business Unit Overview
            if 'bunit' in filtered_df.columns:
                bunit_counts = filtered_df['bunit'].value_counts()
                
                st.subheader("📊 Business Unit Email Activity")
                
                # Overall metrics
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total Business Units", len(bunit_counts))
                with col2:
                    st.metric("Most Active Unit", bunit_counts.index[0] if len(bunit_counts) > 0 else "N/A")
                with col3:
                    st.metric("Highest Activity", f"{bunit_counts.iloc[0]:,}" if len(bunit_counts) > 0 else "0")
                with col4:
                    avg_activity = bunit_counts.mean() if len(bunit_counts) > 0 else 0
                    st.metric("Average Activity", f"{avg_activity:.0f}")

                # Top Business Units Table
                st.subheader("🏆 Top 15 Business Units by Email Activity")
                
                bunit_analysis = []
                for rank, (bunit, count) in enumerate(bunit_counts.head(15).items(), 1):
                    # Calculate percentage of total
                    percentage = (count / len(filtered_df) * 100) if len(filtered_df) > 0 else 0
                    
                    # Get unique senders for this bunit
                    bunit_senders = filtered_df[filtered_df['bunit'] == bunit]['sender'].nunique()
                    
                    # Get unique departments for this bunit
                    bunit_depts = filtered_df[filtered_df['bunit'] == bunit]['department'].nunique() if 'department' in filtered_df.columns else 0
                    
                    # Calculate emails with word matches
                    bunit_word_matches = 0
                    if 'word_list_match' in filtered_df.columns:
                        bunit_data = filtered_df[filtered_df['bunit'] == bunit]
                        bunit_word_matches = len(bunit_data[
                            (bunit_data['word_list_match'].notna()) & 
                            (bunit_data['word_list_match'] != '') & 
                            (bunit_data['word_list_match'].astype(str) != '0')
                        ])
                    
                    # Calculate risk score average if available
                    avg_risk = "N/A"
                    if 'risk_score' in filtered_df.columns:
                        bunit_risk = filtered_df[filtered_df['bunit'] == bunit]['risk_score'].mean()
                        avg_risk = f"{bunit_risk:.1f}"
                    
                    bunit_analysis.append({
                        'Rank': f"#{rank}",
                        'Business Unit': str(bunit)[:40] + ('...' if len(str(bunit)) > 40 else ''),
                        'Email Count': f"{count:,}",
                        'Percentage': f"{percentage:.1f}%",
                        'Unique Senders': bunit_senders,
                        'Departments': bunit_depts,
                        'Word Matches': bunit_word_matches,
                        'Avg Risk': avg_risk
                    })
                
                # Create and style the dataframe
                bunit_df = pd.DataFrame(bunit_analysis)
                
                def highlight_activity(row):
                    styles = [''] * len(row)
                    try:
                        count = int(str(row['Email Count']).replace(',', ''))
                        if count >= 1000:
                            styles[2] = 'background-color: #ffebee; color: #c62828; font-weight: bold'  # Very high activity
                        elif count >= 500:
                            styles[2] = 'background-color: #fff3e0; color: #ef6c00; font-weight: bold'  # High activity
                        elif count >= 100:
                            styles[2] = 'background-color: #fffde7; color: #f57f17; font-weight: bold'  # Medium activity
                    except:
                        pass
                    return styles
                
                styled_bunit_df = bunit_df.style.apply(highlight_activity, axis=1)
                st.dataframe(styled_bunit_df, use_container_width=True, height=500)

                # Department Analysis within Business Units
                if 'department' in filtered_df.columns:
                    st.subheader("🏛️ Department Analysis")
                    
                    # Select business unit for detailed department analysis
                    selected_bunit = st.selectbox(
                        "Select Business Unit for Department Breakdown:",
                        options=bunit_counts.head(10).index.tolist(),
                        help="Choose from the top 10 most active business units"
                    )
                    
                    if selected_bunit:
                        bunit_data = filtered_df[filtered_df['bunit'] == selected_bunit]
                        dept_counts = bunit_data['department'].value_counts()
                        
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.write(f"**Top Departments in {selected_bunit}:**")
                            dept_analysis = []
                            
                            for rank, (dept, count) in enumerate(dept_counts.head(10).items(), 1):
                                percentage = (count / len(bunit_data) * 100)
                                dept_senders = bunit_data[bunit_data['department'] == dept]['sender'].nunique()
                                
                                dept_word_matches = 0
                                if 'word_list_match' in bunit_data.columns:
                                    dept_data = bunit_data[bunit_data['department'] == dept]
                                    dept_word_matches = len(dept_data[
                                        (dept_data['word_list_match'].notna()) & 
                                        (dept_data['word_list_match'] != '') & 
                                        (dept_data['word_list_match'].astype(str) != '0')
                                    ])
                                
                                dept_analysis.append({
                                    'Rank': f"#{rank}",
                                    'Department': str(dept)[:30] + ('...' if len(str(dept)) > 30 else ''),
                                    'Emails': f"{count:,}",
                                    'Percentage': f"{percentage:.1f}%",
                                    'Senders': dept_senders,
                                    'Word Matches': dept_word_matches
                                })
                            
                            dept_df = pd.DataFrame(dept_analysis)
                            st.dataframe(dept_df, use_container_width=True, height=400)
                        
                        with col2:
                            st.write(f"**{selected_bunit} Overview:**")
                            st.write(f"• Total Emails: **{len(bunit_data):,}**")
                            st.write(f"• Departments: **{dept_counts.nunique()}**")
                            st.write(f"• Unique Senders: **{bunit_data['sender'].nunique()}**")
                            
                            if 'word_list_match' in bunit_data.columns:
                                word_matches = len(bunit_data[
                                    (bunit_data['word_list_match'].notna()) & 
                                    (bunit_data['word_list_match'] != '') & 
                                    (bunit_data['word_list_match'].astype(str) != '0')
                                ])
                                st.write(f"• Word Matches: **{word_matches:,}**")
                            
                            if 'risk_score' in bunit_data.columns:
                                avg_risk = bunit_data['risk_score'].mean()
                                st.write(f"• Average Risk Score: **{avg_risk:.1f}**")
                            
                            # Time-based analysis
                            if 'time' in bunit_data.columns:
                                bunit_data_time = bunit_data.copy()
                                bunit_data_time['time'] = pd.to_datetime(bunit_data_time['time'], errors='coerce')
                                bunit_data_time['hour'] = bunit_data_time['time'].dt.hour
                                
                                business_hours = len(bunit_data_time[
                                    (bunit_data_time['hour'] >= 9) & (bunit_data_time['hour'] <= 17)
                                ])
                                business_hours_pct = (business_hours / len(bunit_data_time) * 100) if len(bunit_data_time) > 0 else 0
                                st.write(f"• Business Hours: **{business_hours_pct:.1f}%**")

                # Cross-Unit Analysis
                st.subheader("🔄 Cross-Business Unit Analysis")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**Activity Distribution:**")
                    total_emails = len(filtered_df)
                    top_5_bunits = bunit_counts.head(5)
                    top_5_total = top_5_bunits.sum()
                    
                    st.write(f"• Top 5 Units: **{(top_5_total/total_emails*100):.1f}%** of total activity")
                    st.write(f"• Most Active Unit Share: **{(bunit_counts.iloc[0]/total_emails*100):.1f}%**")
                    
                    # Calculate concentration
                    if len(bunit_counts) > 0:
                        concentration = (bunit_counts.head(3).sum() / total_emails * 100)
                        st.write(f"• Top 3 Units Concentration: **{concentration:.1f}%**")
                
                with col2:
                    st.write("**Word Match Distribution:**")
                    if 'word_list_match' in filtered_df.columns:
                        emails_with_matches = filtered_df[
                            (filtered_df['word_list_match'].notna()) & 
                            (filtered_df['word_list_match'] != '') & 
                            (filtered_df['word_list_match'].astype(str) != '0')
                        ]
                        
                        if len(emails_with_matches) > 0:
                            bunit_word_matches = emails_with_matches['bunit'].value_counts()
                            top_word_match_unit = bunit_word_matches.index[0] if len(bunit_word_matches) > 0 else "N/A"
                            top_word_match_count = bunit_word_matches.iloc[0] if len(bunit_word_matches) > 0 else 0
                            
                            st.write(f"• Top Word Match Unit: **{top_word_match_unit}**")
                            st.write(f"• Word Matches: **{top_word_match_count:,}**")
                            st.write(f"• Total Units with Matches: **{len(bunit_word_matches)}**")
                        else:
                            st.write("• No word matches found in dataset")
                    else:
                        st.write("• Word match data not available")

            else:
                st.warning("Business Unit (bunit) data not available in the dataset")
                st.info("Please ensure your email data includes the 'bunit' field for business unit analysis")


def app_flow_dashboard_page():
    # Professional styling with enhanced design
    st.markdown("""
    <style>
    /* Main page styles */
    .main-header {
        background: linear-gradient(135deg, #3e5249 0%, #4a5d52 100%);
        color: #f5f5f0;
        padding: 2.5rem 2rem;
        border-radius: 15px;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 8px 24px rgba(62, 82, 73, 0.3);
        border: 1px solid rgba(245, 245, 240, 0.1);
    }
    
    .main-title {
        font-size: 2.8rem;
        font-weight: 700;
        margin: 0;
        color: #f5f5f0;
        text-shadow: 0 2px 4px rgba(0,0,0,0.3);
    }
    
    .main-subtitle {
        font-size: 1.2rem;
        margin: 0.5rem 0 0 0;
        opacity: 0.9;
        font-weight: 300;
        color: #e8e8e0;
    }

    /* Enhanced box styles with earthy colors */
    .flow-box {
        background: linear-gradient(135deg, #7d8471 0%, #6b7360 100%);
        color: #f5f5f0;
        padding: 1.5rem;
        border-radius: 12px;
        margin: 1rem 0;
        text-align: center;
        font-weight: 600;
        box-shadow: 0 6px 20px rgba(125, 132, 113, 0.25);
        border: 1px solid rgba(245, 245, 240, 0.1);
        transition: transform 0.3s ease, box-shadow 0.3s ease;
        position: relative;
        overflow: hidden;
    }
    
    .flow-box::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(245, 245, 240, 0.1), transparent);
        transition: left 0.5s;
    }
    
    .flow-box:hover::before {
        left: 100%;
    }
    
    .flow-box:hover {
        transform: translateY(-3px);
        box-shadow: 0 10px 28px rgba(125, 132, 113, 0.35);
    }

    .process-box {
        background: linear-gradient(135deg, #8b7765 0%, #7a6b59 100%);
        color: #f5f5f0;
        padding: 1.5rem;
        border-radius: 12px;
        margin: 1rem 0;
        text-align: center;
        font-weight: 600;
        box-shadow: 0 6px 20px rgba(139, 119, 101, 0.25);
        border: 1px solid rgba(245, 245, 240, 0.1);
        transition: transform 0.3s ease, box-shadow 0.3s ease;
        position: relative;
        overflow: hidden;
    }
    
    .process-box::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(245, 245, 240, 0.15), transparent);
        transition: left 0.5s;
    }
    
    .process-box:hover::before {
        left: 100%;
    }
    
    .process-box:hover {
        transform: translateY(-3px);
        box-shadow: 0 10px 28px rgba(139, 119, 101, 0.35);
    }

    .output-box {
        background: linear-gradient(135deg, #6d7f8b 0%, #5f7179 100%);
        color: #f5f5f0;
        padding: 1.5rem;
        border-radius: 12px;
        margin: 1rem 0;
        text-align: center;
        font-weight: 600;
        box-shadow: 0 6px 20px rgba(109, 127, 139, 0.25);
        border: 1px solid rgba(245, 245, 240, 0.1);
        transition: transform 0.3s ease, box-shadow 0.3s ease;
        position: relative;
        overflow: hidden;
    }
    
    .output-box::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(245, 245, 240, 0.15), transparent);
        transition: left 0.5s;
    }
    
    .output-box:hover::before {
        left: 100%;
    }
    
    .output-box:hover {
        transform: translateY(-3px);
        box-shadow: 0 10px 28px rgba(109, 127, 139, 0.35);
    }

    .analysis-box {
        background: linear-gradient(135deg, #6a7c69 0%, #5d6f5c 100%);
        color: #f5f5f0;
        padding: 1.5rem;
        border-radius: 12px;
        margin: 1rem 0;
        text-align: center;
        font-weight: 600;
        box-shadow: 0 6px 20px rgba(106, 124, 105, 0.25);
        border: 1px solid rgba(245, 245, 240, 0.1);
        transition: transform 0.3s ease, box-shadow 0.3s ease;
        position: relative;
        overflow: hidden;
    }
    
    .analysis-box::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(245, 245, 240, 0.15), transparent);
        transition: left 0.5s;
    }
    
    .analysis-box:hover::before {
        left: 100%;
    }
    
    .analysis-box:hover {
        transform: translateY(-3px);
        box-shadow: 0 10px 28px rgba(106, 124, 105, 0.35);
    }

    .arrow {
        text-align: center;
        font-size: 2.5rem;
        color: #6b6b47;
        margin: 1rem 0;
        text-shadow: 0 2px 4px rgba(0,0,0,0.1);
        animation: bounce 2s infinite;
    }
    
    @keyframes bounce {
        0%, 20%, 50%, 80%, 100% {
            transform: translateY(0);
        }
        40% {
            transform: translateY(-5px);
        }
        60% {
            transform: translateY(-3px);
        }
    }

    .section-header {
        background: linear-gradient(135deg, #4a5249 0%, #5d6356 100%);
        color: #f5f5f0;
        padding: 2rem;
        border-radius: 15px;
        text-align: center;
        font-size: 1.8rem;
        font-weight: 700;
        margin: 2rem 0;
        box-shadow: 0 8px 20px rgba(74, 82, 73, 0.3);
        border: 1px solid rgba(245, 245, 240, 0.1);
        position: relative;
        overflow: hidden;
    }
    
    .section-header::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 3px;
        background: linear-gradient(90deg, #7d8471, #8b7765, #6d7f8b, #6a7c69);
        animation: rainbow 3s linear infinite;
    }
    
    @keyframes rainbow {
        0% { transform: translateX(-100%); }
        100% { transform: translateX(100%); }
    }

    /* Professional card styles */
    .card {
        background: #faf9f6;
        border-radius: 15px;
        padding: 2rem;
        margin: 1rem 0;
        box-shadow: 0 6px 20px rgba(74, 82, 73, 0.15);
        border: 1px solid #e6e4df;
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }
    
    .card:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 28px rgba(74, 82, 73, 0.22);
    }

    .card-header {
        font-size: 1.4rem;
        font-weight: 700;
        color: #3e4b3e;
        margin-bottom: 1rem;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid #d4d0c4;
    }

    /* Enhanced text styles */
    .feature-list {
        list-style: none;
        padding: 0;
    }
    
    .feature-list li {
        padding: 0.5rem 0;
        padding-left: 1.5rem;
        position: relative;
        color: #5a5a4a;
    }
    
    .feature-list li::before {
        content: '▶';
        position: absolute;
        left: 0;
        color: #7d8471;
        font-weight: bold;
    }

    /* Responsive design */
    @media (max-width: 768px) {
        .main-title {
            font-size: 2rem;
        }
        
        .flow-box, .process-box, .output-box, .analysis-box {
            padding: 1rem;
        }
        
        .section-header {
            font-size: 1.4rem;
            padding: 1.5rem;
        }
    }
    
    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    
    .stTabs [data-baseweb="tab"] {
        height: 60px;
        padding: 0 24px;
        background-color: #f5f3ef;
        border-radius: 10px;
        border: 2px solid #d4d0c4;
        font-weight: 600;
        color: #5a5a4a;
    }
    
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #7d8471 0%, #6b7360 100%);
        color: #f5f5f0;
        border-color: #7d8471;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Professional header
    st.markdown("""
    <div class="main-header">
        <h1 class="main-title">🔐 ExfilEye Application Architecture</h1>
        <p class="main-subtitle">Enterprise Data Loss Prevention & Email Security Monitoring System</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Introduction with professional layout
    st.markdown("""
    <div class="card">
        <h3 class="card-header">🎯 System Overview</h3>
        <p style="font-size: 1.1rem; line-height: 1.7; color: #4a5568;">
            <strong>ExfilEye</strong> is an enterprise-grade email security monitoring platform designed to detect 
            and prevent data exfiltration through advanced machine learning algorithms, behavioral analysis, 
            and real-time threat intelligence. The system provides comprehensive visibility into email 
            communications to identify potential insider threats and unauthorized data transfers.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Enhanced tabs with professional layout
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🔄 Application Flow", 
        "⚙️ Processing Engine", 
        "📊 Analytics Engine", 
        "🛡️ Security Features",
        "🏗️ Architecture"
    ])
    
    with tab1:
        st.markdown("""
        <div class="section-header">
            📋 Complete Application Workflow
        </div>
        """, unsafe_allow_html=True)
        
        col1, col2, col3 = st.columns([1, 10, 1])
        with col2:
            st.markdown("""
            <div class="flow-box">
                🚀 <strong>INITIALIZATION</strong><br>
                <small>User Authentication & Dashboard Access</small>
            </div>
            <div class="arrow">⬇️</div>
            
            <div class="flow-box">
                📥 <strong>DATA INGESTION</strong><br>
                <small>CSV Upload with Email Data & Optional BAU Whitelist</small>
            </div>
            <div class="arrow">⬇️</div>
            
            <div class="process-box">
                🔍 <strong>DATA VALIDATION</strong><br>
                <small>Schema Validation, Field Verification & Data Quality Checks</small>
            </div>
            <div class="arrow">⬇️</div>
            
            <div class="process-box">
                🧹 <strong>DATA PREPROCESSING</strong><br>
                <small>Normalization, Parsing & Temporal Analysis</small>
            </div>
            <div class="arrow">⬇️</div>
            
            <div class="process-box">
                🏢 <strong>DOMAIN CLASSIFICATION</strong><br>
                <small>ML-Based Domain Categorization & Risk Assessment</small>
            </div>
            <div class="arrow">⬇️</div>
            
            <div class="analysis-box">
                🎯 <strong>CONTENT ANALYSIS</strong><br>
                <small>Keyword Detection & Sensitive Data Identification</small>
            </div>
            <div class="arrow">⬇️</div>
            
            <div class="analysis-box">
                🧠 <strong>RISK CALCULATION</strong><br>
                <small>Multi-Factor Scoring & Threat Level Assessment</small>
            </div>
            <div class="arrow">⬇️</div>
            
            <div class="analysis-box">
                🔬 <strong>ANOMALY DETECTION</strong><br>
                <small>Behavioral Analysis & Pattern Recognition</small>
            </div>
            <div class="arrow">⬇️</div>
            
            <div class="output-box">
                📊 <strong>SECURITY DASHBOARD</strong><br>
                <small>Real-Time Risk Visualization & Alert Management</small>
            </div>
            <div class="arrow">⬇️</div>
            
            <div class="output-box">
                📈 <strong>ADVANCED ANALYTICS</strong><br>
                <small>Trend Analysis, Predictions & Intelligence Reports</small>
            </div>
            <div class="arrow">⬇️</div>
            
            <div class="output-box">
                🌐 <strong>NETWORK ANALYSIS</strong><br>
                <small>Communication Patterns & Relationship Mapping</small>
            </div>
            <div class="arrow">⬇️</div>
            
            <div class="output-box">
                📧 <strong>INCIDENT RESPONSE</strong><br>
                <small>Automated Alerts & Follow-up Actions</small>
            </div>
            <div class="arrow">⬇️</div>
            
            <div class="flow-box">
                ✅ <strong>SECURITY TEAM ACTION</strong><br>
                <small>Investigation, Response & Threat Mitigation</small>
            </div>
            """, unsafe_allow_html=True)
    
    with tab2:
        st.markdown("""
        <div class="section-header">
            ⚙️ Data Processing Engine Architecture
        </div>
        """, unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            <div class="card">
                <h4 class="card-header">📥 Input Processing Pipeline</h4>
                <div class="process-box">
                    📄 <strong>Schema Validation</strong><br>
                    <small>Required field verification & data type checking</small>
                </div>
                <div class="arrow">⬇️</div>
                <div class="process-box">
                    🧹 <strong>Data Sanitization</strong><br>
                    <small>Email standardization & timestamp parsing</small>
                </div>
                <div class="arrow">⬇️</div>
                <div class="process-box">
                    📧 <strong>Entity Extraction</strong><br>
                    <small>Domain parsing, recipient analysis & attachment processing</small>
                </div>
                <div class="arrow">⬇️</div>
                <div class="process-box">
                    ⏰ <strong>Temporal Enrichment</strong><br>
                    <small>Business hours detection & activity patterns</small>
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="card">
                <h4 class="card-header">🔧 Intelligence Enhancement</h4>
                <div class="analysis-box">
                    🏢 <strong>Domain Intelligence</strong><br>
                    <small>Business/Free/Internal classification with industry mapping</small>
                </div>
                <div class="arrow">⬇️</div>
                <div class="analysis-box">
                    🎯 <strong>Content Intelligence</strong><br>
                    <small>Sensitive keyword detection & content categorization</small>
                </div>
                <div class="arrow">⬇️</div>
                <div class="analysis-box">
                    📎 <strong>Attachment Intelligence</strong><br>
                    <small>File type analysis, size assessment & risk evaluation</small>
                </div>
                <div class="arrow">⬇️</div>
                <div class="analysis-box">
                    👤 <strong>User Behavior Intelligence</strong><br>
                    <small>Leaver detection & behavioral profiling</small>
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        # Core Components
        st.markdown("""
        <div class="section-header">🔍 Core Processing Components</div>
        """, unsafe_allow_html=True)
        
        comp_col1, comp_col2, comp_col3 = st.columns(3)
        
        with comp_col1:
            st.markdown("""
            <div class="card">
                <h4 class="card-header">🏗️ DataProcessor</h4>
                <ul class="feature-list">
                    <li>Field validation & integrity checks</li>
                    <li>Email parsing & normalization</li>
                    <li>Temporal analysis & time zones</li>
                    <li>Recipient counting & validation</li>
                    <li>Domain extraction & standardization</li>
                    <li>Data quality assessment</li>
                </ul>
            </div>
            """)
        
        with comp_col2:
            st.markdown("""
            <div class="card">
                <h4 class="card-header">🏢 DomainClassifier</h4>
                <ul class="feature-list">
                    <li>Enterprise domain identification</li>
                    <li>Free email provider detection</li>
                    <li>Educational institution mapping</li>
                    <li>Government domain classification</li>
                    <li>Industry sector categorization</li>
                    <li>Geographic region analysis</li>
                </ul>
            </div>
            """)
        
        with comp_col3:
            st.markdown("""
            <div class="card">
                <h4 class="card-header">🔍 KeywordDetector</h4>
                <ul class="feature-list">
                    <li>Intellectual property keywords</li>
                    <li>Financial data patterns</li>
                    <li>Legal document indicators</li>
                    <li>Confidential content markers</li>
                    <li>Regulatory compliance terms</li>
                    <li>Custom keyword libraries</li>
                </ul>
            </div>
            """)
    
    with tab3:
        st.markdown("""
        <div class="section-header">📊 Advanced Analytics & Risk Assessment</div>
        """, unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            <div class="card">
                <h4 class="card-header">🧠 Multi-Layer Risk Scoring</h4>
                <div class="analysis-box">
                    🚨 <strong>CRITICAL (90-100 points)</strong><br>
                    <small>Leaver + Attachments + Keywords + Free Email + After Hours</small>
                </div>
                <div class="analysis-box">
                    🔴 <strong>HIGH (70-89 points)</strong><br>
                    <small>Leaver Activity + Large Attachments + Sensitive Keywords</small>
                </div>
                <div class="analysis-box">
                    🟡 <strong>MEDIUM (40-69 points)</strong><br>
                    <small>Attachments + Keywords + Unusual Timing</small>
                </div>
                <div class="analysis-box">
                    🟢 <strong>LOW (0-39 points)</strong><br>
                    <small>Standard business communications</small>
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="card">
                <h4 class="card-header">🔬 Machine Learning Analytics</h4>
                <div class="process-box">
                    📈 <strong>Volume Anomaly Detection</strong><br>
                    <small>Statistical analysis of email frequency patterns</small>
                </div>
                <div class="process-box">
                    🌙 <strong>Temporal Anomaly Detection</strong><br>
                    <small>After-hours & weekend activity analysis</small>
                </div>
                <div class="process-box">
                    📎 <strong>Content Anomaly Detection</strong><br>
                    <small>Unusual attachment patterns & file types</small>
                </div>
                <div class="process-box">
                    🌐 <strong>Network Anomaly Detection</strong><br>
                    <small>New domain communications & relationship changes</small>
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        # Risk Factor Weights
        st.markdown("""
        <div class="section-header">⚖️ Weighted Risk Assessment Matrix</div>
        """, unsafe_allow_html=True)
        
        risk_col1, risk_col2, risk_col3, risk_col4, risk_col5 = st.columns(5)
        
        with risk_col1:
            st.markdown("""
            <div class="card" style="text-align: center;">
                <h4 style="color: #dc3545;">🏃‍♂️ Leaver Activity</h4>
                <div style="font-size: 2rem; font-weight: bold; color: #dc3545;">70</div>
                <p><strong>Weight Points</strong></p>
                <small>Last working day detection</small>
            </div>
            """)
        
        with risk_col2:
            st.markdown("""
            <div class="card" style="text-align: center;">
                <h4 style="color: #fd7e14;">🎯 IP Keywords</h4>
                <div style="font-size: 2rem; font-weight: bold; color: #fd7e14;">25</div>
                <p><strong>Weight Points</strong></p>
                <small>Sensitive content detection</small>
            </div>
            """)
        
        with risk_col3:
            st.markdown("""
            <div class="card" style="text-align: center;">
                <h4 style="color: #ffc107;">📧 Free Domains</h4>
                <div style="font-size: 2rem; font-weight: bold; color: #ffc107;">20</div>
                <p><strong>Weight Points</strong></p>
                <small>External email providers</small>
            </div>
            """)
        
        with risk_col4:
            st.markdown("""
            <div class="card" style="text-align: center;">
                <h4 style="color: #20c997;">📎 Attachments</h4>
                <div style="font-size: 2rem; font-weight: bold; color: #20c997;">15</div>
                <p><strong>Weight Points</strong></p>
                <small>File transfer analysis</small>
            </div>
            """)
        
        with risk_col5:
            st.markdown("""
            <div class="card" style="text-align: center;">
                <h4 style="color: #6f42c1;">🌙 After Hours</h4>
                <div style="font-size: 2rem; font-weight: bold; color: #6f42c1;">10</div>
                <p><strong>Weight Points</strong></p>
                <small>Unusual timing patterns</small>
            </div>
            """)
    
    with tab4:
        st.markdown("""
        <div class="section-header">🛡️ Enterprise Security Framework</div>
        """, unsafe_allow_html=True)
        
        # Security Tool Integration
        sec_col1, sec_col2 = st.columns(2)
        
        with sec_col1:
            st.markdown("""
            <div class="card">
                <h4 class="card-header">🔧 Security Tool Integration</h4>
                <div class="analysis-box">
                    🛡️ <strong>Tessian Integration</strong><br>
                    <small>Policy-driven email security & DLP monitoring</small>
                </div>
                <div class="analysis-box">
                    📬 <strong>Mimecast Integration</strong><br>
                    <small>Email gateway security & threat analysis</small>
                </div>
                <div class="analysis-box">
                    📊 <strong>Coverage Gap Analysis</strong><br>
                    <small>Security blind spot identification & remediation</small>
                </div>
                <div class="analysis-box">
                    🔍 <strong>SIEM Integration</strong><br>
                    <small>Security event correlation & incident management</small>
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        with sec_col2:
            st.markdown("""
            <div class="card">
                <h4 class="card-header">📋 Security Coverage Status</h4>
                <div class="output-box">
                    ✅ <strong>Full Protection</strong><br>
                    <small>Tessian + Mimecast + ExfilEye monitoring</small>
                </div>
                <div class="output-box" style="background: linear-gradient(135deg, #ffc107 0%, #ff8800 100%);">
                    ⚠️ <strong>Partial Coverage</strong><br>
                    <small>Single security tool deployment</small>
                </div>
                <div class="output-box" style="background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);">
                    🚨 <strong>Security Gap</strong><br>
                    <small>No security tool coverage detected</small>
                </div>
                <div class="output-box">
                    🔄 <strong>Remediation</strong><br>
                    <small>Automated security enhancement recommendations</small>
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        # Advanced Security Features
        st.markdown("""
        <div class="section-header">🚀 Advanced Security Capabilities</div>
        """, unsafe_allow_html=True)
        
        feat_col1, feat_col2, feat_col3 = st.columns(3)
        
        with feat_col1:
            st.markdown("""
            <div class="card">
                <h4 class="card-header">🔍 Threat Intelligence</h4>
                <ul class="feature-list">
                    <li>Machine learning anomaly detection</li>
                    <li>Behavioral pattern analysis</li>
                    <li>Statistical outlier identification</li>
                    <li>Advanced clustering algorithms</li>
                    <li>Predictive threat modeling</li>
                    <li>Real-time risk assessment</li>
                </ul>
            </div>
            """)
        
        with feat_col2:
            st.markdown("""
            <div class="card">
                <h4 class="card-header">🌐 Network Intelligence</h4>
                <ul class="feature-list">
                    <li>Communication relationship mapping</li>
                    <li>Domain reputation analysis</li>
                    <li>External communication tracking</li>
                    <li>Business unit segmentation</li>
                    <li>Geographic communication patterns</li>
                    <li>Social network analysis</li>
                </ul>
            </div>
            """)
        
        with feat_col3:
            st.markdown("""
            <div class="card">
                <h4 class="card-header">📊 Business Intelligence</h4>
                <ul class="feature-list">
                    <li>Word frequency & sentiment analysis</li>
                    <li>Department communication metrics</li>
                    <li>Temporal trend identification</li>
                    <li>BAU pattern recognition</li>
                    <li>Compliance reporting automation</li>
                    <li>Executive dashboard analytics</li>
                </ul>
            </div>
            """)
    
    with tab5:
        st.markdown("""
        <div class="section-header">🏗️ System Architecture & Technical Stack</div>
        """, unsafe_allow_html=True)
        
        # Data Flow Architecture
        flow_col1, flow_col2, flow_col3, flow_col4 = st.columns(4)
        
        with flow_col1:
            st.markdown("""
            <div class="card" style="text-align: center;">
                <div class="flow-box">
                    📥 <strong>INPUT LAYER</strong>
                </div>
                <ul class="feature-list" style="text-align: left; margin-top: 1rem;">
                    <li>Email CSV data ingestion</li>
                    <li>BAU whitelist management</li>
                    <li>Configuration parameters</li>
                    <li>API integrations</li>
                    <li>Real-time data streams</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
        
        with flow_col2:
            st.markdown("""
            <div class="card" style="text-align: center;">
                <div class="process-box">
                    ⚙️ <strong>PROCESSING LAYER</strong>
                </div>
                <ul class="feature-list" style="text-align: left; margin-top: 1rem;">
                    <li>Data validation & cleaning</li>
                    <li>Email parsing & normalization</li>
                    <li>Domain classification engine</li>
                    <li>Keyword detection system</li>
                    <li>Content analysis pipeline</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
        
        with flow_col3:
            st.markdown("""
            <div class="card" style="text-align: center;">
                <div class="analysis-box">
                    🧠 <strong>ANALYTICS LAYER</strong>
                </div>
                <ul class="feature-list" style="text-align: left; margin-top: 1rem;">
                    <li>Multi-factor risk scoring</li>
                    <li>ML anomaly detection</li>
                    <li>Behavioral pattern recognition</li>
                    <li>Threat intelligence engine</li>
                    <li>Predictive modeling</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
        
        with flow_col4:
            st.markdown("""
            <div class="card" style="text-align: center;">
                <div class="output-box">
                    📊 <strong>PRESENTATION LAYER</strong>
                </div>
                <ul class="feature-list" style="text-align: left; margin-top: 1rem;">
                    <li>Interactive dashboards</li>
                    <li>Security risk reports</li>
                    <li>Analytics visualizations</li>
                    <li>Incident response alerts</li>
                    <li>Executive summaries</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
        
        # Technical Components
        st.markdown("""
        <div class="section-header">🔧 Technical Component Architecture</div>
        """, unsafe_allow_html=True)
        
        arch_col1, arch_col2 = st.columns(2)
        
        with arch_col1:
            st.markdown("""
            <div class="card">
                <h4 class="card-header">🔧 Core Processing Modules</h4>
                
                <div style="margin: 1rem 0;">
                    <h5 style="color: #3e4b3e;">📦 utils/data_processor.py</h5>
                    <ul class="feature-list">
                        <li>Multi-format email data validation</li>
                        <li>Advanced temporal analysis & parsing</li>
                        <li>Attachment metadata extraction</li>
                        <li>Recipient network analysis</li>
                        <li>Data quality assessment metrics</li>
                    </ul>
                </div>
                
                <div style="margin: 1rem 0;">
                    <h5 style="color: #3e4b3e;">🏢 utils/domain_classifier.py</h5>
                    <ul class="feature-list">
                        <li>Enterprise domain identification</li>
                        <li>Free email provider detection</li>
                        <li>Educational & government mapping</li>
                        <li>Industry sector classification</li>
                        <li>Geographic region analysis</li>
                    </ul>
                </div>
                
                <div style="margin: 1rem 0;">
                    <h5 style="color: #3e4b3e;">🧠 utils/risk_engine.py</h5>
                    <ul class="feature-list">
                        <li>Weighted multi-factor scoring</li>
                        <li>Leaver activity detection (70 pts)</li>
                        <li>IP keyword analysis (25 pts)</li>
                        <li>Free email flagging (20 pts)</li>
                        <li>Dynamic threshold adjustment</li>
                    </ul>
                </div>
            </div>
            """)
        
        with arch_col2:
            st.markdown("""
            <div class="card">
                <h4 class="card-header">📊 Analytics & Intelligence Modules</h4>
                
                <div style="margin: 1rem 0;">
                    <h5 style="color: #3e4b3e;">🔍 utils/anomaly_detector.py</h5>
                    <ul class="feature-list">
                        <li>Unsupervised ML anomaly detection</li>
                        <li>Behavioral baseline establishment</li>
                        <li>Statistical outlier identification</li>
                        <li>Ensemble method integration</li>
                        <li>Real-time pattern analysis</li>
                    </ul>
                </div>
                
                <div style="margin: 1rem 0;">
                    <h5 style="color: #3e4b3e;">📈 utils/visualization.py</h5>
                    <ul class="feature-list">
                        <li>Interactive Plotly dashboards</li>
                        <li>Network relationship graphs</li>
                        <li>Risk factor heat maps</li>
                        <li>Temporal trend analysis</li>
                        <li>Executive summary charts</li>
                    </ul>
                </div>
                
                <div style="margin: 1rem 0;">
                    <h5 style="color: #3e4b3e;">📧 utils/email_generator.py</h5>
                    <ul class="feature-list">
                        <li>Automated security alert generation</li>
                        <li>Incident response templates</li>
                        <li>Compliance report automation</li>
                        <li>Stakeholder notification system</li>
                        <li>Follow-up action recommendations</li>
                    </ul>
                </div>
            </div>
            """)
        
        # Security Workflow Summary
        st.markdown("""
        <div class="section-header">🛡️ Enterprise Security Workflow</div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div class="card">
            <p style="font-size: 1.1rem; line-height: 1.8; color: #4a5568;">
                The ExfilEye platform implements a comprehensive 8-stage security analysis workflow designed 
                for enterprise environments:
            </p>
            
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin: 2rem 0;">
                <div>
                    <h5 style="color: #3e4b3e;">🔒 Security-First Design</h5>
                    <ul class="feature-list">
                        <li><strong>Data Ingestion:</strong> Secure multi-format email data processing</li>
                        <li><strong>Content Analysis:</strong> Deep inspection with privacy protection</li>
                        <li><strong>Domain Intelligence:</strong> Comprehensive reputation analysis</li>
                        <li><strong>Risk Calculation:</strong> Multi-layered threat assessment</li>
                    </ul>
                </div>
                
                <div>
                    <h5 style="color: #3e4b3e;">⚡ Real-Time Operations</h5>
                    <ul class="feature-list">
                        <li><strong>Threat Detection:</strong> Immediate high-risk identification</li>
                        <li><strong>Visualization:</strong> Interactive security dashboards</li>
                        <li><strong>Alert Generation:</strong> Automated incident response</li>
                        <li><strong>Continuous Monitoring:</strong> 24/7 pattern analysis</li>
                    </ul>
                </div>
            </div>
            
            <div style="background: linear-gradient(135deg, #ebe8e0 0%, #d9d5c7 100%); padding: 1.5rem; border-radius: 10px; margin: 1rem 0;">
                <h5 style="color: #4a5249; margin-bottom: 0.5rem;">🎯 Mission-Critical Objective</h5>
                <p style="margin: 0; color: #4a5249; font-weight: 500;">
                    Detect and prevent data exfiltration attempts and insider threats before they impact 
                    the organization, providing security teams with actionable intelligence and automated 
                    response capabilities for comprehensive email security monitoring.
                </p>
            </div>
        </div>
        """, unsafe_allow_html=True)


        

def enhanced_domain_analysis_page(domain_classifier):
    st.header("🏢 Enhanced Domain Analysis")
    st.write("Advanced domain extraction and categorization with strict internal detection and industry classification")
    
    if st.session_state.processed_data is None:
        st.warning("Please upload email data first in the Data Upload page.")
        return
    
    df = st.session_state.processed_data
    
    # Perform comprehensive domain analysis
    with st.spinner("Analyzing domains with enhanced categorization..."):
        domain_analysis = domain_classifier.extract_and_classify_all_domains(df)
    
    # Display summary metrics
    st.subheader("📊 Domain Analysis Summary")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Unique Sender Domains", domain_analysis['risk_summary']['unique_sender_domains'])
    with col2:
        st.metric("Unique Recipient Domains", domain_analysis['risk_summary']['unique_recipient_domains'])
    with col3:
        st.metric("Internal Communications", domain_analysis['risk_summary']['total_internal_communications'])
    with col4:
        st.metric("External Communications", domain_analysis['risk_summary']['total_external_communications'])
    
    # Classification Legend
    st.info("**Classification Legend:** 🔵 Internal | 🟢 Business | 🟡 Free")
    
    # Sender Domain Analysis
    st.subheader("📤 Sender Domain Analysis")
    sender_data = []
    for domain, info in domain_analysis['sender_domains'].items():
        sender_data.append({
            'Domain': domain,
            'Email Count': info['count'],
            'Classification': info['classification'],
            'Category': info['category'],
            'Industry': info['industry'],
            'Is Business': info['is_business']
        })
    
    if sender_data:
        sender_df = pd.DataFrame(sender_data)
        sender_df = sender_df.sort_values('Email Count', ascending=False)
        
        # Apply styling to highlight different classifications
        def highlight_classification(row):
            if row['Classification'] == 'internal':
                return ['background-color: #cce5ff; font-weight: bold; color: #0056b3'] * len(row)
            elif row['Classification'] == 'business':
                return ['background-color: #e8f5e8'] * len(row)
            elif row['Classification'] == 'free':
                return ['background-color: #fff3cd'] * len(row)
            else:
                return [''] * len(row)
        
        st.dataframe(
            sender_df.style.apply(highlight_classification, axis=1),
            use_container_width=True
        )
    
    # Recipient Domain Analysis
    st.subheader("📥 Recipient Domain Analysis")
    recipient_data = []
    for domain, info in domain_analysis['recipient_domains'].items():
        recipient_data.append({
            'Domain': domain,
            'Email Count': info['count'],
            'Classification': info['classification'],
            'Category': info['category'],
            'Industry': info['industry'],
            'Is Business': info['is_business'],
            'Sender Count': len(info['senders'])
        })
    
    if recipient_data:
        recipient_df = pd.DataFrame(recipient_data)
        recipient_df = recipient_df.sort_values('Email Count', ascending=False)
        
        st.dataframe(
            recipient_df.style.apply(highlight_classification, axis=1),
            use_container_width=True
        )
    
    # Industry Breakdown
    st.subheader("🏭 Industry Classification Breakdown")
    if domain_analysis['industry_breakdown']:
        industry_df = pd.DataFrame(
            list(domain_analysis['industry_breakdown'].items()),
            columns=['Industry', 'Domain Count']
        )
        industry_df = industry_df.sort_values('Domain Count', ascending=False)
        
        col1, col2 = st.columns([1, 2])
        with col1:
            st.dataframe(industry_df, use_container_width=True)
        with col2:
            import plotly.express as px
            fig = px.pie(
                industry_df, 
                values='Domain Count', 
                names='Industry',
                title='Domain Distribution by Industry'
            )
            st.plotly_chart(fig, use_container_width=True)
    
    # Internal vs External Communications
    st.subheader("🔄 Communication Type Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Internal Communications**")
        if domain_analysis['internal_communications']:
            internal_df = pd.DataFrame(domain_analysis['internal_communications'])
            st.dataframe(internal_df.head(10), use_container_width=True)
        else:
            st.info("No internal communications detected")
    
    with col2:
        st.write("**External Communications (High Risk)**")
        if domain_analysis['external_communications']:
            external_df = pd.DataFrame(domain_analysis['external_communications'])
            high_risk_external = external_df[external_df['risk_level'] == 'high']
            if not high_risk_external.empty:
                st.dataframe(high_risk_external.head(10), use_container_width=True)
            else:
                st.info("No high-risk external communications detected")
        else:
            st.info("No external communications detected")
    
    # Enhanced Internal Detection Results
    st.subheader("🔍 Enhanced Internal Detection Results")
    
    # Show detailed analysis of internal communications
    if domain_analysis['internal_communications']:
        st.success(f"Detected {len(domain_analysis['internal_communications'])} internal communications using enhanced detection:")
        st.write("**Detection Criteria:**")
        st.write("- Exact domain matching between sender and recipient")
        st.write("- Verification that both domains are legitimate business domains")
        st.write("- Exclusion of free email providers")
        st.write("- Support for subdomain relationships within same organization")
        
        # Show sample internal communications
        internal_sample = pd.DataFrame(domain_analysis['internal_communications'][:5])
        if not internal_sample.empty:
            st.dataframe(internal_sample, use_container_width=True)
    else:
        st.info("No internal communications detected with current dataset")
    
    # Export functionality
    st.subheader("📊 Export Analysis")
    if st.button("Export Domain Analysis to CSV"):
        # Prepare comprehensive export data
        export_data = {
            'sender_domains': pd.DataFrame(sender_data) if sender_data else pd.DataFrame(),
            'recipient_domains': pd.DataFrame(recipient_data) if recipient_data else pd.DataFrame(),
            'industry_breakdown': pd.DataFrame(list(domain_analysis['industry_breakdown'].items()), 
                                             columns=['Industry', 'Count']) if domain_analysis['industry_breakdown'] else pd.DataFrame(),
            'internal_communications': pd.DataFrame(domain_analysis['internal_communications']) if domain_analysis['internal_communications'] else pd.DataFrame(),
            'external_communications': pd.DataFrame(domain_analysis['external_communications']) if domain_analysis['external_communications'] else pd.DataFrame()
        }
        
        # Create download buttons for each dataset
        for name, data in export_data.items():
            if not data.empty:
                csv = data.to_csv(index=False)
                st.download_button(
                    label=f"Download {name.replace('_', ' ').title()}",
                    data=csv,
                    file_name=f"domain_analysis_{name}.csv",
                    mime="text/csv"
                )

if __name__ == "__main__":
    main()