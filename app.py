import streamlit as st
import pandas as pd
import numpy as np
import os
from datetime import datetime, timedelta
import io
import warnings
import time
warnings.filterwarnings('ignore')
pd.options.mode.chained_assignment = None

# Import utility modules
from utils.data_processor import DataProcessor
from utils.risk_engine import RiskEngine
from utils.anomaly_detector import AnomalyDetector
from utils.domain_classifier import DomainClassifier
from utils.visualization import Visualizer

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

def filter_whitelisted_emails(df, whitelist_df):
    """Filter out whitelisted emails from the dataset"""
    if whitelist_df is None or whitelist_df.empty or df.empty:
        return df
    
    # Create mask for non-whitelisted emails
    mask = pd.Series([True] * len(df), index=df.index)
    
    for idx, row in df.iterrows():
        sender = row.get('sender', '')
        recipients = row.get('recipients', '')
        
        # Check sender email
        if sender in whitelist_df['email_address'].values:
            mask[idx] = False
            continue
            
        # Check sender domain
        sender_domain = sender.split('@')[-1] if '@' in sender else ''
        if sender_domain in whitelist_df['domain'].values:
            mask[idx] = False
            continue
            
        # Check recipient domains
        if pd.notna(recipients):
            recipient_emails = str(recipients).split(',')
            for email in recipient_emails:
                email = email.strip()
                if email in whitelist_df['email_address'].values:
                    mask[idx] = False
                    break
                recipient_domain = email.split('@')[-1] if '@' in email else ''
                if recipient_domain in whitelist_df['domain'].values:
                    mask[idx] = False
                    break
    
    return df[mask]

def main():
    st.title("🔍 ExfilEye - DLP Email Monitor")

    # Initialize components
    data_processor = DataProcessor()
    risk_engine = RiskEngine()
    anomaly_detector = AnomalyDetector()
    domain_classifier = DomainClassifier()
    visualizer = Visualizer()
    keyword_detector = KeywordDetector()

    # Enhanced Sidebar navigation with custom styling
    st.sidebar.markdown("""
    <style>
    .sidebar-title {
        font-size: 1.5rem;
        font-weight: 700;
        color: #1f4e79;
        text-align: center;
        padding: 1rem 0;
        border-bottom: 2px solid #e8f4fd;
        margin-bottom: 1.5rem;
    }
    .section-header {
        font-size: 1rem;
        font-weight: 600;
        color: #2c5aa0;
        margin: 1.5rem 0 0.5rem 0;
        padding: 0.5rem;
        background: linear-gradient(90deg, #f8f9fa 0%, #e9ecef 100%);
        border-radius: 8px;
        border-left: 4px solid #2c5aa0;
    }
    .nav-description {
        font-size: 0.85rem;
        color: #6c757d;
        font-style: italic;
        margin-bottom: 1rem;
        padding: 0 0.5rem;
    }
    </style>
    """, unsafe_allow_html=True)
    


    # Enhanced navigation footer
    st.sidebar.markdown("---")
    st.sidebar.markdown("""
    <div style="
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        margin-top: 2rem;
        text-align: center;
        color: white;
    ">
        <div style="font-size: 0.9rem; font-weight: 600; margin-bottom: 0.5rem;">
            🔐 ExfilEye DLP Monitor
        </div>
        <div style="font-size: 0.75rem; opacity: 0.9;">
            Real-time Email Security Intelligence
        </div>
        <div style="font-size: 0.7rem; opacity: 0.7; margin-top: 0.5rem;">
            v2.0 | Enterprise Edition
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Quick stats in sidebar if data is available
    if st.session_state.processed_data is not None:
        st.sidebar.markdown("### 📊 Quick Stats")
        original_df = st.session_state.processed_data.copy()
        df_filtered = filter_whitelisted_emails(original_df, st.session_state.whitelist_data)
        
        col1, col2 = st.sidebar.columns(2)
        with col1:
            st.metric("Total Emails", f"{len(original_df):,}", label_visibility="visible")
        with col2:
            st.metric("Analyzed", f"{len(df_filtered):,}", label_visibility="visible")
        
        # Risk indicator if available
        if hasattr(st.session_state, 'risk_scores') and st.session_state.risk_scores is not None and len(st.session_state.risk_scores) > 0:
            high_risk_count = sum(1 for score in st.session_state.risk_scores if score >= 61)
            if high_risk_count > 0:
                st.sidebar.markdown(f"""
                <div style="
                    background-color: #ffebee;
                    border: 1px solid #f8bbd9;
                    border-radius: 6px;
                    padding: 0.5rem;
                    margin: 0.5rem 0;
                    text-align: center;
                ">
                    <div style="color: #c62828; font-weight: 600; font-size: 0.85rem;">
                        🚨 {high_risk_count} High Risk Alerts
                    </div>
                </div>
                """, unsafe_allow_html=True)


    # Enhanced title
    st.sidebar.markdown('<div class="sidebar-title">🔍 ExfilEye Navigation</div>', unsafe_allow_html=True)
    
    # Core Functions section
    st.sidebar.markdown('<div class="section-header">🎯 Core Functions</div>', unsafe_allow_html=True)
    st.sidebar.markdown('<div class="nav-description">Essential email security monitoring tools</div>', unsafe_allow_html=True)
    main_pages = ["📁 Data Upload", "📋 Daily Checks", "📈 Analytics", "⚪ Whitelist Domains Check"]
    
    # Follow-up Management section
    st.sidebar.markdown('<div class="section-header">📧 Follow-up Management</div>', unsafe_allow_html=True)
    st.sidebar.markdown('<div class="nav-description">Generate and manage security follow-up communications</div>', unsafe_allow_html=True)
    followup_pages = ["📧 Follow-up Email Center"]
    
    # System Information section
    st.sidebar.markdown('<div class="section-header">ℹ️ System Information</div>', unsafe_allow_html=True)
    st.sidebar.markdown('<div class="nav-description">Detailed analysis and system overview</div>', unsafe_allow_html=True)
    system_pages = ["📊 Extra Info", "📧 Email Monitoring Sources", "🔄 App Workflow Overview"]
    
    # Combine all pages for radio selection with better spacing
    all_pages = main_pages + followup_pages + system_pages
    
    st.sidebar.markdown("<br>", unsafe_allow_html=True)
    page = st.sidebar.radio(
        "Select Page", 
        all_pages,
        label_visibility="collapsed"
    )

    if page == "📁 Data Upload":
        data_upload_page(data_processor, domain_classifier, keyword_detector)
    elif page == "📋 Daily Checks":
        dashboard_page(risk_engine, anomaly_detector, visualizer)
    elif page == "📈 Analytics":
        analytics_page(visualizer, anomaly_detector, domain_classifier)
    elif page == "📊 Extra Info":
        find_the_needle_page(domain_classifier, visualizer)
    elif page == "📧 Email Monitoring Sources":
        security_coverage_page()
    elif page == "🔄 App Workflow Overview":
        app_workflow_overview_page()
    elif page == "⚪ Whitelist Domains Check":
        whitelist_dashboard_page()
    elif page == "📧 Follow-up Email Center":
        followup_email_center_page()

def security_coverage_page():
    st.header("📧 Email Monitoring Sources")
    
    if st.session_state.processed_data is None:
        st.warning("Please upload email data first in the Data Upload page.")
        return
    
    # Filter out whitelisted emails
    original_df = st.session_state.processed_data.copy()
    df = filter_whitelisted_emails(original_df, st.session_state.whitelist_data)
    
    if df.empty:
        st.warning("All emails are whitelisted. Security coverage analysis not available.")
        st.info("Visit the 'Whitelist Domains Check' page to review whitelisted emails.")
        return
    
    # Add note about whitelist filtering
    st.info(f"📋 **Filtered Analysis:** Analyzing {len(df):,} non-whitelisted emails out of {len(original_df):,} total emails.")
    
    # Add explanatory note about email monitoring sources
    st.info("""
    📋 **Email Monitoring Sources Information**
    
    This analysis shows email monitoring coverage from two different security systems:
    - **Mimecast**: Captures and monitors all outgoing emails as a comprehensive email gateway solution
    - **Tessian**: Policy-based monitoring system that triggers alerts only when specific security policies are matched
    
    The monitoring categories are:
    - **Dual Monitoring**: Emails captured by Mimecast and also triggered Tessian policies
    - **Mimecast Only**: Emails captured by Mimecast but did not trigger any Tessian policies
    - **Tessian Only**: Emails that triggered Tessian policies (less common scenario)
    - **No Monitoring**: Emails not captured by either system (indicates potential gaps)
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
                    try:
                        processed_df = data_processor.process_email_data(df)

                        # Apply domain classification
                        processed_df = domain_classifier.classify_domains(processed_df)

                        # Apply keyword detection
                        processed_df = keyword_detector.detect_keywords(processed_df)
                    except Exception as processing_error:
                        st.error(f"Error processing data: {str(processing_error)}")
                        st.info("This error may be due to data format issues. Please check that text fields don't contain NaN values.")
                        return

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



def dashboard_page(risk_engine, anomaly_detector, visualizer):
    # Professional header with custom styling
    st.markdown("""
    <div style="background: linear-gradient(90deg, #1f4e79 0%, #2c5aa0 100%); padding: 2rem; border-radius: 10px; margin-bottom: 2rem;">
        <h1 style="color: white; margin: 0; font-size: 2.5rem; font-weight: 600;">
            📋 Daily Checks
        </h1>
        <p style="color: #e8f4fd; margin: 0.5rem 0 0 0; font-size: 1.1rem;">
            Real-time Email Security Monitoring & Risk Analysis
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Add explanatory note about security tool coverage and whitelist filtering
    st.info("""
    ℹ️ **Security Tool Coverage Note:** 
    Tessian operates on policy-driven detection and selectively monitors email events based on configured security policies. 
    It targets communications containing sensitive information patterns, suspicious attachments, and potential data loss scenarios. 
    Not all emails will show Tessian coverage as it focuses resources on emails matching specific security criteria and 
    organizational risk policies, rather than monitoring every email event.
    
    📋 **Whitelist Filtering:** All emails from/to whitelisted domains and addresses are excluded from this dashboard. 
    To review whitelisted communications, visit the "Whitelist Domains Check" page.
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

    # Filter out whitelisted emails
    original_df = st.session_state.processed_data.copy()
    df = filter_whitelisted_emails(original_df, st.session_state.whitelist_data)
    
    if df.empty:
        st.warning("All emails are whitelisted. Please check the Whitelist Domains Check page for details.")
        return
    
    # Calculate risk scores for filtered data
    if st.session_state.risk_scores is None:
        with st.spinner("🔄 Calculating risk scores..."):
            all_risk_scores = risk_engine.calculate_risk_scores(
                original_df,
                st.session_state.whitelist_data
            )
            st.session_state.risk_scores = all_risk_scores
    
    # Get risk scores for non-whitelisted emails only
    original_indices = df.index
    
    # Create a list of risk scores that matches the filtered dataframe length
    risk_scores = []
    for i in original_indices:
        if i < len(st.session_state.risk_scores):
            risk_scores.append(st.session_state.risk_scores[i])
        else:
            risk_scores.append(0)  # Default risk score for missing indices
    
    # Add risk scores to dataframe
    df.loc[:, 'risk_score'] = risk_scores
    df.loc[:, 'risk_level'] = df['risk_score'].apply(lambda x: 
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
    df.loc[:, 'has_attachments_bool'] = df['attachments'].notna() & (df['attachments'] != '') & (df['attachments'].astype(str) != '0')
    df.loc[:, 'has_last_working_day'] = df['last_working_day'].notna()
    
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
    
    df.loc[:, 'security_coverage'] = df.apply(get_security_coverage, axis=1)

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

    df.loc[:, 'word_match_score'] = df['word_list_match'].apply(get_word_match_score)

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
            Emails that meet critical criteria, including:<br>
            • Messages with file attachments<br>
            • Keywords matches indicating sensitive content<br>
            • Emails sent by departing employees to free/public email domains
        </p>
    </div>
    """, unsafe_allow_html=True)

    if len(high_risk_emails) > 0:
        # Display with highlighting - include email_domain to show free email detection
        display_cols = ['time', 'sender', 'recipients', 'email_domain', 'subject', 'risk_score', 'last_working_day', 'word_list_match', 'attachments']
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
        display_cols = ['time', 'sender', 'recipients', 'email_domain', 'subject', 'risk_score', 'last_working_day', 'word_list_match', 'attachments']
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
        display_cols = ['time', 'sender', 'recipients', 'subject', 'risk_score', 'last_working_day', 'word_list_match', 'attachments']
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
        display_cols = ['time', 'sender', 'recipients', 'subject', 'risk_score', 'attachments', 'last_working_day', 'word_list_match']
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

            return styles

        styled_low_risk = low_risk_emails[available_cols].style.apply(highlight_low_risk, axis=1)
        st.dataframe(styled_low_risk, use_container_width=True, height=400)
    else:
        st.info("No low-risk emails found.")



def analytics_page(visualizer, anomaly_detector, domain_classifier):
    st.header("📈 Advanced Analytics")

    if st.session_state.processed_data is None:
        st.warning("Please upload email data first in the Data Upload page.")
        return

    # Filter out whitelisted emails
    original_df = st.session_state.processed_data.copy()
    df = filter_whitelisted_emails(original_df, st.session_state.whitelist_data)
    
    if df.empty:
        st.warning("All emails are whitelisted. Analytics not available for whitelisted communications.")
        st.info("Visit the 'Whitelist Domains Check' page to review whitelisted emails.")
        return
    
    # Add note about whitelist filtering
    st.info(f"📋 **Filtered Analysis:** Showing {len(df):,} non-whitelisted emails out of {len(original_df):,} total emails. Whitelisted emails excluded from analysis.")

    if st.session_state.risk_scores is not None:
        # Get risk scores for the filtered dataframe
        original_indices = df.index
        risk_scores = []
        for i in original_indices:
            if i < len(st.session_state.risk_scores):
                risk_scores.append(st.session_state.risk_scores[i])
            else:
                risk_scores.append(0)  # Default risk score for missing indices
        
        df.loc[:, 'risk_score'] = risk_scores
        df.loc[:, 'risk_level'] = df['risk_score'].apply(lambda x: 
            'High' if x >= 61 else 'Medium' if x >= 31 else 'Low'
        )

    # Analytics options
    analysis_type = st.selectbox(
        "Select Analysis Type",
        ["Overview", "Anomaly Detection", "Risk Analysis", "Domain Analysis", "Advanced Analytics - Low Risk BAU"]
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

            # Enhanced Anomaly Details
            st.subheader("📋 Detailed Anomaly Analysis")
            
            # Get anomaly explanations from the detector
            if hasattr(anomaly_detector, 'last_analyzed_df'):
                anomaly_df_with_reasons = anomaly_detector.last_analyzed_df[anomaly_detector.last_analyzed_df['is_anomaly']].copy()
                
                if not anomaly_df_with_reasons.empty:
                    # Add risk scores to anomaly data if available
                    if 'risk_score' in df.columns:
                        # Merge risk scores from the main dataframe
                        anomaly_df_with_reasons = anomaly_df_with_reasons.merge(
                            df[['risk_score']].reset_index(), 
                            left_index=True, 
                            right_on='index', 
                            how='left'
                        ).set_index('index')
                    
                    # Sort by anomaly score (most anomalous first)
                    if 'anomaly_score' in anomaly_df_with_reasons.columns:
                        anomaly_df_with_reasons = anomaly_df_with_reasons.sort_values('anomaly_score', ascending=True)
                    
                    st.write(f"**{len(anomaly_df_with_reasons)} Anomalous Emails Detected**")
                    st.info("📊 These emails show behavioral patterns that deviate significantly from normal activity")
                    
                    # Enhanced display with risk indicators
                    display_data = []
                    for idx, (original_idx, row) in enumerate(anomaly_df_with_reasons.head(20).iterrows()):
                        # Format time
                        time_str = str(row.get('time', 'N/A'))
                        if 'T' in time_str:
                            time_str = time_str.split('T')[0] + ' ' + time_str.split('T')[1][:8]
                        
                        # Get anomaly reasons
                        reasons = "Statistical outlier"
                        if 'anomaly_reasons' in row and row['anomaly_reasons']:
                            reasons = str(row['anomaly_reasons']).replace(' | ', ' • ')
                        
                        # Format risk score and determine risk indicator
                        risk_score = row.get('risk_score', 0)
                        if pd.notna(risk_score) and risk_score > 0:
                            risk_display = f"{risk_score:.1f}/100"
                            # Determine risk indicator from dashboard classification
                            if risk_score >= 61:
                                risk_indicator = "🔴 High Risk"
                                risk_category = "Critical Alert"
                            elif risk_score >= 31:
                                risk_indicator = "🟡 Medium Risk"
                                risk_category = "Monitor"
                            else:
                                risk_indicator = "🟢 Low Risk"
                                risk_category = "Normal"
                        else:
                            risk_display = "N/A"
                            risk_indicator = "⚪ Unknown"
                            risk_category = "Unassessed"
                        
                        # Format anomaly score
                        anomaly_score = row.get('anomaly_score', 0)
                        anomaly_display = f"{anomaly_score:.3f}" if anomaly_score else "N/A"
                        
                        # Get additional context from original email data
                        attachments = row.get('attachments', '')
                        has_attachments = "📎 Yes" if pd.notna(attachments) and str(attachments).strip() and str(attachments) != '0' else "❌ No"
                        
                        word_match = row.get('word_list_match', '')
                        has_keywords = "🎯 Yes" if pd.notna(word_match) and str(word_match).strip() and str(word_match) != '0' else "❌ No"
                        
                        # Check for leaver status
                        leaver_status = "🏃‍♂️ Leaver" if pd.notna(row.get('last_working_day')) else "👤 Active"
                        
                        # Get email domain type
                        email_domain = row.get('email_domain', 'Unknown')
                        if any(free_domain in str(email_domain).lower() for free_domain in ['gmail', 'yahoo', 'hotmail', 'outlook']):
                            domain_type = "📧 Free Email"
                        else:
                            domain_type = "🏢 Business"
                        
                        display_data.append({
                            'Priority': f"#{idx+1}",
                            'Date/Time': time_str,
                            'Sender': str(row.get('sender', 'Unknown'))[:35] + ('...' if len(str(row.get('sender', ''))) > 35 else ''),
                            'Subject': str(row.get('subject', 'No Subject'))[:35] + ('...' if len(str(row.get('subject', ''))) > 35 else ''),
                            'Risk Indicator': risk_indicator,
                            'Risk Score': risk_display,
                            'Risk Category': risk_category,
                            'Anomaly Score': anomaly_display,
                            'Leaver Status': leaver_status,
                            'Attachments': has_attachments,
                            'Keywords': has_keywords,
                            'Domain Type': domain_type,
                            'Recipients': str(row.get('recipient_count', 'N/A')),
                            'Anomaly Reasons': reasons[:60] + ('...' if len(reasons) > 60 else '')
                        })
                    
                    # Display as enhanced dataframe
                    anomaly_display_df = pd.DataFrame(display_data)
                    
                    # Enhanced color coding based on both risk and anomaly scores
                    def highlight_anomalies_enhanced(row):
                        styles = [''] * len(row)
                        
                        # Color code risk indicator
                        if 'Risk Indicator' in row.index:
                            risk_idx = row.index.get_loc('Risk Indicator')
                            if '🔴' in str(row['Risk Indicator']):
                                styles[risk_idx] = 'background-color: #ffebee; color: #c62828; font-weight: bold'
                            elif '🟡' in str(row['Risk Indicator']):
                                styles[risk_idx] = 'background-color: #fff3e0; color: #ef6c00; font-weight: bold'
                            elif '🟢' in str(row['Risk Indicator']):
                                styles[risk_idx] = 'background-color: #e8f5e8; color: #2e7d32; font-weight: bold'
                        
                        # Highlight risk score
                        if 'Risk Score' in row.index and row['Risk Score'] != 'N/A':
                            try:
                                score = float(str(row['Risk Score']).split('/')[0])
                                risk_score_idx = row.index.get_loc('Risk Score')
                                if score >= 80:
                                    styles[risk_score_idx] = 'background-color: #ffcdd2; color: #b71c1c; font-weight: bold'
                                elif score >= 60:
                                    styles[risk_score_idx] = 'background-color: #ffe0b2; color: #e65100; font-weight: bold'
                                elif score >= 40:
                                    styles[risk_score_idx] = 'background-color: #fff9c4; color: #f57f17; font-weight: bold'
                            except:
                                pass
                        
                        # Highlight leaver status
                        if 'Leaver Status' in row.index and '🏃‍♂️' in str(row['Leaver Status']):
                            leaver_idx = row.index.get_loc('Leaver Status')
                            styles[leaver_idx] = 'background-color: #ffebee; color: #c62828; font-weight: bold'
                        
                        # Highlight keywords presence
                        if 'Keywords' in row.index and '🎯' in str(row['Keywords']):
                            keywords_idx = row.index.get_loc('Keywords')
                            styles[keywords_idx] = 'background-color: #fff3e0; color: #ef6c00; font-weight: bold'
                        
                        return styles
                    
                    # Apply enhanced styling and display
                    styled_df = anomaly_display_df.style.apply(highlight_anomalies_enhanced, axis=1)
                    st.dataframe(styled_df, use_container_width=True, height=500)
                    
                    # Enhanced summary statistics
                    st.subheader("📊 Anomaly Intelligence Summary")
                    
                    # Risk indicator breakdown
                    col1, col2, col3, col4, col5 = st.columns(5)
                    
                    with col1:
                        critical_anomalies = len([d for d in display_data if '🔴' in d.get('Risk Indicator', '')])
                        st.metric("🔴 Critical Risk", critical_anomalies, help="High risk anomalies requiring immediate attention")
                    
                    with col2:
                        medium_anomalies = len([d for d in display_data if '🟡' in d.get('Risk Indicator', '')])
                        st.metric("🟡 Medium Risk", medium_anomalies, help="Medium risk anomalies for monitoring")
                    
                    with col3:
                        leaver_anomalies = len([d for d in display_data if '🏃‍♂️' in d.get('Leaver Status', '')])
                        st.metric("🏃‍♂️ Leavers", leaver_anomalies, help="Anomalies from departing employees")
                    
                    with col4:
                        keyword_anomalies = len([d for d in display_data if '🎯' in d.get('Keywords', '')])
                        st.metric("🎯 With Keywords", keyword_anomalies, help="Anomalies containing sensitive keywords")
                    
                    with col5:
                        attachment_anomalies = len([d for d in display_data if '📎' in d.get('Attachments', '')])
                        st.metric("📎 With Files", attachment_anomalies, help="Anomalies containing attachments")
                    
                    # Additional insights
                    st.subheader("🔍 Risk Distribution Analysis")
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        risk_scores = [float(d['Risk Score'].split('/')[0]) for d in display_data if d['Risk Score'] != 'N/A']
                        avg_risk = sum(risk_scores) / len(risk_scores) if len(risk_scores) > 0 else 0
                        max_risk = max(risk_scores) if risk_scores else 0
                        st.metric("Average Risk Score", f"{avg_risk:.1f}/100", f"Max: {max_risk:.1f}")
                        
                        unique_senders = len(set([d['Sender'] for d in display_data]))
                        st.metric("Unique Senders", unique_senders)
                    
                    with col2:
                        total_recipients = sum([int(d['Recipients']) for d in display_data if str(d['Recipients']).isdigit()])
                        avg_recipients = total_recipients / len(display_data) if len(display_data) > 0 else 0
                        st.metric("Total Recipients", total_recipients, f"Avg: {avg_recipients:.1f}")
                        
                        free_email_anomalies = len([d for d in display_data if '📧' in d.get('Domain Type', '')])
                        st.metric("Free Email Domains", free_email_anomalies)
                    
                    # Enhanced detailed view option
                    st.subheader("🔎 Individual Anomaly Deep Dive")
                    selected_anomaly = st.selectbox(
                        "Select an anomaly for comprehensive analysis:",
                        options=range(len(display_data)),
                        format_func=lambda x: f"#{x+1}: {display_data[x]['Risk Indicator']} - {display_data[x]['Sender'][:25]} - {display_data[x]['Subject'][:30]}"
                    )
                    
                    if selected_anomaly is not None:
                        selected_row = anomaly_df_with_reasons.iloc[selected_anomaly]
                        selected_display = display_data[selected_anomaly]
                        
                        # Header with risk indicator
                        risk_indicator = selected_display['Risk Indicator']
                        st.markdown(f"""
                        <div style="background: linear-gradient(90deg, #f8f9fa 0%, #e9ecef 100%); padding: 1rem; border-radius: 8px; margin: 1rem 0; border-left: 4px solid {'#dc3545' if '🔴' in risk_indicator else '#ffc107' if '🟡' in risk_indicator else '#28a745'};">
                            <h3 style="margin: 0; color: #495057;">Anomaly #{selected_anomaly + 1} - {risk_indicator}</h3>
                            <p style="margin: 0.5rem 0 0 0; color: #6c757d;">Complete forensic analysis and risk assessment</p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # Three-column layout for comprehensive details
                        col1, col2, col3 = st.columns([1, 1, 1])
                        
                        with col1:
                            st.markdown("#### 📧 Email Details")
                            st.write(f"**📅 Time:** {selected_row.get('time', 'N/A')}")
                            st.write(f"**👤 Sender:** {selected_row.get('sender', 'N/A')}")
                            st.write(f"**📝 Subject:** {selected_row.get('subject', 'N/A')}")
                            st.write(f"**👥 Recipients:** {selected_row.get('recipient_count', 'N/A')}")
                            st.write(f"**🌐 Email Domain:** {selected_row.get('email_domain', 'N/A')}")
                            st.write(f"**🏢 Department:** {selected_row.get('department', 'N/A')}")
                            st.write(f"**💼 Business Unit:** {selected_row.get('bunit', 'N/A')}")
                            
                            # Leaver information
                            if pd.notna(selected_row.get('last_working_day')):
                                st.markdown("**🏃‍♂️ Leaver Status:** ⚠️ **DEPARTING EMPLOYEE**")
                                st.write(f"**Last Working Day:** {selected_row.get('last_working_day')}")
                            else:
                                st.write("**👤 Employee Status:** Active")
                            
                        with col2:
                            st.markdown("#### ⚖️ Risk Assessment")
                            risk_score = selected_row.get('risk_score', 0)
                            if pd.notna(risk_score) and risk_score > 0:
                                st.write(f"**🎯 Risk Score:** {risk_score:.1f}/100")
                                # Risk level classification
                                if risk_score >= 61:
                                    st.markdown("**📊 Risk Classification:** 🔴 **HIGH RISK**")
                                    st.markdown("**⚡ Action Required:** Immediate investigation")
                                elif risk_score >= 31:
                                    st.markdown("**📊 Risk Classification:** 🟡 **MEDIUM RISK**")
                                    st.markdown("**⚡ Action Required:** Monitor and review")
                                else:
                                    st.markdown("**📊 Risk Classification:** 🟢 **LOW RISK**")
                                    st.markdown("**⚡ Action Required:** Log for trends")
                            else:
                                st.write("**🎯 Risk Score:** Not assessed")
                            
                            # Anomaly metrics
                            if 'anomaly_score' in selected_row:
                                anomaly_score = selected_row['anomaly_score']
                                st.write(f"**🔬 Anomaly Score:** {anomaly_score:.3f}")
                                anomaly_severity = "Extreme" if anomaly_score < -2 else "High" if anomaly_score < -1 else "Moderate"
                                st.write(f"**📈 Anomaly Severity:** {anomaly_severity}")
                            
                            # Content analysis
                            st.markdown("#### 📋 Content Analysis")
                            attachments = selected_row.get('attachments', '')
                            if pd.notna(attachments) and str(attachments).strip() and str(attachments) != '0':
                                st.write(f"**📎 Attachments:** ⚠️ {attachments}")
                            else:
                                st.write("**📎 Attachments:** None")
                            
                            word_match = selected_row.get('word_list_match', '')
                            if pd.notna(word_match) and str(word_match).strip() and str(word_match) != '0':
                                st.write(f"**🎯 Keywords Found:** ⚠️ {word_match}")
                            else:
                                st.write("**🎯 Keywords Found:** None")
                        
                        with col3:
                            st.markdown("#### 🚨 Anomaly Analysis")
                            if 'anomaly_reasons' in selected_row and selected_row['anomaly_reasons']:
                                reasons = str(selected_row['anomaly_reasons']).split(' | ')
                                st.write("**🔍 Detected Anomalies:**")
                                for i, reason in enumerate(reasons, 1):
                                    st.write(f"{i}. {reason}")
                            else:
                                st.write("• Statistical outlier based on behavioral patterns")
                            
                            st.markdown("#### 🛡️ Security Indicators")
                            
                            # Domain type assessment
                            email_domain = selected_row.get('email_domain', '')
                            if any(free_domain in str(email_domain).lower() for free_domain in ['gmail', 'yahoo', 'hotmail', 'outlook']):
                                st.write("**🌐 Domain Type:** ⚠️ Free Email Provider")
                            else:
                                st.write("**🌐 Domain Type:** Business Domain")
                            
                            # Security coverage
                            tessian = selected_row.get('tessian_policy', '')
                            mimecast = selected_row.get('mimecast', '')
                            
                            has_tessian = pd.notna(tessian) and str(tessian).strip() not in ['', '0', 'nan', 'None']
                            has_mimecast = pd.notna(mimecast) and str(mimecast).strip() not in ['', '0', 'nan', 'None']
                            
                            if has_tessian and has_mimecast:
                                st.write("**🛡️ Security Coverage:** ✅ Full (Tessian + Mimecast)")
                            elif has_tessian or has_mimecast:
                                tool = "Tessian" if has_tessian else "Mimecast"
                                st.write(f"**🛡️ Security Coverage:** ⚠️ Partial ({tool} only)")
                            else:
                                st.write("**🛡️ Security Coverage:** ❌ No Coverage")
                            
                            # Timing analysis
                            try:
                                email_time = pd.to_datetime(selected_row.get('time'))
                                hour = email_time.hour
                                if hour < 6 or hour > 22:
                                    st.write(f"**⏰ Timing:** ⚠️ After hours ({hour:02d}:{email_time.minute:02d})")
                                elif 6 <= hour <= 8 or 18 <= hour <= 22:
                                    st.write(f"**⏰ Timing:** 🟡 Early/Late ({hour:02d}:{email_time.minute:02d})")
                                else:
                                    st.write(f"**⏰ Timing:** ✅ Business hours ({hour:02d}:{email_time.minute:02d})")
                            except:
                                st.write("**⏰ Timing:** Unable to analyze")
                        
                        # Recommendations section
                        st.markdown("---")
                        st.markdown("#### 🎯 Recommended Actions")
                        
                        risk_score = selected_row.get('risk_score', 0)
                        has_leaver = pd.notna(selected_row.get('last_working_day'))
                        has_keywords = pd.notna(selected_row.get('word_list_match')) and str(selected_row.get('word_list_match')).strip() and str(selected_row.get('word_list_match')) != '0'
                        has_attachments = pd.notna(selected_row.get('attachments')) and str(selected_row.get('attachments')).strip() and str(selected_row.get('attachments')) != '0'
                        
                        recommendations = []
                        
                        if has_leaver:
                            recommendations.append("🚨 **PRIORITY 1:** Review all recent emails from this departing employee")
                            recommendations.append("🔍 **PRIORITY 1:** Check if emails contain company intellectual property")
                            recommendations.append("📧 **PRIORITY 1:** Verify recipient legitimacy and business justification")
                        
                        if has_keywords and has_attachments:
                            recommendations.append("⚠️ **PRIORITY 2:** Scan attachments for sensitive data")
                            recommendations.append("🔐 **PRIORITY 2:** Review keyword context in email content")
                        
                        if risk_score >= 61:
                            recommendations.append("🚨 **HIGH RISK:** Escalate to security team immediately")
                            recommendations.append("📞 **HIGH RISK:** Consider contacting sender to verify legitimate activity")
                        elif risk_score >= 31:
                            recommendations.append("⚠️ **MEDIUM RISK:** Monitor sender for pattern changes")
                            recommendations.append("📝 **MEDIUM RISK:** Document for trend analysis")
                        
                        # General recommendations
                        if not has_tessian or not has_mimecast:
                            recommendations.append("🛡️ **SECURITY:** Ensure complete security tool coverage")
                        
                        # Display recommendations
                        if recommendations:
                            for rec in recommendations:
                                st.write(rec)
                        else:
                            st.info("Standard monitoring protocols apply. Continue observing for pattern changes.")
                
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

    elif analysis_type == "Domain Analysis":
        st.subheader("🏢 Domain Analysis")
        st.write("Advanced domain extraction and categorization with strict internal detection and industry classification")
        
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


def whitelist_dashboard_page():
    st.header("⚪ Whitelist Domains Check")
    
    if st.session_state.processed_data is None:
        st.warning("Please upload email data first in the Data Upload page.")
        return
    
    original_df = st.session_state.processed_data.copy()
    
    # Get whitelisted emails
    if st.session_state.whitelist_data is None or st.session_state.whitelist_data.empty:
        st.info("No whitelist data available. Upload a whitelist file in the Data Upload page.")
        return
    
    # Find whitelisted emails
    whitelisted_emails = []
    whitelist_df = st.session_state.whitelist_data
    
    for idx, row in original_df.iterrows():
        sender = row.get('sender', '')
        recipients = row.get('recipients', '')
        is_whitelisted = False
        whitelist_reason = ""
        
        # Check sender email
        if sender in whitelist_df['email_address'].values:
            is_whitelisted = True
            whitelist_reason = f"Sender email '{sender}' is whitelisted"
        
        # Check sender domain
        if not is_whitelisted:
            sender_domain = sender.split('@')[-1] if '@' in sender else ''
            if sender_domain in whitelist_df['domain'].values:
                is_whitelisted = True
                whitelist_reason = f"Sender domain '{sender_domain}' is whitelisted"
        
        # Check recipient domains
        if not is_whitelisted and pd.notna(recipients):
            recipient_emails = str(recipients).split(',')
            for email in recipient_emails:
                email = email.strip()
                if email in whitelist_df['email_address'].values:
                    is_whitelisted = True
                    whitelist_reason = f"Recipient email '{email}' is whitelisted"
                    break
                recipient_domain = email.split('@')[-1] if '@' in email else ''
                if recipient_domain in whitelist_df['domain'].values:
                    is_whitelisted = True
                    whitelist_reason = f"Recipient domain '{recipient_domain}' is whitelisted"
                    break
        
        if is_whitelisted:
            whitelisted_emails.append({
                'index': idx,
                'time': row.get('time', ''),
                'sender': sender,
                'recipients': recipients,
                'subject': row.get('subject', 'No Subject'),
                'department': row.get('department', 'Unknown'),
                'business_unit': row.get('bunit', 'Unknown'),
                'whitelist_reason': whitelist_reason,
                'attachments': row.get('attachments', ''),
                'word_list_match': row.get('word_list_match', '')
            })
    
    # Display whitelist overview
    st.markdown("""
    **Whitelist Overview**
    
    This dashboard shows all email communications that match your whitelist criteria. These emails are excluded 
    from security analysis on other dashboards as they represent trusted business communications.
    """)
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Emails", len(original_df))
    
    with col2:
        st.metric("Whitelisted Emails", len(whitelisted_emails))
    
    with col3:
        whitelist_percentage = (len(whitelisted_emails) / len(original_df) * 100) if len(original_df) > 0 else 0
        st.metric("Whitelist Percentage", f"{whitelist_percentage:.1f}%")
    
    with col4:
        non_whitelisted = len(original_df) - len(whitelisted_emails)
        st.metric("Non-Whitelisted Emails", non_whitelisted)
    
    if whitelisted_emails:
        # Convert to DataFrame for better display
        whitelisted_df = pd.DataFrame(whitelisted_emails)
        
        # Whitelist analysis tabs
        tab1, tab2, tab3, tab4 = st.tabs(["📋 Whitelisted Emails", "📊 Whitelist Analysis", "🏢 Domain Breakdown", "⚙️ Whitelist Management"])
        
        with tab1:
            st.subheader("Whitelisted Email Communications")
            
            # Display whitelisted emails
            display_cols = ['time', 'sender', 'recipients', 'subject', 'department', 'business_unit', 'whitelist_reason']
            
            # Format for display
            display_df = whitelisted_df[display_cols].copy()
            display_df['time'] = pd.to_datetime(display_df['time']).dt.strftime('%Y-%m-%d %H:%M')
            display_df['subject'] = display_df['subject'].str[:50] + '...'
            
            st.dataframe(display_df, use_container_width=True, height=400)
            
            # Export functionality
            if st.button("📥 Export Whitelisted Emails"):
                csv_data = whitelisted_df.to_csv(index=False)
                st.download_button(
                    label="Download Whitelisted Emails CSV",
                    data=csv_data,
                    file_name=f"whitelisted_emails_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        
        with tab2:
            st.subheader("Whitelist Pattern Analysis")
            
            # Analyze whitelist reasons
            reason_counts = whitelisted_df['whitelist_reason'].value_counts()
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Whitelist Reasons Distribution:**")
                for reason, count in reason_counts.items():
                    percentage = (count / len(whitelisted_emails) * 100)
                    st.write(f"• {reason}: **{count}** emails ({percentage:.1f}%)")
            
            with col2:
                # Department breakdown
                dept_counts = whitelisted_df['department'].value_counts()
                st.write("**Top Departments (Whitelisted):**")
                for dept, count in dept_counts.head(5).items():
                    percentage = (count / len(whitelisted_emails) * 100)
                    st.write(f"• {dept}: **{count}** emails ({percentage:.1f}%)")
            
            # Time-based analysis
            st.subheader("📅 Whitelist Activity Over Time")
            
            if 'time' in whitelisted_df.columns:
                whitelisted_df['date'] = pd.to_datetime(whitelisted_df['time']).dt.date
                daily_whitelist = whitelisted_df.groupby('date').size()
                
                import plotly.express as px
                fig = px.line(
                    x=daily_whitelist.index,
                    y=daily_whitelist.values,
                    title="Daily Whitelisted Email Volume",
                    labels={'x': 'Date', 'y': 'Email Count'}
                )
                st.plotly_chart(fig, use_container_width=True)
        
        with tab3:
            st.subheader("Whitelisted Domain Breakdown")
            
            # Extract domains from whitelist reasons
            sender_domains = []
            recipient_domains = []
            
            for reason in whitelisted_df['whitelist_reason']:
                if 'Sender domain' in reason:
                    domain = reason.split("'")[1]
                    sender_domains.append(domain)
                elif 'Recipient domain' in reason:
                    domain = reason.split("'")[1]
                    recipient_domains.append(domain)
            
            col1, col2 = st.columns(2)
            
            with col1:
                if sender_domains:
                    sender_domain_counts = pd.Series(sender_domains).value_counts()
                    st.write("**Whitelisted Sender Domains:**")
                    for domain, count in sender_domain_counts.head(10).items():
                        st.write(f"• {domain}: **{count}** emails")
                else:
                    st.info("No whitelisted sender domains found")
            
            with col2:
                if recipient_domains:
                    recipient_domain_counts = pd.Series(recipient_domains).value_counts()
                    st.write("**Whitelisted Recipient Domains:**")
                    for domain, count in recipient_domain_counts.head(10).items():
                        st.write(f"• {domain}: **{count}** emails")
                else:
                    st.info("No whitelisted recipient domains found")
        
        with tab4:
            st.subheader("Whitelist Management & Review")
            
            # Current whitelist display
            st.write("**Current Whitelist Entries:**")
            st.dataframe(st.session_state.whitelist_data, use_container_width=True)
            
            # Domain removal recommendations
            st.subheader("🔍 Whitelist Review Recommendations")
            
            # Analyze potential domains to remove
            recommendations = []
            
            # Check for domains with no recent activity
            if len(whitelisted_emails) > 0:
                recent_threshold = pd.Timestamp.now() - pd.Timedelta(days=30)
                whitelisted_df['time_parsed'] = pd.to_datetime(whitelisted_df['time'])
                recent_whitelist = whitelisted_df[whitelisted_df['time_parsed'] > recent_threshold]
                
                if len(recent_whitelist) < len(whitelisted_emails):
                    inactive_count = len(whitelisted_emails) - len(recent_whitelist)
                    recommendations.append({
                        'type': 'Inactive Domains',
                        'description': f'{inactive_count} whitelisted emails are older than 30 days',
                        'action': 'Review domains with no recent activity for potential removal',
                        'priority': 'Medium'
                    })
            
            # Check for domains with sensitive content
            sensitive_whitelist = whitelisted_df[
                (whitelisted_df['word_list_match'].notna()) & 
                (whitelisted_df['word_list_match'] != '')
            ]
            
            if len(sensitive_whitelist) > 0:
                recommendations.append({
                    'type': 'Sensitive Content',
                    'description': f'{len(sensitive_whitelist)} whitelisted emails contain sensitive keywords',
                    'action': 'Review if these domains should remain whitelisted',
                    'priority': 'High'
                })
            
            # Check for domains with attachments
            attachment_whitelist = whitelisted_df[
                (whitelisted_df['attachments'].notna()) & 
                (whitelisted_df['attachments'] != '')
            ]
            
            if len(attachment_whitelist) > 0:
                recommendations.append({
                    'type': 'Attachment Activity',
                    'description': f'{len(attachment_whitelist)} whitelisted emails contain attachments',
                    'action': 'Verify attachment activity is appropriate for whitelisted domains',
                    'priority': 'Medium'
                })
            
            if recommendations:
                st.write("**Review Recommendations:**")
                for rec in recommendations:
                    priority_color = "🔴" if rec['priority'] == 'High' else "🟡" if rec['priority'] == 'Medium' else "🟢"
                    
                    with st.expander(f"{priority_color} {rec['type']} - {rec['priority']} Priority"):
                        st.write(f"**Description:** {rec['description']}")
                        st.write(f"**Recommended Action:** {rec['action']}")
            else:
                st.success("✅ No immediate whitelist review actions required.")
            
            # Whitelist modification tools
            st.subheader("🛠️ Whitelist Modification Tools")
            
            st.info("""
            **To modify the whitelist:**
            1. Download the current whitelist using the button below
            2. Edit the CSV file to add/remove entries
            3. Re-upload the modified whitelist in the Data Upload page
            """)
            
            if st.button("📥 Download Current Whitelist"):
                csv_data = st.session_state.whitelist_data.to_csv(index=False)
                st.download_button(
                    label="Download Whitelist CSV",
                    data=csv_data,
                    file_name=f"whitelist_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
    else:
        st.info("✅ No emails match the current whitelist criteria.")
        
        # Show current whitelist
        st.subheader("Current Whitelist Configuration")
        st.dataframe(st.session_state.whitelist_data, use_container_width=True)

def app_workflow_overview_page():
    st.header("🔄 ExfilEye Application Workflow")
    
    st.markdown("""
    **ExfilEye** is an enterprise email security monitoring platform that detects data exfiltration 
    and insider threats through advanced analytics and behavioral analysis.
    """)
    
    # High-Level Workflow
    st.subheader("📋 High-Level Workflow (8 Stages)")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **🔵 Data Processing (Stages 1-4)**
        
        1. **📥 Data Ingestion**
           - Upload CSV email data + optional BAU whitelist
           - Validate required fields and data integrity
        
        2. **🧹 Data Processing** 
           - Parse emails, normalize timestamps, extract domains
           - Calculate behavioral metrics (after-hours, volume patterns)
        
        3. **🏢 Domain Classification**
           - Categorize domains (Internal/Business/Free/Government)
           - Industry classification and risk assessment
        
        4. **🎯 Content Analysis**
           - Detect IP keywords and sensitive content
           - Analyze attachments and file types
        """)
    
    with col2:
        st.markdown("""
        **🔴 Security Analysis (Stages 5-8)**
        
        5. **🧠 Risk Scoring**
           - Multi-factor weighted scoring (Leaver: 70pts, IP Keywords: 25pts, Free Domains: 20pts)
           - Classify as Critical/High/Medium/Low risk
        
        6. **🔬 Anomaly Detection**
           - ML-based behavioral pattern analysis
           - Statistical outlier identification
        
        7. **📊 Security Dashboard**
           - Real-time threat visualization
           - Risk-categorized email views with security coverage analysis
        
        8. **📧 Incident Response**
           - Automated alert generation
           - Follow-up action recommendations
        """)
    
    # Key Security Features
    st.subheader("🛡️ Key Security Features")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        **Critical Risk Detection**
        - Leaver + Attachments + Keywords + Free Domains
        - Immediate investigation required
        - Automated high-priority alerts
        """)
    
    with col2:
        st.markdown("""
        **Security Tool Integration**
        - Tessian/Mimecast coverage analysis
        - Security gap identification
        - Protection status monitoring
        """)
    
    with col3:
        st.markdown("""
        **Business Intelligence**
        - Department/Business Unit analytics
        - Domain intelligence and classification
        - Word frequency and pattern analysis
        """)
    
    # Risk Assessment Matrix
    st.subheader("⚖️ Risk Assessment Matrix")
    
    risk_col1, risk_col2, risk_col3, risk_col4 = st.columns(4)
    
    with risk_col1:
        st.metric("🏃‍♂️ Leaver Activity", "70 pts", "Last working day detection")
    
    with risk_col2:
        st.metric("🎯 IP Keywords", "25 pts", "Sensitive content detection")
    
    with risk_col3:
        st.metric("📧 Free Domains", "20 pts", "External email providers")
    
    with risk_col4:
        st.metric("📎 Attachments", "15 pts", "File transfer analysis")
    
    # Dashboard Navigation
    st.subheader("🧭 Dashboard Components")
    
    st.markdown("""
    | Page | Purpose | Key Features |
    |------|---------|--------------|
    | **📁 Data Upload** | CSV ingestion & validation | File upload, whitelist management, data preview |
    | **📊 Security Dashboard** | Real-time threat monitoring | Critical/High/Medium/Low risk views, KPI cards |
    | **📈 Advanced Analytics** | ML analysis & patterns | Anomaly detection, word frequencies, business intelligence |
    | **📧 Email Monitoring Sources** | Security coverage analysis | Tessian/Mimecast status, protection gaps |
    | **🔍 Find the Needle** | Domain intelligence | New domain detection, business unit patterns |
    """)
    
    # Quick Start Guide
    st.subheader("🚀 Quick Start Guide")
    
    st.markdown("""
    **Step-by-Step Security Analysis:**
    
    1. **Upload Data** → Navigate to Data Upload → Upload CSV → Verify validation
    2. **Initial Assessment** → Security Dashboard → Review KPI cards → Examine risk sections  
    3. **Deep Analysis** → Advanced Analytics → Review anomalies → Analyze patterns
    4. **Domain Intelligence** → Find the Needle → Review domain classifications
    5. **Security Coverage** → Email Monitoring Sources → Assess protection gaps
    6. **Incident Response** → Generate alerts → Export reports → Coordinate response
    """)
    
    # Mission Statement
    st.info("""
    **🎯 Mission:** Detect and prevent data exfiltration attempts and insider threats before they impact 
    the organization, providing security teams with actionable intelligence and automated response 
    capabilities for comprehensive email security monitoring.
    """)

def find_the_needle_page(domain_classifier, visualizer):
    """Advanced analytics dashboard for department/business unit patterns and suspicious domain identification"""
    st.header("🔍 Find the Needle - Advanced Business Intelligence")
    
    if st.session_state.processed_data is None:
        st.warning("Please upload email data first in the Data Upload page.")
        return
    
    # Filter out whitelisted emails
    original_df = st.session_state.processed_data.copy()
    df = filter_whitelisted_emails(original_df, st.session_state.whitelist_data)
    
    if df.empty:
        st.warning("All emails are whitelisted. Business intelligence analysis not available.")
        st.info("Visit the 'Whitelist Domains Check' page to review whitelisted emails.")
        return
    
    # Add note about whitelist filtering
    st.info(f"📋 **Filtered Analysis:** Analyzing {len(df):,} non-whitelisted emails out of {len(original_df):,} total emails.")
    
    # Check for required fields
    required_fields = ['department', 'bunit']
    missing_fields = [field for field in required_fields if field not in df.columns]
    
    if missing_fields:
        st.error(f"Required fields missing from data: {', '.join(missing_fields)}")
        st.info("This dashboard requires 'department' and 'bunit' fields in your email data.")
        return
    
    st.markdown("""
    **Advanced Analytics for Business Intelligence and Policy Development**
    
    This dashboard provides deep insights into organizational email patterns across departments and business units,
    helping identify suspicious domain activities and establish new monitoring policies.
    """)
    
    # Create tabs for different analyses
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🏢 Department Analytics", 
        "🏬 Business Unit Insights", 
        "🔄 Cross-Dept Communication",
        "🚨 Suspicious Domains", 
        "📊 Policy Recommendations"
    ])
    
    with tab1:
        st.subheader("Department Email Behavior Analysis")
        
        # Department overview metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            unique_depts = df['department'].nunique()
            st.metric("Unique Departments", unique_depts)
        
        with col2:
            avg_emails_per_dept = df.groupby('department').size().mean()
            st.metric("Avg Emails/Dept", f"{avg_emails_per_dept:.1f}")
        
        with col3:
            if 'risk_level' in df.columns:
                high_risk_mask = df['risk_level'] == 'High'
                high_risk_depts = df.loc[high_risk_mask, 'department'].nunique()
            else:
                high_risk_depts = 0
            st.metric("Depts with High Risk", high_risk_depts)
        
        with col4:
            if 'sender_domain_category' in df.columns:
                external_comm_mask = df['sender_domain_category'] != 'Internal'
                external_comm_depts = df.loc[external_comm_mask, 'department'].nunique()
            else:
                external_comm_depts = 0
            st.metric("Depts with External Comm", external_comm_depts)
        
        # Department risk distribution
        st.subheader("Risk Distribution by Department")
        
        # Create a safe risk level column
        df_with_risk = df.copy()
        if 'risk_level' in df.columns:
            df_with_risk['risk_level_safe'] = df['risk_level']
        else:
            df_with_risk['risk_level_safe'] = 'Low'
        dept_risk_analysis = df_with_risk.groupby(['department', 'risk_level_safe']).size().unstack(fill_value=0)
        
        if not dept_risk_analysis.empty:
            import plotly.express as px
            import plotly.graph_objects as go
            
            # Create stacked bar chart
            fig = go.Figure()
            
            risk_colors = {'High': '#ff4444', 'Medium': '#ff8800', 'Low': '#44ff44'}
            
            for risk_level in dept_risk_analysis.columns:
                if risk_level in risk_colors:
                    fig.add_trace(go.Bar(
                        name=risk_level,
                        x=dept_risk_analysis.index,
                        y=dept_risk_analysis[risk_level],
                        marker_color=risk_colors[risk_level]
                    ))
            
            fig.update_layout(
                title="Email Risk Distribution by Department",
                xaxis_title="Department",
                yaxis_title="Number of Emails",
                barmode='stack',
                height=500
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        # Department external communication patterns
        st.subheader("External Communication Patterns")
        
        if 'sender_domain_category' in df.columns:
            external_mask = df['sender_domain_category'] != 'Internal'
            external_df = df.loc[external_mask].copy()
        else:
            external_df = pd.DataFrame()
        if not external_df.empty:
            dept_external_stats = external_df.groupby('department').agg({
                'sender': 'count',
                'recipients': lambda x: x.str.split(',').str.len().sum(),
                'attachments': lambda x: (x.notna() & (x != '')).sum()
            }).round(2)
            
            dept_external_stats.columns = ['External Emails', 'Total Recipients', 'Emails with Attachments']
            dept_external_stats = dept_external_stats.sort_values('External Emails', ascending=False)
            
            st.dataframe(dept_external_stats, use_container_width=True)
        
        # Top departments by IP keyword detection
        if 'ip_keywords_detected' in df.columns:
            st.subheader("IP Keywords by Department")
            
            ip_by_dept = df[df['ip_keywords_detected'] > 0].groupby('department').agg({
                'ip_keywords_detected': ['count', 'sum', 'mean']
            }).round(2)
            
            ip_by_dept.columns = ['Emails with IP Keywords', 'Total IP Keywords', 'Avg IP Keywords/Email']
            ip_by_dept = ip_by_dept.sort_values('Total IP Keywords', ascending=False)
            
            st.dataframe(ip_by_dept, use_container_width=True)
    
    with tab2:
        st.subheader("Business Unit Intelligence Dashboard")
        
        # Business unit overview metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            unique_bunits = df['bunit'].nunique()
            st.metric("Unique Business Units", unique_bunits)
        
        with col2:
            avg_emails_per_bunit = df.groupby('bunit').size().mean()
            st.metric("Avg Emails/BUnit", f"{avg_emails_per_bunit:.1f}")
        
        with col3:
            if 'risk_level' in df.columns:
                high_risk_mask_bu = df['risk_level'] == 'High'
                high_risk_bunits = df.loc[high_risk_mask_bu, 'bunit'].nunique()
            else:
                high_risk_bunits = 0
            st.metric("BUnits with High Risk", high_risk_bunits)
        
        with col4:
            if 'anomaly_score' in df.columns:
                anomaly_mask = df['anomaly_score'] > 0
                anomalous_bunits = df.loc[anomaly_mask, 'bunit'].nunique()
                st.metric("BUnits with Anomalies", anomalous_bunits)
            else:
                st.metric("BUnits with Anomalies", 0)
        
        # Business unit communication matrix
        st.subheader("Cross-Business Unit Communication Analysis")
        
        # Create communication matrix between business units
        bunit_comm_data = []
        for _, row in df.iterrows():
            sender_bunit = row['bunit']
            if pd.notna(row.get('recipients', '')):
                # This is simplified - in real implementation, you'd map recipient emails to business units
                bunit_comm_data.append({
                    'Source BUnit': sender_bunit,
                    'Email Count': 1,
                    'Risk Level': row.get('risk_level', 'Low'),
                    'Has Attachments': pd.notna(row.get('attachments', '')) and row.get('attachments', '') != ''
                })
        
        if bunit_comm_data:
            bunit_df = pd.DataFrame(bunit_comm_data)
            bunit_summary = bunit_df.groupby(['Source BUnit', 'Risk Level']).size().unstack(fill_value=0)
            
            if not bunit_summary.empty:
                st.dataframe(bunit_summary, use_container_width=True)
        
        # Business unit anomaly analysis
        if 'anomaly_score' in df.columns:
            st.subheader("Business Unit Anomaly Patterns")
            
            bunit_anomalies = df[df['anomaly_score'] > 0].groupby('bunit').agg({
                'anomaly_score': ['count', 'mean', 'max'],
                'sender': 'nunique'
            }).round(2)
            
            bunit_anomalies.columns = ['Anomalous Emails', 'Avg Anomaly Score', 'Max Anomaly Score', 'Unique Senders']
            bunit_anomalies = bunit_anomalies.sort_values('Avg Anomaly Score', ascending=False)
            
            st.dataframe(bunit_anomalies, use_container_width=True)
    
    with tab3:
        st.subheader("Cross-Departmental Communication Pattern Monitoring")
        
        # Overview metrics for cross-departmental communication
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total_depts = df['department'].nunique()
            st.metric("Total Departments", total_depts)
        
        with col2:
            # Estimate cross-departmental emails by looking at sender patterns
            cross_dept_estimate = df.groupby('department')['sender'].nunique().sum()
            st.metric("Est. Cross-Dept Emails", cross_dept_estimate)
        
        with col3:
            if 'risk_level' in df.columns:
                high_risk_cross_dept = 0
                for dept in df['department'].unique():
                    dept_data = df[df['department'] == dept]
                    high_risk_mask = dept_data.get('risk_level', pd.Series(['Low'] * len(dept_data))) == 'High'
                    high_risk_cross_dept += high_risk_mask.sum()
                st.metric("High Risk Cross-Dept", high_risk_cross_dept)
            else:
                st.metric("High Risk Cross-Dept", "N/A")
        
        with col4:
            external_domains_by_dept = df.groupby('department')['sender_domain'].nunique().sum() if 'sender_domain' in df.columns else 0
            st.metric("External Domains Used", external_domains_by_dept)
        
        # Enhanced Department Communication Analysis
        st.subheader("Department Communication Flow Analysis")
        
        # Volume of Communication Between Departments
        st.write("### 📊 Volume of Communication Between Departments")
        
        # Create department-to-department communication matrix
        # For this analysis, we'll use sender department and attempt to infer recipient departments
        dept_comm_matrix = {}
        dept_volume_data = []
        
        for sender_dept in df['department'].unique():
            sender_data = df[df['department'] == sender_dept]
            
            # Calculate volumes for this department
            total_emails = len(sender_data)
            external_emails = 0
            if 'sender_domain_category' in df.columns:
                sender_domain_cat = sender_data.get('sender_domain_category', pd.Series([''] * len(sender_data)))
                external_emails = (sender_domain_cat != 'Internal').sum()
            
            internal_emails = total_emails - external_emails
            
            dept_volume_data.append({
                'Sender Department': sender_dept,
                'Total Emails Sent': total_emails,
                'Internal Communications': internal_emails,
                'External Communications': external_emails,
                'External Ratio': f"{(external_emails/total_emails*100):.1f}%" if total_emails > 0 else "0%"
            })
        
        dept_volume_df = pd.DataFrame(dept_volume_data)
        st.dataframe(dept_volume_df, use_container_width=True)
        
        # Communication Direction Analysis
        st.write("### 🔄 Communication Direction Analysis")
        
        direction_analysis = []
        for dept in df['department'].unique():
            dept_data = df[df['department'] == dept]
            
            # Analyze initiation patterns (emails sent by department)
            emails_sent = len(dept_data)
            unique_senders = dept_data['sender'].nunique()
            
            # Estimate emails received (this would need recipient department mapping in real scenario)
            # For now, we'll use a simplified approach
            avg_recipients_per_email = dept_data['recipients'].str.split(',').str.len().mean() if dept_data['recipients'].notna().any() else 0
            
            direction_analysis.append({
                'Department': dept,
                'Emails Initiated': emails_sent,
                'Unique Senders': unique_senders,
                'Avg Recipients/Email': f"{avg_recipients_per_email:.1f}",
                'Initiation Rate': 'High' if emails_sent > df.groupby('department').size().mean() else 'Normal'
            })
        
        direction_df = pd.DataFrame(direction_analysis)
        st.dataframe(direction_df, use_container_width=True)
        
        # Content Patterns Analysis
        st.write("### 📋 Content Patterns Analysis")
        
        content_patterns = []
        for dept in df['department'].unique():
            dept_data = df[df['department'] == dept]
            
            # Analyze content patterns
            has_attachments = (dept_data['attachments'].notna() & (dept_data['attachments'] != '')).sum()
            
            # IP keywords analysis
            ip_keywords = 0
            if 'ip_keywords_detected' in df.columns:
                ip_keywords = (dept_data['ip_keywords_detected'] > 0).sum()
            
            # Risk level analysis
            high_risk_emails = 0
            if 'risk_level' in df.columns:
                high_risk_mask = dept_data.get('risk_level', pd.Series(['Low'] * len(dept_data))) == 'High'
                high_risk_emails = high_risk_mask.sum()
            
            # Subject analysis (if available)
            avg_subject_length = 0
            if 'subject' in dept_data.columns:
                avg_subject_length = dept_data['subject'].str.len().mean()
            
            content_patterns.append({
                'Department': dept,
                'Emails with Attachments': has_attachments,
                'Attachment Rate': f"{(has_attachments/len(dept_data)*100):.1f}%" if len(dept_data) > 0 else "0%",
                'IP Keywords Detected': ip_keywords,
                'High Risk Emails': high_risk_emails,
                'Avg Subject Length': f"{avg_subject_length:.0f}" if avg_subject_length > 0 else "N/A"
            })
        
        content_df = pd.DataFrame(content_patterns)
        st.dataframe(content_df, use_container_width=True)
        
        # Visualize content patterns
        if len(content_df) > 0:
            import plotly.express as px
            import plotly.graph_objects as go
            
            # Create attachment rate visualization
            fig_attachments = px.bar(
                content_df, 
                x='Department', 
                y='Emails with Attachments',
                title="Emails with Attachments by Department",
                color='Emails with Attachments',
                color_continuous_scale='Blues'
            )
            fig_attachments.update_layout(height=400)
            st.plotly_chart(fig_attachments, use_container_width=True)
        
        # Anomaly Detection
        st.write("### 🚨 Communication Anomalies Detection")
        
        anomalies_detected = []
        
        # Calculate baseline statistics
        overall_avg_emails = df.groupby('department').size().mean()
        overall_attachment_rate = (df['attachments'].notna() & (df['attachments'] != '')).sum() / len(df) if len(df) > 0 else 0
        
        for dept in df['department'].unique():
            dept_data = df[df['department'] == dept]
            dept_email_count = len(dept_data)
            
            # Volume anomalies
            if dept_email_count > (overall_avg_emails * 2):
                anomalies_detected.append({
                    'Department': dept,
                    'Anomaly Type': 'High Volume',
                    'Details': f'{dept_email_count} emails (>{overall_avg_emails*2:.0f} expected)',
                    'Severity': 'Medium',
                    'Risk Factor': 'Volume Spike'
                })
            elif dept_email_count < (overall_avg_emails * 0.3):
                anomalies_detected.append({
                    'Department': dept,
                    'Anomaly Type': 'Low Volume',
                    'Details': f'{dept_email_count} emails (<{overall_avg_emails*0.3:.0f} expected)',
                    'Severity': 'Low',
                    'Risk Factor': 'Unusual Quietness'
                })
            
            # Attachment anomalies
            dept_attachment_rate = (dept_data['attachments'].notna() & (dept_data['attachments'] != '')).sum() / len(dept_data) if len(dept_data) > 0 else 0
            if dept_attachment_rate > (overall_attachment_rate * 3):
                anomalies_detected.append({
                    'Department': dept,
                    'Anomaly Type': 'High Attachment Usage',
                    'Details': f'{dept_attachment_rate:.1%} attachment rate (>{overall_attachment_rate*3:.1%} expected)',
                    'Severity': 'Medium',
                    'Risk Factor': 'Data Transfer Risk'
                })
            
            # External communication anomalies
            if 'sender_domain_category' in df.columns:
                sender_domain_cat = dept_data.get('sender_domain_category', pd.Series([''] * len(dept_data)))
                external_rate = (sender_domain_cat != 'Internal').sum() / len(dept_data) if len(dept_data) > 0 else 0
                if external_rate > 0.8:
                    anomalies_detected.append({
                        'Department': dept,
                        'Anomaly Type': 'High External Communication',
                        'Details': f'{external_rate:.1%} external emails',
                        'Severity': 'High',
                        'Risk Factor': 'External Data Flow'
                    })
            
            # Time-based anomalies (if time data available)
            if 'time' in df.columns:
                try:
                    dept_data_time = dept_data.copy()
                    dept_data_time['time_parsed'] = pd.to_datetime(dept_data_time['time'])
                    dept_data_time['hour'] = dept_data_time['time_parsed'].dt.hour
                    
                    # Check for unusual timing patterns
                    night_emails = ((dept_data_time['hour'] >= 22) | (dept_data_time['hour'] <= 5)).sum()
                    night_rate = night_emails / len(dept_data_time) if len(dept_data_time) > 0 else 0
                    
                    if night_rate > 0.3:
                        anomalies_detected.append({
                            'Department': dept,
                            'Anomaly Type': 'After-Hours Activity',
                            'Details': f'{night_rate:.1%} emails sent outside business hours',
                            'Severity': 'Medium',
                            'Risk Factor': 'Unusual Timing'
                        })
                except:
                    pass  # Skip time analysis if parsing fails
        
        if anomalies_detected:
            st.write("**Detected Anomalies:**")
            anomalies_df = pd.DataFrame(anomalies_detected)
            
            # Color code by severity with proper text contrast
            def highlight_severity(row):
                if row['Severity'] == 'High':
                    return ['background-color: #ffebee; color: #c62828; font-weight: bold'] * len(row)
                elif row['Severity'] == 'Medium':
                    return ['background-color: #fff3e0; color: #ef6c00; font-weight: bold'] * len(row)
                else:
                    return ['background-color: #e8f5e8; color: #2e7d32; font-weight: bold'] * len(row)
            
            st.dataframe(anomalies_df.style.apply(highlight_severity, axis=1), use_container_width=True)
            
            # Anomaly summary metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                high_severity = (anomalies_df['Severity'] == 'High').sum()
                st.metric("High Severity Anomalies", high_severity)
            with col2:
                medium_severity = (anomalies_df['Severity'] == 'Medium').sum()
                st.metric("Medium Severity Anomalies", medium_severity)
            with col3:
                affected_depts = anomalies_df['Department'].nunique()
                st.metric("Departments Affected", affected_depts)
        else:
            st.success("No significant communication anomalies detected across departments.")
        
        # Communication Flow Visualization
        st.write("### 🌐 Department Communication Flow Visualization")
        
        if len(df) > 0:
            # Create a network-style visualization of department communications
            dept_sizes = df['department'].value_counts()
            
            if len(dept_sizes) > 1:
                fig_flow = go.Figure()
                
                # Create a circular layout for departments
                import math
                n_depts = len(dept_sizes)
                angles = [2 * math.pi * i / n_depts for i in range(n_depts)]
                
                for i, (dept, size) in enumerate(dept_sizes.items()):
                    x = math.cos(angles[i])
                    y = math.sin(angles[i])
                    
                    fig_flow.add_trace(go.Scatter(
                        x=[x],
                        y=[y],
                        mode='markers+text',
                        marker=dict(size=min(size/2, 100), opacity=0.7),
                        text=[f"{dept}<br>{size} emails"],
                        textposition="middle center",
                        name=dept,
                        showlegend=False
                    ))
                
                fig_flow.update_layout(
                    title="Department Communication Network",
                    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    height=500,
                    showlegend=False
                )
                
                st.plotly_chart(fig_flow, use_container_width=True)
        
        
        
        # Time-based cross-departmental analysis
        st.subheader("Temporal Cross-Departmental Patterns")
        
        if 'time' in df.columns:
            # Convert time to datetime if it's not already
            df_time = df.copy()
            try:
                df_time['time_parsed'] = pd.to_datetime(df_time['time'])
                df_time['hour'] = df_time['time_parsed'].dt.hour
                df_time['day_of_week'] = df_time['time_parsed'].dt.day_name()
                
                # Department activity by hour
                dept_hourly = df_time.groupby(['department', 'hour']).size().unstack(fill_value=0)
                
                if not dept_hourly.empty:
                    st.write("**Department Email Activity by Hour of Day:**")
                    
                    import plotly.express as px
                    import plotly.graph_objects as go
                    
                    # Create heatmap
                    fig = go.Figure(data=go.Heatmap(
                        z=dept_hourly.values,
                        x=dept_hourly.columns,
                        y=dept_hourly.index,
                        colorscale='Blues',
                        showscale=True
                    ))
                    
                    fig.update_layout(
                        title="Department Email Activity Heatmap (by Hour)",
                        xaxis_title="Hour of Day",
                        yaxis_title="Department",
                        height=400
                    )
                    
                    st.plotly_chart(fig, use_container_width=True)
                
            except Exception as e:
                st.info("Time analysis not available - time format may need adjustment")
        
        # Unusual cross-departmental patterns
        st.subheader("Unusual Cross-Departmental Communication Flags")
        
        unusual_patterns = []
        
        # Flag departments with high external communication
        if 'sender_domain_category' in df.columns:
            for dept in df['department'].unique():
                dept_data = df[df['department'] == dept]
                sender_domain_cat = dept_data.get('sender_domain_category', pd.Series([''] * len(dept_data)))
                external_ratio = (sender_domain_cat != 'Internal').sum() / len(dept_data) if len(dept_data) > 0 else 0
                
                if external_ratio > 0.7:  # More than 70% external communication
                    unusual_patterns.append({
                        'Department': dept,
                        'Pattern': 'High External Communication',
                        'Details': f'{external_ratio:.1%} of emails are external',
                        'Risk Level': 'Medium' if external_ratio > 0.8 else 'Low'
                    })
        
        # Flag departments with high IP keyword usage
        if 'ip_keywords_detected' in df.columns:
            for dept in df['department'].unique():
                dept_data = df[df['department'] == dept]
                ip_emails = (dept_data['ip_keywords_detected'] > 0).sum()
                total_emails = len(dept_data)
                ip_ratio = ip_emails / total_emails if total_emails > 0 else 0
                
                if ip_ratio > 0.3:  # More than 30% have IP keywords
                    unusual_patterns.append({
                        'Department': dept,
                        'Pattern': 'High IP Keyword Usage',
                        'Details': f'{ip_ratio:.1%} of emails contain IP keywords',
                        'Risk Level': 'High'
                    })
        
        if unusual_patterns:
            st.write("**Flagged Unusual Patterns:**")
            unusual_df = pd.DataFrame(unusual_patterns)
            
            # Color code by risk level
            def highlight_risk(row):
                if row['Risk Level'] == 'High':
                    return ['background-color: #ffebee'] * len(row)
                elif row['Risk Level'] == 'Medium':
                    return ['background-color: #fff3e0'] * len(row)
                else:
                    return ['background-color: #e8f5e8'] * len(row)
            
            st.dataframe(unusual_df.style.apply(highlight_risk, axis=1), use_container_width=True)
        else:
            st.success("No unusual cross-departmental patterns detected.")
        
        # Cross-departmental collaboration insights
        st.subheader("Cross-Departmental Collaboration Insights")
        
        collaboration_insights = []
        
        # Analyze department diversity in email communications
        unique_depts = df['department'].nunique()
        if unique_depts > 1:
            collaboration_insights.append(
                f"Organization has {unique_depts} departments actively sending emails"
            )
            
            # Find most active departments
            most_active_dept = df['department'].value_counts().index[0]
            most_active_count = df['department'].value_counts().iloc[0]
            collaboration_insights.append(
                f"Most active department: {most_active_dept} ({most_active_count} emails)"
            )
            
            # Find departments with most external communication
            if 'sender_domain_category' in df.columns:
                external_by_dept = df.groupby('department').apply(
                    lambda x: (x.get('sender_domain_category', pd.Series([''] * len(x))) != 'Internal').sum()
                ).sort_values(ascending=False)
                
                if not external_by_dept.empty:
                    top_external_dept = external_by_dept.index[0]
                    top_external_count = external_by_dept.iloc[0]
                    collaboration_insights.append(
                        f"Department with most external communication: {top_external_dept} ({top_external_count} external emails)"
                    )
        
        for insight in collaboration_insights:
            st.info(insight)
    
    with tab4:
        st.subheader("🔍 Suspicious Domain Intelligence & New Domain Detection")
        
        # Enhanced domain analysis using the domain classifier
        domain_analysis = domain_classifier.extract_and_classify_all_domains(df)
        
        # New Domain Communications Flagging
        st.subheader("🚨 New Domain Communications - Flag for Review")
        
        st.info("""
        **Domain Intelligence Alert System**
        
        This analysis identifies communications to domains that haven't been contacted before by specific users or departments, 
        which could indicate new business relationships, potential security risks, or policy violations requiring review.
        """)
        
        # Analyze new domain communications by sender
        new_domain_communications = []
        
        if 'sender' in df.columns and 'time' in df.columns:
            # Sort by time to identify chronological communication patterns
            df_sorted = df.sort_values('time').copy()
            
            # Track domains contacted by each sender over time
            sender_domain_history = {}
            
            for idx, row in df_sorted.iterrows():
                sender = row.get('sender', '')
                recipient_domains = row.get('recipients', '')
                timestamp = row.get('time', '')
                department = row.get('department', 'Unknown')
                bunit = row.get('bunit', 'Unknown')
                subject = row.get('subject', 'No Subject')
                
                if not sender or not recipient_domains:
                    continue
                
                # Extract recipient domains from the recipients field
                import re
                email_pattern = r'\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b'
                domains = list(set(re.findall(email_pattern, str(recipient_domains))))
                
                # Initialize sender history if not exists
                if sender not in sender_domain_history:
                    sender_domain_history[sender] = set()
                
                # Check each domain
                for domain in domains:
                    if domain and domain.lower().strip():
                        domain_clean = domain.lower().strip()
                        
                        # Check if this is a new domain for this sender
                        if domain_clean not in sender_domain_history[sender]:
                            # Flag as new domain communication
                            new_domain_communications.append({
                                'timestamp': timestamp,
                                'sender': sender,
                                'department': department,
                                'business_unit': bunit,
                                'new_domain': domain_clean,
                                'subject': subject[:50] + ('...' if len(subject) > 50 else ''),
                                'domain_category': domain_classifier._get_detailed_category(domain_clean),
                                'risk_level': 'High' if domain_clean in domain_classifier.all_free_domains else 'Medium',
                                'requires_review': True
                            })
                        
                        # Add domain to sender's history
                        sender_domain_history[sender].add(domain_clean)
        
        # Display new domain communications
        if new_domain_communications:
            st.subheader(f"⚠️ {len(new_domain_communications)} New Domain Communications Flagged for Review")
            
            # Create DataFrame for better display
            new_domains_df = pd.DataFrame(new_domain_communications)
            
            # Summary metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                unique_senders = new_domains_df['sender'].nunique()
                st.metric("Unique Senders", unique_senders)
            
            with col2:
                unique_domains = new_domains_df['new_domain'].nunique()
                st.metric("New Domains Found", unique_domains)
            
            with col3:
                high_risk_count = len(new_domains_df[new_domains_df['risk_level'] == 'High'])
                st.metric("High Risk (Free Email)", high_risk_count)
            
            with col4:
                affected_depts = new_domains_df['department'].nunique()
                st.metric("Departments Affected", affected_depts)
            
            # Risk-based filtering
            st.subheader("🎯 Filter New Domain Communications")
            
            filter_col1, filter_col2, filter_col3 = st.columns(3)
            
            with filter_col1:
                risk_filter = st.selectbox(
                    "Filter by Risk Level:",
                    options=['All', 'High', 'Medium'],
                    index=0
                )
            
            with filter_col2:
                dept_filter = st.selectbox(
                    "Filter by Department:",
                    options=['All'] + sorted(new_domains_df['department'].unique().tolist()),
                    index=0
                )
            
            with filter_col3:
                category_filter = st.selectbox(
                    "Filter by Domain Category:",
                    options=['All'] + sorted(new_domains_df['domain_category'].unique().tolist()),
                    index=0
                )
            
            # Apply filters
            filtered_df = new_domains_df.copy()
            
            if risk_filter != 'All':
                filtered_df = filtered_df[filtered_df['risk_level'] == risk_filter]
            
            if dept_filter != 'All':
                filtered_df = filtered_df[filtered_df['department'] == dept_filter]
            
            if category_filter != 'All':
                filtered_df = filtered_df[filtered_df['domain_category'] == category_filter]
            
            # Display filtered results
            st.write(f"**Showing {len(filtered_df)} flagged communications:**")
            
            # Style the dataframe based on risk level
            def highlight_risk_level(row):
                if 'Risk Level' in row and row['Risk Level'] == 'High':
                    return ['background-color: #ffebee; color: #c62828; font-weight: bold'] * len(row)
                elif 'Risk Level' in row and row['Risk Level'] == 'Medium':
                    return ['background-color: #fff3e0; color: #ef6c00'] * len(row)
                else:
                    return [''] * len(row)
            
            if not filtered_df.empty:
                # Reorder columns for better display - check if columns exist first
                available_columns = ['timestamp', 'sender', 'department', 'business_unit', 'new_domain', 'domain_category', 'subject']
                if 'risk_level' in filtered_df.columns:
                    available_columns.insert(-1, 'risk_level')
                
                # Only use columns that actually exist in the dataframe
                display_columns = [col for col in available_columns if col in filtered_df.columns]
                filtered_display = filtered_df[display_columns].copy()
                
                # Format timestamp
                if 'timestamp' in filtered_display.columns:
                    filtered_display['timestamp'] = pd.to_datetime(filtered_display['timestamp']).dt.strftime('%Y-%m-%d %H:%M')
                
                # Rename columns for better readability
                column_mapping = {
                    'timestamp': 'Time',
                    'sender': 'Sender',
                    'department': 'Department',
                    'business_unit': 'Business Unit',
                    'new_domain': 'New Domain',
                    'domain_category': 'Category',
                    'risk_level': 'Risk Level',
                    'subject': 'Subject'
                }
                
                # Only rename columns that exist
                filtered_display.columns = [column_mapping.get(col, col) for col in filtered_display.columns]
                
                styled_df = filtered_display.style.apply(highlight_risk_level, axis=1)
                st.dataframe(styled_df, use_container_width=True, height=400)
                
                # Detailed analysis of flagged domains
                st.subheader("📊 Detailed Analysis")
                
                # Top new domains by frequency
                domain_freq = filtered_df['new_domain'].value_counts()
                if not domain_freq.empty:
                    st.write("**Most Frequently Contacted New Domains:**")
                    freq_df = pd.DataFrame({
                        'Domain': domain_freq.index[:10],
                        'Contact Count': domain_freq.values[:10],
                        'Category': [domain_classifier._get_detailed_category(d) for d in domain_freq.index[:10]]
                    })
                    st.dataframe(freq_df, use_container_width=True)
                
                # Department breakdown
                dept_breakdown = filtered_df.groupby(['department', 'risk_level']).size().unstack(fill_value=0)
                if not dept_breakdown.empty:
                    st.write("**New Domain Communications by Department:**")
                    st.dataframe(dept_breakdown, use_container_width=True)
                
                # Export functionality
                st.subheader("📤 Export Flagged Communications")
                
                if st.button("Generate Review Report"):
                    csv_data = filtered_df.to_csv(index=False)
                    st.download_button(
                        label="Download New Domain Communications Report",
                        data=csv_data,
                        file_name=f"new_domain_communications_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
            else:
                st.info("No new domain communications match the selected filters.")
        else:
            st.success("✅ No new domain communications detected.")
            st.info("All communications are to previously contacted domains, indicating established business relationships.")
        
        # Additional Domain Intelligence
        st.subheader("🧠 Additional Domain Intelligence")
        
        # Suspicious domain indicators
        st.write("### 🚩 Suspicious Domain Patterns")
        
        suspicious_patterns = []
        
        # Analyze sender domains
        if 'sender_domain' in df.columns:
            # Create aggregation dictionary based on available columns
            agg_dict = {
                'sender': 'count'
            }
            
            # Add risk level analysis if column exists
            if 'risk_level' in df.columns:
                agg_dict['risk_level'] = lambda x: (x == 'High').sum()
            
            # Add IP keywords analysis if column exists
            if 'ip_keywords_detected' in df.columns:
                agg_dict['ip_keywords_detected'] = 'sum'
            
            sender_domain_stats = df.groupby(['sender_domain', 'department', 'bunit']).agg(agg_dict).reset_index()
            
            # Set column names based on what was aggregated
            new_columns = ['Domain', 'Department', 'Business Unit', 'Email Count']
            if 'risk_level' in df.columns:
                new_columns.append('High Risk Emails')
            if 'ip_keywords_detected' in df.columns:
                new_columns.append('IP Keywords')
            
            sender_domain_stats.columns = new_columns
            
            # Flag suspicious patterns based on available columns
            suspicious_mask = sender_domain_stats['Email Count'] > 0  # Base condition
            
            if 'High Risk Emails' in sender_domain_stats.columns:
                suspicious_mask = suspicious_mask & (sender_domain_stats['High Risk Emails'] > 0)
            
            if 'IP Keywords' in sender_domain_stats.columns:
                suspicious_mask = suspicious_mask | (sender_domain_stats['IP Keywords'] > 0)
            
            suspicious_domains = sender_domain_stats[suspicious_mask]
            
            if not suspicious_domains.empty:
                st.write("**Domains with Suspicious Activity:**")
                st.dataframe(suspicious_domains, use_container_width=True)
            else:
                st.info("No domains with suspicious activity patterns detected.")
        
        # Domain statistics summary
        st.subheader("📈 Domain Statistics Summary")
        
        domain_summary = {
            'Total Unique Sender Domains': df['sender_domain'].nunique() if 'sender_domain' in df.columns else 0,
            'Internal Domains': len([d for d in df.get('sender_domain', []) if 'Internal' in str(df.get('sender_domain_category', ''))]),
            'Free Email Domains': len([d for d in df.get('sender_domain', []) if 'Free Email' in str(df.get('sender_domain_category', ''))]),
            'Business Domains': len([d for d in df.get('sender_domain', []) if 'Business' in str(df.get('sender_domain_category', ''))])
        }
        
        col1, col2 = st.columns(2)
        
        with col1:
            for key, value in list(domain_summary.items())[:2]:
                st.metric(key, value)
        
        with col2:
            for key, value in list(domain_summary.items())[2:]:
                st.metric(key, value)
        
        # Historical new domain detection
        st.subheader("📅 Historical New Domain Activity")
        
        if 'time' in df.columns:
            # Analyze domains by time period to identify new ones
            df_sorted = df.sort_values('time')
            
            # Split data into time periods (e.g., first half vs second half)
            midpoint = len(df_sorted) // 2
            early_domains = set(df_sorted.iloc[:midpoint]['sender_domain'].dropna()) if 'sender_domain' in df.columns else set()
            late_domains = set(df_sorted.iloc[midpoint:]['sender_domain'].dropna()) if 'sender_domain' in df.columns else set()
            
            new_domains = late_domains - early_domains
            
            if new_domains:
                st.write(f"**{len(new_domains)} new sender domains detected in recent activity:**")
                new_domain_df = df[df['sender_domain'].isin(new_domains)].groupby('sender_domain').agg({
                    'sender': 'count',
                    'department': lambda x: ', '.join([str(val) for val in x.unique() if pd.notna(val)]),
                    'bunit': lambda x: ', '.join([str(val) for val in x.unique() if pd.notna(val)])
                }).reset_index()
                
                new_domain_df.columns = ['New Domain', 'Email Count', 'Departments', 'Business Units']
                st.dataframe(new_domain_df, use_container_width=True)
            else:
                st.info("No new sender domains detected in recent period.")
    
    with tab4:
        st.subheader("Policy Recommendations for Business as Usual Monitoring")
        
        # Generate recommendations based on analysis
        recommendations = []
        
        # Department-based recommendations
        if 'department' in df.columns:
            high_risk_mask_rec = df.get('risk_level', pd.Series(['Low'] * len(df))) == 'High'
            high_risk_dept_emails = df[high_risk_mask_rec]
            if not high_risk_dept_emails.empty:
                high_risk_depts = high_risk_dept_emails['department'].value_counts()
                if not high_risk_depts.empty:
                    top_risk_dept = high_risk_depts.index[0]
                    recommendations.append({
                        'Category': 'Department Monitoring',
                        'Priority': 'High',
                        'Recommendation': f'Implement enhanced monitoring for {top_risk_dept} department due to high-risk email activity',
                        'Rationale': f'{high_risk_depts.iloc[0]} high-risk emails detected'
                    })
        
        # Business unit recommendations
        if 'bunit' in df.columns and 'anomaly_score' in df.columns:
            anomalous_bunits = df[df['anomaly_score'] > 0]['bunit'].value_counts()
            if not anomalous_bunits.empty:
                top_anomaly_bunit = anomalous_bunits.index[0]
                recommendations.append({
                    'Category': 'Business Unit Policy',
                    'Priority': 'Medium',
                    'Recommendation': f'Review email policies for {top_anomaly_bunit} business unit',
                    'Rationale': f'{anomalous_bunits.iloc[0]} anomalous emails detected'
                })
        
        # Domain-based recommendations
        if 'sender_domain_category' in df.columns:
            sender_domain_cat_policy = df.get('sender_domain_category', pd.Series([''] * len(df)))
            free_email_mask = sender_domain_cat_policy == 'Free Email'
            free_email_usage = free_email_mask.sum()
            if free_email_usage > 0:
                recommendations.append({
                    'Category': 'Domain Policy',
                    'Priority': 'Medium',
                    'Recommendation': 'Consider restricting or monitoring free email domain usage for business communications',
                    'Rationale': f'{free_email_usage} emails sent from free email domains detected'
                })
        
        # IP keyword recommendations
        if 'ip_keywords_detected' in df.columns:
            ip_keyword_count = (df['ip_keywords_detected'] > 0).sum()
            if ip_keyword_count > 0:
                recommendations.append({
                    'Category': 'Content Monitoring',
                    'Priority': 'High',
                    'Recommendation': 'Implement automated flagging for emails containing IP-related keywords',
                    'Rationale': f'{ip_keyword_count} emails with IP keywords detected'
                })
        
        # Display recommendations
        if recommendations:
            st.write("**Automated Policy Recommendations:**")
            
            for i, rec in enumerate(recommendations):
                priority_color = {'High': '🔴', 'Medium': '🟡', 'Low': '🟢'}
                
                with st.expander(f"{priority_color.get(rec['Priority'], '⚪')} {rec['Category']} - {rec['Priority']} Priority"):
                    st.write(f"**Recommendation:** {rec['Recommendation']}")
                    st.write(f"**Rationale:** {rec['Rationale']}")
        else:
            st.info("No specific policy recommendations generated. Your email patterns appear to be within normal parameters.")
        
        # BAU monitoring suggestions
        st.subheader("Business as Usual (BAU) Monitoring Setup")
        
        st.markdown("""
        **Suggested ongoing monitoring policies based on your data:**
        
        1. **Department-Level Monitoring:**
           - Set baseline thresholds for each department's email volume
           - Monitor cross-departmental communication patterns
           - Flag unusual attachment types by department
        
        2. **Business Unit Intelligence:**
           - Track external domain communication by business unit
           - Monitor IP keyword usage patterns per business unit
           - Set up alerts for new external communications
        
        3. **Domain Intelligence:**
           - Maintain whitelist of approved business domains
           - Flag new domain communications for review
           - Monitor free email domain usage trends
        
        4. **Behavioral Baselines:**
           - Establish normal communication patterns per department/business unit
           - Set up anomaly detection thresholds
           - Monitor deviation from established patterns
        """)
        
        # Export recommendations
        if st.button("Export Policy Recommendations"):
            if recommendations:
                rec_df = pd.DataFrame(recommendations)
                csv = rec_df.to_csv(index=False)
                st.download_button(
                    label="Download Recommendations CSV",
                    data=csv,
                    file_name=f"policy_recommendations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )


def followup_email_center_page():
    """Dashboard for managing follow-up emails for security events"""
    st.header("📧 Follow-up Email Center")
    
    if st.session_state.processed_data is None:
        st.warning("Please upload email data first in the Data Upload page.")
        return
    
    # Initialize session state for selected events if not exists
    if 'selected_events' not in st.session_state:
        st.session_state.selected_events = []
    
    if 'generated_emails' not in st.session_state:
        st.session_state.generated_emails = []
    
    # Filter out whitelisted emails
    original_df = st.session_state.processed_data.copy()
    df = filter_whitelisted_emails(original_df, st.session_state.whitelist_data)
    
    if df.empty:
        st.warning("All emails are whitelisted. No events available for follow-up.")
        return
    
    # Create tabs for different sections
    tab1, tab2, tab3 = st.tabs(["🎯 Select Events", "📝 Generate Emails", "📋 Manage Follow-ups"])
    
    with tab1:
        st.subheader("Select Events for Follow-up")
        
        # Filter events by risk level and other criteria
        col1, col2, col3 = st.columns(3)
        
        with col1:
            risk_filter = st.multiselect(
                "Filter by Risk Level",
                options=['High', 'Medium', 'Low'],
                default=['High', 'Medium'],
                key="risk_filter"
            )
        
        with col2:
            dept_filter = st.multiselect(
                "Filter by Department",
                options=df['department'].unique() if 'department' in df.columns else [],
                key="dept_filter"
            )
        
        with col3:
            anomaly_filter = st.checkbox(
                "Show only anomalous emails",
                value=False,
                key="anomaly_filter"
            )
        
        # Apply filters
        filtered_df = df.copy()
        
        if 'risk_level' in df.columns and risk_filter:
            filtered_df = filtered_df[filtered_df['risk_level'].isin(risk_filter)]
        
        if 'department' in df.columns and dept_filter:
            filtered_df = filtered_df[filtered_df['department'].isin(dept_filter)]
        
        if anomaly_filter and 'anomaly_score' in df.columns:
            filtered_df = filtered_df[filtered_df['anomaly_score'] > 0]
        
        st.info(f"Found {len(filtered_df)} events matching your criteria")
        
        # Display events for selection
        if not filtered_df.empty:
            st.subheader("Available Events")
            
            # Create a selection table with key information
            display_columns = ['sender', 'time', 'subject', 'recipients', 'email_domain']
            if 'risk_level' in filtered_df.columns:
                display_columns.append('risk_level')
            if 'department' in filtered_df.columns:
                display_columns.append('department')
            if 'attachments' in filtered_df.columns:
                display_columns.append('attachments')
            if 'ip_keywords_detected' in filtered_df.columns:
                display_columns.append('ip_keywords_detected')
            
            # Ensure all display columns exist
            available_columns = [col for col in display_columns if col in filtered_df.columns]
            
            if available_columns:
                # Add selection checkboxes
                selection_df = filtered_df[available_columns].copy()
                selection_df.insert(0, 'Select', False)
                
                # Create editable dataframe for selection
                edited_df = st.data_editor(
                    selection_df,
                    disabled=[col for col in selection_df.columns if col != 'Select'],
                    hide_index=True,
                    use_container_width=True,
                    key="event_selector"
                )
                
                # Update selected events
                if st.button("Add Selected Events to Follow-up Queue", type="primary"):
                    selected_mask = edited_df['Select']
                    new_selections = filtered_df[selected_mask].copy()
                    
                    if not new_selections.empty:
                        # Add unique identifier for tracking
                        new_selections['selection_id'] = [f"evt_{int(datetime.now().timestamp())}_{i}" for i in range(len(new_selections))]
                        new_selections['selected_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        
                        # Add to session state
                        if not st.session_state.selected_events:
                            st.session_state.selected_events = new_selections.to_dict('records')
                        else:
                            existing_df = pd.DataFrame(st.session_state.selected_events)
                            combined_df = pd.concat([existing_df, new_selections], ignore_index=True)
                            st.session_state.selected_events = combined_df.to_dict('records')
                        
                        st.success(f"Added {len(new_selections)} events to follow-up queue")
                        st.rerun()
    
    with tab2:
        st.subheader("Generate Follow-up Emails")
        
        if not st.session_state.selected_events:
            st.info("No events selected for follow-up. Please select events in the 'Select Events' tab.")
        else:
            st.success(f"Ready to generate emails for {len(st.session_state.selected_events)} selected events")
            
            # Email template selection
            col1, col2 = st.columns(2)
            
            with col1:
                email_type = st.selectbox(
                    "Email Template Type",
                    options=['Security Inquiry', 'Policy Reminder', 'Training Notification', 'Risk Assessment'],
                    key="email_template_type"
                )
            
            with col2:
                urgency_level = st.selectbox(
                    "Urgency Level",
                    options=['Low', 'Medium', 'High', 'Critical'],
                    key="urgency_level"
                )
            
            # Custom email settings
            st.subheader("Email Customization")
            
            custom_subject = st.text_input(
                "Custom Subject Line (optional)",
                placeholder="Leave empty to use template default",
                key="custom_subject"
            )
            
            custom_message = st.text_area(
                "Additional Message (optional)",
                placeholder="Add any specific context or instructions",
                key="custom_message"
            )
            
            # Preview selected events
            if st.expander("Preview Selected Events", expanded=False):
                events_df = pd.DataFrame(st.session_state.selected_events)
                preview_columns = ['sender', 'subject', 'selected_at']
                if 'risk_level' in events_df.columns:
                    preview_columns.append('risk_level')
                
                available_preview_cols = [col for col in preview_columns if col in events_df.columns]
                st.dataframe(events_df[available_preview_cols], use_container_width=True)
            
            # Output method selection
            st.subheader("Output Method")
            output_method = st.radio(
                "Choose how to handle generated emails:",
                options=["Open in Outlook", "Export as CSV", "Send via SMTP"],
                index=0,
                help="Select your preferred method for handling the generated follow-up emails"
            )
            
            # Generate emails
            if st.button("Generate Follow-up Emails", type="primary"):
                from utils.email_generator import EmailGenerator
                
                email_generator = EmailGenerator()
                
                # Generate emails for each selected event
                generated_emails = []
                
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                for i, event in enumerate(st.session_state.selected_events):
                    status_text.text(f"Generating email {i+1} of {len(st.session_state.selected_events)}")
                    
                    # Get appropriate template
                    subject_template, body_template = email_generator.get_template(email_type)
                    
                    # Generate email
                    generated_email = email_generator.generate_email(
                        event,
                        subject_template,
                        body_template
                    )
                    
                    # Add metadata
                    generated_email.update({
                        'event_id': event.get('selection_id', f"evt_{i}"),
                        'template_type': email_type,
                        'urgency_level': urgency_level,
                        'custom_subject': custom_subject,
                        'custom_message': custom_message,
                        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'status': 'Draft'
                    })
                    
                    generated_emails.append(generated_email)
                    progress_bar.progress((i + 1) / len(st.session_state.selected_events))
                
                # Handle different output methods
                if output_method == "Open in Outlook":
                    # Prepare emails for Outlook integration
                    outlook_emails = email_generator.prepare_outlook_emails(generated_emails)
                    st.session_state.generated_emails.extend(outlook_emails)
                    
                    status_text.text("Email generation completed!")
                    st.success(f"Successfully generated {len(generated_emails)} follow-up emails for Outlook")
                    
                    # Show Outlook integration options
                    st.subheader("📧 Open Emails in Outlook")
                    st.info("Click the buttons below to open each email directly in your Outlook application. All fields will be pre-filled - you just need to review and send.")
                    
                    for i, email in enumerate(outlook_emails):
                        with st.expander(f"Email {i+1}: {email.get('to', 'Unknown')} - {email.get('subject', 'No Subject')[:50]}..."):
                            col1, col2 = st.columns([3, 1])
                            
                            with col1:
                                st.write(f"**To:** {email.get('to', 'N/A')}")
                                st.write(f"**Subject:** {email.get('subject', 'N/A')}")
                                st.write("**Body Preview:**")
                                body_preview = email.get('body', 'N/A')[:200] + '...' if len(email.get('body', '')) > 200 else email.get('body', 'N/A')
                                st.text(body_preview)
                            
                            with col2:
                                # Create the Outlook mailto button
                                outlook_link = email.get('outlook_link', '')
                                if outlook_link:
                                    st.markdown(f"""
                                    <a href="{outlook_link}" target="_blank">
                                        <button style="
                                            background-color: #0078d4;
                                            color: white;
                                            border: none;
                                            padding: 10px 15px;
                                            border-radius: 5px;
                                            cursor: pointer;
                                            width: 100%;
                                            margin-bottom: 10px;
                                        ">📧 Open in Outlook</button>
                                    </a>
                                    """, unsafe_allow_html=True)
                
                elif output_method == "Export as CSV":
                    # Export as CSV
                    st.session_state.generated_emails.extend(generated_emails)
                    
                    status_text.text("Email generation completed!")
                    st.success(f"Successfully generated {len(generated_emails)} follow-up emails")
                    
                    # Create CSV export
                    emails_df = email_generator.export_emails_to_csv(generated_emails)
                    csv_data = emails_df.to_csv(index=False)
                    
                    st.download_button(
                        label="📥 Download Generated Emails CSV",
                        data=csv_data,
                        file_name=f"followup_emails_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv",
                        type="primary"
                    )
                
                elif output_method == "Send via SMTP":
                    # Store generated emails
                    st.session_state.generated_emails.extend(generated_emails)
                    
                    status_text.text("Email generation completed!")
                    st.success(f"Successfully generated {len(generated_emails)} follow-up emails")
                    st.warning("SMTP sending functionality would need to be configured with your email server settings.")
                
                # Show preview of first email
                if generated_emails:
                    st.subheader("Email Preview")
                    with st.expander("Preview First Generated Email", expanded=True):
                        first_email = generated_emails[0]
                        st.write(f"**To:** {first_email.get('to', 'N/A')}")
                        st.write(f"**Subject:** {first_email.get('subject', 'N/A')}")
                        st.write("**Body:**")
                        st.text_area("", value=first_email.get('body', 'N/A'), height=200, disabled=True)
    
    with tab3:
        st.subheader("Manage Follow-up Activities")
        
        # Display summary metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Selected Events", len(st.session_state.selected_events))
        
        with col2:
            draft_count = len([e for e in st.session_state.generated_emails if e.get('status') == 'Draft'])
            st.metric("Draft Emails", draft_count)
        
        with col3:
            sent_count = len([e for e in st.session_state.generated_emails if e.get('status') == 'Sent'])
            st.metric("Sent Emails", sent_count)
        
        with col4:
            response_count = len([e for e in st.session_state.generated_emails if e.get('status') == 'Responded'])
            st.metric("Responses Received", response_count)
        
        # Manage selected events
        if st.session_state.selected_events:
            st.subheader("Selected Events Queue")
            
            events_df = pd.DataFrame(st.session_state.selected_events)
            
            # Create management interface
            if st.button("Clear All Selected Events", type="secondary"):
                st.session_state.selected_events = []
                st.success("Cleared all selected events")
                st.rerun()
            
            # Show events table
            if not events_df.empty:
                display_cols = ['sender', 'subject', 'selected_at']
                if 'risk_level' in events_df.columns:
                    display_cols.append('risk_level')
                if 'department' in events_df.columns:
                    display_cols.append('department')
                
                available_display_cols = [col for col in display_cols if col in events_df.columns]
                st.dataframe(events_df[available_display_cols], use_container_width=True)
        
        # Manage generated emails
        if st.session_state.generated_emails:
            st.subheader("Generated Emails Management")
            
            emails_df = pd.DataFrame(st.session_state.generated_emails)
            
            # Check if there are Outlook emails
            outlook_emails = [email for email in st.session_state.generated_emails if 'outlook_link' in email]
            
            if outlook_emails:
                st.subheader("📧 Outlook Integration")
                st.info(f"You have {len(outlook_emails)} emails ready for Outlook. Click the buttons below to open them in your Outlook application.")
                
                # Group Outlook emails for easy access
                for i, email in enumerate(outlook_emails[:5]):  # Show first 5
                    col1, col2, col3 = st.columns([2, 2, 1])
                    
                    with col1:
                        st.write(f"**{i+1}.** {email.get('to', 'Unknown')}")
                    
                    with col2:
                        subject = email.get('subject', 'No Subject')
                        st.write(f"{subject[:40]}..." if len(subject) > 40 else subject)
                    
                    with col3:
                        outlook_link = email.get('outlook_link', '')
                        if outlook_link:
                            st.markdown(f"""
                            <a href="{outlook_link}" target="_blank">
                                <button style="
                                    background-color: #0078d4;
                                    color: white;
                                    border: none;
                                    padding: 5px 10px;
                                    border-radius: 3px;
                                    cursor: pointer;
                                    width: 100%;
                                    font-size: 12px;
                                ">📧 Open</button>
                            </a>
                            """, unsafe_allow_html=True)
                
                if len(outlook_emails) > 5:
                    st.info(f"Showing first 5 emails. {len(outlook_emails) - 5} more emails available in the detailed view below.")
            
            # Email status management
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("Mark All as Sent", type="secondary"):
                    for email in st.session_state.generated_emails:
                        email['status'] = 'Sent'
                        email['sent_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    st.success("Marked all emails as sent")
                    st.rerun()
            
            with col2:
                if st.button("Clear All Generated Emails", type="secondary"):
                    st.session_state.generated_emails = []
                    st.success("Cleared all generated emails")
                    st.rerun()
            
            # Show emails table
            email_display_cols = ['to', 'subject', 'template_type', 'status', 'generated_at']
            if 'recipient_email' in emails_df.columns:
                email_display_cols[0] = 'recipient_email'
            
            available_email_cols = [col for col in email_display_cols if col in emails_df.columns]
            
            if available_email_cols:
                st.dataframe(emails_df[available_email_cols], use_container_width=True)
            
            # Export functionality
            st.subheader("Export Options")
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("Export Selected Events", type="secondary"):
                    if st.session_state.selected_events:
                        events_export_df = pd.DataFrame(st.session_state.selected_events)
                        csv = events_export_df.to_csv(index=False)
                        st.download_button(
                            label="Download Events CSV",
                            data=csv,
                            file_name=f"selected_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                            mime="text/csv"
                        )
            
            with col2:
                if st.button("Export Generated Emails", type="secondary"):
                    if st.session_state.generated_emails:
                        emails_export_df = pd.DataFrame(st.session_state.generated_emails)
                        csv = emails_export_df.to_csv(index=False)
                        st.download_button(
                            label="Download Emails CSV",
                            data=csv,
                            file_name=f"generated_emails_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                            mime="text/csv"
                        )


if __name__ == "__main__":
    main()