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
        ["📁 Data Upload", "📊 Dashboard", "📈 Analytics", "🌐 Network View", "📧 Follow-up Actions", "📋 Reports", "⚙️ Whitelist Management"]
    )

    if page == "📁 Data Upload":
        data_upload_page(data_processor, domain_classifier, keyword_detector)
    elif page == "⚙️ Whitelist Management":
        whitelist_management_page()
    elif page == "📊 Dashboard":
        dashboard_page(risk_engine, anomaly_detector, visualizer)
    elif page == "📈 Analytics":
        analytics_page(visualizer, anomaly_detector)
    elif page == "🌐 Network View":
        network_view_page(visualizer)
    elif page == "📧 Follow-up Actions":
        follow_up_actions_page(email_generator)
    elif page == "📋 Reports":
        reports_page()

def data_upload_page(data_processor, domain_classifier, keyword_detector):
    st.header("📁 Data Upload")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Email Data Upload")
        uploaded_file = st.file_uploader(
            "Upload Email Data (CSV)",
            type=['csv'],
            help="Required fields: time, sender, recipients, email_domain, word_list_match, recipient_status, subject, attachments, act, delivered, deliveryErrors, direction, eventtype, aggreatedid, tessian, tessian_response, mimecast, tessian_outcome, tessian_policy, last_working_day, bunit, department, businessPillar"
        )

        if uploaded_file is not None:
            try:
                # Load and validate data
                df = pd.read_csv(uploaded_file)

                # Check required fields
                required_fields = [
                    'time', 'sender', 'recipients', 'email_domain', 'word_list_match',
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
    high_risk_emails['has_last_working_day_sort'] = high_risk_emails['last_working_day'].notna()
    high_risk_emails = high_risk_emails.sort_values(['has_last_working_day_sort', 'risk_score', 'time'], ascending=[False, False, False])
    
    st.markdown(f"""
    <div class="analysis-card" style="background: #fff5f5; border: 2px solid #dc3545;">
        <div class="analysis-header">
            <span class="analysis-icon">🚨</span>
            <h3 class="analysis-title" style="color: #dc3545;">Critical Security Alerts</h3>
            <span class="count-badge" style="background: #f8d7da; color: #721c24;">{len(high_risk_emails)} emails</span>
        </div>
        <p style="color: #6c757d; margin-bottom: 1rem;">
            Critical alerts: Emails with attachments, word matches, leaver to free email domains
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
    high_security_emails['has_last_working_day_sort'] = high_security_emails['last_working_day'].notna()
    high_security_emails = high_security_emails.sort_values(['has_last_working_day_sort', 'risk_score', 'time'], ascending=[False, False, False])
    
    st.markdown(f"""
    <div class="analysis-card" style="background: #fff8f0; border: 2px solid #ff8c00;">
        <div class="analysis-header">
            <span class="analysis-icon">🟠</span>
            <h3 class="analysis-title" style="color: #cc5500;">High Security Alerts</h3>
            <span class="count-badge" style="background: #ffe4cc; color: #cc5500;">{len(high_security_emails)} emails</span>
        </div>
        <p style="color: #6c757d; margin-bottom: 1rem;">
            High security alerts: Emails with attachments, leaver to free email domains
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
            Emails with attachments and sensitive keywords, sent to non-free domains (no leaver status)
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

        col1, col2 = st.columns(2)

        with col1:
            volume_fig = visualizer.create_volume_trend_chart(df)
            st.plotly_chart(volume_fig, use_container_width=True)

        with col2:
            domain_fig = visualizer.create_domain_analysis_chart(df)
            st.plotly_chart(domain_fig, use_container_width=True)

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
            anomaly_emails = df[anomalies].copy()
            anomaly_emails['anomaly_score'] = anomaly_detector.get_anomaly_score(df)[anomalies]
            
            # Display top anomalies
            top_anomalies = anomaly_emails.nlargest(10, 'anomaly_score')
            display_cols = ['time', 'sender', 'subject', 'anomaly_score']
            available_cols = [col for col in display_cols if col in top_anomalies.columns]
            st.dataframe(top_anomalies[available_cols])
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
            high_risk = df[df.get('risk_level', '') == 'High']
            if not high_risk.empty:
                display_cols = ['time', 'sender', 'subject', 'risk_score', 'risk_level']
                available_cols = [col for col in display_cols if col in high_risk.columns]
                st.dataframe(high_risk[available_cols])
            else:
                st.info("No high-risk emails found.")
        else:
            st.warning("Risk analysis not available. Please ensure risk scores are calculated.")
    
    elif analysis_type == "Domain Analysis":
        st.subheader("Domain Communication Analysis")
        
        # Domain analysis chart
        domain_chart = visualizer.create_domain_analysis_chart(df)
        st.plotly_chart(domain_chart, use_container_width=True)
        
        # Domain statistics
        if 'recipient_domains' in df.columns:
            st.subheader("Domain Statistics")
            
            # Extract all domains
            all_domains = []
            for domains_str in df['recipient_domains'].dropna():
                if isinstance(domains_str, str):
                    all_domains.extend([d.strip() for d in domains_str.split(',')])
            
            if all_domains:
                from collections import Counter
                domain_counts = Counter(all_domains)
                
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Unique Domains", len(domain_counts))
                with col2:
                    st.metric("Most Common Domain", domain_counts.most_common(1)[0][0])
                
                # Top domains table
                st.subheader("Top Domains")
                top_domains = pd.DataFrame(domain_counts.most_common(20), 
                                         columns=['Domain', 'Email Count'])
                st.dataframe(top_domains)
    
    elif analysis_type == "Advanced Analytics - Low Risk BAU":
        from utils.bau_analyzer import BAUAnalyzer
        
        st.subheader("🔍 Low Risk Business-as-Usual Analysis")
        st.info("Analyzing low-risk emails for BAU patterns and hidden threats including potential IP exfiltration in banking contexts")
        
        # Initialize BAU analyzer
        bau_analyzer = BAUAnalyzer()
        
        # Perform analysis
        with st.spinner("Analyzing low-risk email patterns..."):
            analysis_results = bau_analyzer.analyze_low_risk_patterns(df)
        
        # Display results in tabs
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "BAU Overview", 
            "Banking Context", 
            "Hidden IP Risks", 
            "Anomalies", 
            "Recommendations"
        ])
        
        with tab1:
            st.subheader("Business-as-Usual Patterns")
            
            bau_patterns = analysis_results.get('bau_patterns', {})
            
            # Low risk email count
            low_risk_count = len(df[df.get('risk_level', '') == 'Low'])
            total_count = len(df)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Low Risk Emails", low_risk_count)
            with col2:
                st.metric("Low Risk %", f"{(low_risk_count/total_count)*100:.1f}%" if total_count > 0 else "0%")
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
            st.subheader("Banking Sector Context Analysis")
            
            banking_analysis = analysis_results.get('banking_analysis', {})
            
            if banking_analysis.get('overview'):
                overview = banking_analysis['overview']
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Banking Emails", overview.get('total_banking_emails', 0))
                with col2:
                    st.metric("Banking %", f"{overview.get('percentage_of_low_risk', 0):.1f}%")
                with col3:
                    keywords_found = len(overview.get('banking_keywords_found', []))
                    st.metric("Banking Keywords", keywords_found)
                
                # Banking keywords found
                if overview.get('banking_keywords_found'):
                    st.subheader("Banking Keywords Detected")
                    keywords = overview['banking_keywords_found']
                    # Display in columns for better layout
                    cols = st.columns(3)
                    for i, keyword in enumerate(keywords):
                        with cols[i % 3]:
                            st.write(f"• {keyword}")
                
                # Banking patterns
                if banking_analysis.get('patterns'):
                    patterns = banking_analysis['patterns']
                    st.subheader("Banking Email Patterns")
                    
                    if patterns.get('temporal'):
                        temp = patterns['temporal']
                        col1, col2 = st.columns(2)
                        with col1:
                            st.write(f"**Business Hours Compliance:** {temp.get('business_hours_compliance', 0):.1f}%")
                            st.write(f"**Peak Banking Hour:** {temp.get('peak_banking_hours', 'N/A')}:00")
                        with col2:
                            st.write(f"**Weekend Activity:** {temp.get('weekend_banking_activity', 0)} emails")
                    
                    if patterns.get('senders'):
                        send = patterns['senders']
                        st.write(f"**Unique Banking Senders:** {send.get('unique_banking_senders', 0)}")
            else:
                st.info("No banking-related content detected in low-risk emails")
        
        with tab3:
            st.subheader("Hidden IP Risk Detection")
            
            ip_risks_df = analysis_results.get('ip_risks', pd.DataFrame())
            
            if not ip_risks_df.empty:
                st.warning(f"Found {len(ip_risks_df)} potentially sensitive emails in low-risk category")
                
                # Risk score distribution
                risk_scores = ip_risks_df['risk_score']
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Avg Risk Score", f"{risk_scores.mean():.1f}")
                with col2:
                    st.metric("Max Risk Score", f"{risk_scores.max():.0f}")
                with col3:
                    st.metric("High Risk (>7)", len(ip_risks_df[ip_risks_df['risk_score'] > 7]))
                
                # Top risky emails
                st.subheader("Top Risk Emails")
                display_cols = ['sender', 'subject', 'risk_score', 'banking_keywords', 'ip_keywords']
                available_cols = [col for col in display_cols if col in ip_risks_df.columns]
                
                top_risks = ip_risks_df.nlargest(10, 'risk_score')[available_cols]
                st.dataframe(top_risks, use_container_width=True)
                
                # Risk factors analysis
                st.subheader("Common Risk Factors")
                all_factors = []
                for factors_list in ip_risks_df['risk_factors']:
                    if isinstance(factors_list, list):
                        all_factors.extend(factors_list)
                
                if all_factors:
                    from collections import Counter
                    factor_counts = Counter(all_factors)
                    
                    for factor, count in factor_counts.most_common(5):
                        st.write(f"• {factor}: {count} occurrences")
            else:
                st.success("No hidden IP risks detected in low-risk emails")
        
        with tab4:
            st.subheader("Low-Risk Anomalies")
            
            anomalies_df = analysis_results.get('anomalies', pd.DataFrame())
            
            if not anomalies_df.empty:
                st.write(f"**Found {len(anomalies_df)} anomalies in low-risk emails**")
                
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
                
                # Anomaly details
                st.subheader("Anomaly Details")
                display_cols = ['type', 'description', 'severity']
                available_cols = [col for col in display_cols if col in anomalies_df.columns]
                st.dataframe(anomalies_df[available_cols], use_container_width=True)
            else:
                st.info("No anomalies detected in low-risk emails")
        
        with tab5:
            st.subheader("Recommendations & Actions")
            
            recommendations = analysis_results.get('recommendations', [])
            
            if recommendations:
                for i, rec in enumerate(recommendations):
                    with st.expander(f"{rec.get('category', 'General')} - {rec.get('priority', 'Medium')} Priority"):
                        st.write(f"**Issue:** {rec.get('recommendation', '')}")
                        st.write(f"**Suggested Action:** {rec.get('action', '')}")
            else:
                st.success("No immediate actions required based on current analysis")
            
            # Additional suggestions
            st.subheader("Additional Enhancement Ideas")
            st.write("""
            **Consider implementing these features:**
            
            1. **Machine Learning Classification**
               - Train models on banking email patterns
               - Implement content-based risk scoring
               - Use natural language processing for IP detection
            
            2. **Advanced Behavioral Analysis**
               - User baseline profiling for banking employees
               - Peer group comparison analysis
               - Seasonal pattern recognition
            
            3. **Real-time Monitoring**
               - Live dashboard for banking sector activity
               - Automated alerts for IP keyword combinations
               - Integration with compliance systems
            
            4. **Content Deep Dive**
               - Attachment content analysis
               - Email thread reconstruction
               - Communication pattern mapping
            
            5. **Compliance Integration**
               - SOX compliance checking
               - Basel III regulatory alignment
               - GDPR data protection verification
            """)
        
        # Create and display charts
        charts = bau_analyzer.create_bau_dashboard_charts(analysis_results)
        
        if charts:
            st.subheader("📈 Visual Analytics")
            
            chart_cols = st.columns(2)
            chart_idx = 0
            
            for chart_name, chart in charts.items():
                with chart_cols[chart_idx % 2]:
                    st.plotly_chart(chart, use_container_width=True)
                chart_idx += 1

def network_view_page(visualizer):
    st.header("🌐 Network Visualization")

    if st.session_state.processed_data is None:
        st.warning("Please upload email data first in the Data Upload page.")
        return

    df = st.session_state.processed_data.copy()

    if st.session_state.risk_scores is not None:
        df['risk_score'] = st.session_state.risk_scores
        df['risk_level'] = df['risk_score'].apply(lambda x: 
            'High Risk' if x >= 61 else 'Medium Risk' if x >= 31 else 'Normal'
        )

    # Network visualization options
    col1, col2 = st.columns([1, 3])

    with col1:
        st.subheader("Network Options")

        max_nodes = st.slider("Max Nodes", 10, 200, 50)
        risk_filter = st.selectbox(
            "Risk Level Filter",
            ['All', 'High Risk', 'Medium Risk', 'Normal']
        )

        layout_type = st.selectbox(
            "Layout Type",
            ['spring', 'circular', 'random']
        )

    with col2:
        st.subheader("Email Network Graph")

        # Filter data based on selection
        filtered_df = df.copy()
        if risk_filter != 'All':
            filtered_df = filtered_df[filtered_df.get('risk_level', 'Normal') == risk_filter]

        # Create network visualization
        with st.spinner("Generating network graph..."):
            network_fig = visualizer.create_network_graph(filtered_df, max_nodes, layout_type)
            st.plotly_chart(network_fig, use_container_width=True)

    # Network statistics
    st.subheader("📊 Network Statistics")

    col1, col2, col3 = st.columns(3)

    with col1:
        unique_senders = df['sender'].nunique()
        st.metric("Unique Senders", unique_senders)

    with col2:
        unique_domains = df['email_domain'].nunique()
        st.metric("Unique Domains", unique_domains)

    with col3:
        if 'risk_score' in df.columns:
            high_risk_senders = len(df[df.get('risk_level', 'Normal') == 'High Risk']['sender'].unique())
            st.metric("High Risk Senders", high_risk_senders)

def follow_up_actions_page(email_generator):
    st.header("📧 Follow-up Actions")

    if st.session_state.processed_data is None:
        st.warning("Please upload email data first in the Data Upload page.")
        return

    df = st.session_state.processed_data.copy()

    if st.session_state.risk_scores is not None:
        df['risk_score'] = st.session_state.risk_scores
        df['risk_level'] = df['risk_score'].apply(lambda x: 
            'High Risk' if x >= 61 else 'Medium Risk' if x >= 31 else 'Normal'
        )

    # Filter high and medium risk emails
    risky_emails = df[df.get('risk_level', 'Normal').isin(['High Risk', 'Medium Risk'])]

    st.subheader("⚠️ Flagged Emails Requiring Follow-up")
    st.info(f"Found {len(risky_emails)} emails that may require follow-up action.")

    if len(risky_emails) > 0:
        # Selection options
        col1, col2 = st.columns(2)

        with col1:
            selection_mode = st.radio(
                "Selection Mode",
                ["Select All High Risk", "Select All Medium Risk", "Manual Selection"]
            )

        with col2:
            email_type = st.selectbox(
                "Follow-up Type",
                ["Security Inquiry", "Data Classification Review", "Policy Reminder", "Custom"]
            )

        # Email selection
        selected_emails = []

        if selection_mode == "Select All High Risk":
            selected_emails = risky_emails[risky_emails['risk_level'] == 'High Risk'].index.tolist()
        elif selection_mode == "Select All Medium Risk":
            selected_emails = risky_emails[risky_emails['risk_level'] == 'Medium Risk'].index.tolist()
        else:
            # Manual selection with checkboxes
            st.subheader("Select Emails for Follow-up")

            for idx, row in risky_emails.iterrows():
                col1, col2, col3, col4 = st.columns([1, 3, 2, 2])

                with col1:
                    if st.checkbox("", key=f"select_{idx}"):
                        selected_emails.append(idx)

                with col2:
                    st.write(f"**{row['sender']}** → {row['recipients']}")

                with col3:
                    st.write(f"Risk: {row.get('risk_level', 'Unknown')}")

                with col4:
                    st.write(f"Score: {row.get('risk_score', 0):.1f}")

        # Generate follow-up emails
        if selected_emails:
            st.subheader("📝 Generate Follow-up Emails")
            st.info(f"Selected {len(selected_emails)} emails for follow-up.")

            # Email template customization
            if email_type == "Custom":
                subject_template = st.text_input(
                    "Email Subject",
                    "Security Review Required: Email Activity Alert"
                )

                body_template = st.text_area(
                    "Email Body Template",
                    """Dear [SENDER_NAME],

We hope this message finds you well. As part of our ongoing commitment to data security, we have identified some email activity that requires review.

Details:
- Email sent on: [EMAIL_DATE]
- Recipients: [RECIPIENTS]
- Risk Score: [RISK_SCORE]

This is a routine security measure to ensure compliance with our data protection policies. Please contact the IT Security team if you have any questions.

Best regards,
IT Security Team""",
                    height=200
                )
            else:
                subject_template, body_template = email_generator.get_template(email_type)

                st.write("**Subject:**", subject_template)
                st.write("**Body Preview:**")
                st.text_area("", body_template, height=150, disabled=True)

            # Generate emails
            col1, col2 = st.columns(2)

            with col1:
                if st.button("📧 Generate Follow-up Emails", type="primary"):
                    generated_emails = []

                    for idx in selected_emails:
                        email_data = risky_emails.loc[idx]
                        email_content = email_generator.generate_email(
                            email_data, subject_template, body_template
                        )
                        generated_emails.append(email_content)

                    # Display generated emails
                    st.subheader("Generated Emails")

                    for i, email in enumerate(generated_emails):
                        with st.expander(f"Email {i+1}: {email['to']}"):
                            st.write(f"**To:** {email['to']}")
                            st.write(f"**Subject:** {email['subject']}")
                            st.write("**Body:**")
                            st.text_area("", email['body'], height=150, key=f"email_{i}")

                    # Export option
                    emails_df = pd.DataFrame(generated_emails)
                    csv_buffer = io.StringIO()
                    emails_df.to_csv(csv_buffer, index=False)

                    st.download_button(
                        label="📥 Download Follow-up Emails",
                        data=csv_buffer.getvalue(),
                        file_name=f"follow_up_emails_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )

            with col2:
                if st.button("📊 Export Selected Data"):
                    selected_data = risky_emails.loc[selected_emails]
                    csv_buffer = io.StringIO()
                    selected_data.to_csv(csv_buffer, index=False)

                    st.download_button(
                        label="📥 Download Selected Email Data",
                        data=csv_buffer.getvalue(),
                        file_name=f"flagged_emails_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
    else:
        st.success("No emails currently flagged for follow-up action.")

def reports_page():
    st.header("📋 Reports & Export")

    if st.session_state.processed_data is None:
        st.warning("Please upload email data first in the Data Upload page.")
        return

    df = st.session_state.processed_data.copy()

    if st.session_state.risk_scores is not None:
        df['risk_score'] = st.session_state.risk_scores
        df['risk_level'] = df['risk_score'].apply(lambda x: 
            'High Risk' if x >= 61 else 'Medium Risk' if x >= 31 else 'Normal'
        )

    # Report generation options
    st.subheader("📊 Generate Reports")

    col1, col2 = st.columns(2)

    with col1:
        report_type = st.selectbox(
            "Report Type",
            ["Summary Report", "Risk Analysis", "Department Breakdown", "Timeline Analysis", "Custom Export"]
        )

    with col2:
        date_range = st.date_input(
            "Date Range",
            value=[datetime.now() - timedelta(days=30), datetime.now()],
            key="report_date_range"
        )

    # Generate report based on selection
    if report_type == "Summary Report":
        st.subheader("📈 Executive Summary")

        # Key metrics
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Total Emails Analyzed", len(df))

        with col2:
            high_risk_count = len(df[df.get('risk_level', 'Normal') == 'High Risk'])
            st.metric("High Risk Emails", high_risk_count)

        with col3:
            if 'risk_score' in df.columns:
                avg_risk = df['risk_score'].mean()
                st.metric("Average Risk Score", f"{avg_risk:.1f}")

        with col4:
            unique_senders = df['sender'].nunique()
            st.metric("Unique Senders", unique_senders)

        # Summary table
        summary_data = {
            'Risk Level': ['Normal', 'Medium Risk', 'High Risk'],
            'Count': [
                len(df[df.get('risk_level', 'Normal') == 'Normal']),
                len(df[df.get('risk_level', 'Normal') == 'Medium Risk']),
                len(df[df.get('risk_level', 'Normal') == 'High Risk'])
            ]
        }

        summary_df = pd.DataFrame(summary_data)
        summary_df['Percentage'] = (summary_df['Count'] / len(df) * 100).round(1)

        st.dataframe(summary_df, use_container_width=True)

    elif report_type == "Risk Analysis":
        st.subheader("⚠️ Risk Analysis Report")

        if 'risk_score' in df.columns:
            # Risk score distribution
            st.write("**Risk Score Distribution:**")
            st.dataframe(df['risk_score'].describe())

            # Top risk factors
            st.write("**High Risk Emails:**")
            high_risk_emails = df[df.get('risk_level', 'Normal') == 'High Risk']

            if len(high_risk_emails) > 0:
                display_cols = ['time', 'sender', 'recipients', 'subject', 'risk_score']
                available_cols = [col for col in display_cols if col in high_risk_emails.columns]
                st.dataframe(high_risk_emails[available_cols], use_container_width=True)
            else:
                st.info("No high risk emails found.")

    elif report_type == "Department Breakdown":
        st.subheader("🏢 Department Analysis")

        if 'department' in df.columns:
            dept_analysis = df.groupby('department').agg({
                'sender': 'count',
                'risk_score': 'mean' if 'risk_score' in df.columns else 'size'
            }).round(2)

            dept_analysis.columns = ['Email Count', 'Avg Risk Score']
            dept_analysis = dept_analysis.sort_values('Avg Risk Score', ascending=False)

            st.dataframe(dept_analysis, use_container_width=True)

    # Export options
    st.subheader("📥 Export Data")

    col1, col2, col3 = st.columns(3)

    with col1:
        # Full dataset export
        csv_buffer = io.StringIO()
        df.to_csv(csv_buffer, index=False)

        st.download_button(
            label="📊 Export Full Dataset",
            data=csv_buffer.getvalue(),
            file_name=f"email_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

    with col2:
        # High risk emails only
        if 'risk_level' in df.columns:
            high_risk_df = df[df['risk_level'] == 'High Risk']

            if len(high_risk_df) > 0:
                csv_buffer = io.StringIO()
                high_risk_df.to_csv(csv_buffer, index=False)

                st.download_button(
                    label="⚠️ Export High Risk Emails",
                    data=csv_buffer.getvalue(),
                    file_name=f"high_risk_emails_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )

    with col3:
        # Whitelist export
        if not st.session_state.whitelist_data.empty:
            csv_buffer = io.StringIO()
            st.session_state.whitelist_data.to_csv(csv_buffer, index=False)

            st.download_button(
                label="📋 Export Whitelist",
                data=csv_buffer.getvalue(),
                file_name=f"whitelist_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )

if __name__ == "__main__":
    main()