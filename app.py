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
            High risk indicators: Emails with attachments, leaver to free email domains
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
            Emailswith attachments and sensitive keywords, sent to non-free domains (no leaver status)
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
            
            # Get anomaly explanations from the detector
            if hasattr(anomaly_detector, 'last_analyzed_df'):
                anomaly_df_with_reasons = anomaly_detector.last_analyzed_df[anomaly_detector.last_analyzed_df['is_anomaly']].copy()
                
                if not anomaly_df_with_reasons.empty:
                    # Sort by anomaly score (most anomalous first)
                    if 'anomaly_score' in anomaly_df_with_reasons.columns:
                        anomaly_df_with_reasons = anomaly_df_with_reasons.sort_values('anomaly_score', ascending=True)
                    
                    st.write(f"**Top {min(10, len(anomaly_df_with_reasons))} Anomalous Emails with Explanations:**")
                    
                    # Display each anomaly with detailed explanation
                    for idx, (_, row) in enumerate(anomaly_df_with_reasons.head(10).iterrows()):
                        with st.expander(f"🚨 Anomaly #{idx+1}: {row.get('sender', 'Unknown')} - {row.get('subject', 'No Subject')[:50]}..."):
                            col1, col2 = st.columns([1, 1])
                            
                            with col1:
                                st.write("**Email Details:**")
                                st.write(f"• **Time:** {row.get('time', 'N/A')}")
                                st.write(f"• **Sender:** {row.get('sender', 'N/A')}")
                                st.write(f"• **Recipients:** {row.get('recipient_count', 'N/A')}")
                                st.write(f"• **Risk Score:** {row.get('risk_score', 'N/A'):.1f}/100")
                                if 'anomaly_score' in row:
                                    st.write(f"• **Anomaly Score:** {row['anomaly_score']:.2f}")
                                
                            with col2:
                                st.write("**Why This is Flagged as Anomaly:**")
                                if 'anomaly_reasons' in row and row['anomaly_reasons']:
                                    reasons = str(row['anomaly_reasons']).split(' | ')
                                    for reason in reasons:
                                        st.write(f"• {reason}")
                                else:
                                    st.write("• Detected as statistical outlier based on behavioral patterns")
                else:
                    st.info("No anomaly details available.")
            else:
                # Fallback to basic display
                anomaly_emails['anomaly_score'] = anomaly_detector.get_anomaly_score(df)[anomalies]
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

        # Domain statistics with business and free email classification
        st.subheader("Domain Statistics")

        # Initialize domain classifier
        domain_classifier = DomainClassifier()

        # Extract sender domains and classify them
        if 'sender_domain' not in df.columns:
            df['sender_domain'] = df['sender'].apply(lambda x: str(x).split('@')[-1].lower().strip() if pd.notna(x) and '@' in str(x) else '')

        # Get domain counts
        domain_counts = df['sender_domain'].value_counts()

        # Classify domains
        business_domains = []
        free_domains = []

        for domain, count in domain_counts.items():
            if domain and domain != '':
                domain_type = domain_classifier._classify_single_domain(domain)
                if domain_type == 'free':
                    free_domains.append((domain, count))
                else:
                    business_domains.append((domain, count))

        # Sort by count
        business_domains.sort(key=lambda x: x[1], reverse=True)
        free_domains.sort(key=lambda x: x[1], reverse=True)

        # Display metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Unique Domains", len(domain_counts))
        with col2:
            st.metric("Business Domains", len(business_domains))
        with col3:
            st.metric("Free Email Domains", len(free_domains))

        # Display top domains in two columns
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("🏢 Top 20 Business Domains")
            if business_domains:
                business_df = pd.DataFrame(business_domains[:20], columns=['Domain', 'Email Count'])
                business_df['Rank'] = range(1, len(business_df) + 1)
                business_df = business_df[['Rank', 'Domain', 'Email Count']]
                st.dataframe(business_df, use_container_width=True, height=400)
            else:
                st.info("No business domains found in the dataset")

        with col2:
            st.subheader("📧 Top 20 Free Email Domains")
            if free_domains:
                free_df = pd.DataFrame(free_domains[:20], columns=['Domain', 'Email Count'])
                free_df['Rank'] = range(1, len(free_df) + 1)
                free_df = free_df[['Rank', 'Domain', 'Email Count']]
                st.dataframe(free_df, use_container_width=True, height=400)
            else:
                st.info("No free email domains found in the dataset")

        # Overall domain distribution summary
        st.subheader("📊 Domain Type Distribution")
        total_business_emails = sum(count for _, count in business_domains)
        total_free_emails = sum(count for _, count in free_domains)
        total_emails = total_business_emails + total_free_emails

        if total_emails > 0:
            business_pct = (total_business_emails / total_emails) * 100
            free_pct = (total_free_emails / total_emails) * 100

            summary_col1, summary_col2 = st.columns(2)
            with summary_col1:
                st.metric(
                    "Business Domain Emails", 
                    f"{total_business_emails:,}",
                    delta=f"{business_pct:.1f}% of total"
                )
            with summary_col2:
                st.metric(
                    "Free Email Domain Emails", 
                    f"{total_free_emails:,}",
                    delta=f"{free_pct:.1f}% of total"
                )

    elif analysis_type == "Advanced Analytics - Low Risk BAU":
        from utils.bau_analyzer import BAUAnalyzer

        st.subheader("🔍 Advanced Analytics Dashboard")
        st.info("Comprehensive email analysis with threat detection and pattern recognition across ALL email events")

        # Dataset Overview KPIs
        st.subheader("📊 Complete Dataset Overview")

        # Calculate email counts by alert type using the new classification
        total_emails = len(df)

        # Define alert classifications based on same logic as dashboard
        df['has_attachments_bool'] = df['attachments'].notna() & (df['attachments'] != '') & (df['attachments'].astype(str) != '0')
        df['has_last_working_day'] = df['last_working_day'].notna()

        # Critical alerts
        critical_alerts = len(df[
            (df['last_working_day'].notna()) &
            (df['attachments'].notna()) &
            (df['attachments'] != '') &
            (df['attachments'].astype(str) != '0') &
            (df['word_list_match'].notna()) &
            (df['word_list_match'] != '') &
            (df['email_domain'].str.contains('gmail|yahoo|hotmail|outlook|aol|icloud|protonmail|tutanota', case=False, na=False))
        ])

        # High alerts
        high_alerts = len(df[
            (df['last_working_day'].notna()) &
            (df['attachments'].notna()) &
            (df['attachments'] != '') &
            (df['attachments'].astype(str) != '0')
        ]) - critical_alerts

        # Medium alerts
        medium_alerts = len(df[
            (df['has_attachments_bool']) &
            (df['word_list_match'].notna()) &
            (df['word_list_match'] != '') &
            (~df['has_last_working_day']) &
            (~df['email_domain'].str.contains('gmail|yahoo|hotmail|outlook|aol|icloud|protonmail|tutanota', case=False, na=False))
        ])

        # Low alerts (all others)
        low_alerts = total_emails - critical_alerts - high_alerts - medium_alerts

        # Create KPI metrics
        col1, col2, col3, col4, col5 = st.columns(5)

        with col1:
            st.metric(
                label="Total Emails",
                value=f"{total_emails:,}",
                help="Total number of emails in the complete dataset"
            )

        with col2:
            critical_pct = (critical_alerts/total_emails*100) if total_emails > 0 else 0
            st.metric(
                label="Critical Alerts", 
                value=f"{critical_alerts:,}",
                delta=f"{critical_pct:.1f}% of total",
                help="Critical security alerts requiring immediate attention"
            )

        with col3:
            high_pct = (high_alerts/total_emails*100) if total_emails > 0 else 0
            st.metric(
                label="High Alerts",
                value=f"{high_alerts:,}",
                delta=f"{high_pct:.1f}% of total",
                help="High priority security alerts"
            )

        with col4:
            medium_pct = (medium_alerts/total_emails*100) if total_emails > 0 else 0
            st.metric(
                label="Medium Alerts",
                value=f"{medium_alerts:,}",
                delta=f"{medium_pct:.1f}% of total",
                help="Medium priority security indicators"
            )

        with col5:
            low_pct = (low_alerts/total_emails*100) if total_emails > 0 else 0
            st.metric(
                label="Low Alerts",
                value=f"{low_alerts:,}",
                delta=f"{low_pct:.1f}% of total",
                help="Low priority or normal email activity"
            )

        # Use complete dataset for analysis (no filtering)
        filtered_df = df.copy()
        filter_label = "all email events"

        # Initialize BAU analyzer
        bau_analyzer = BAUAnalyzer()

        # Perform analysis on complete dataset
        with st.spinner(f"Analyzing complete dataset patterns..."):
            analysis_results = bau_analyzer.analyze_low_risk_patterns(filtered_df)

        # Advanced Analytics KPIs - Show email counts used for analysis of complete dataset
        st.subheader("📈 Complete Dataset Analysis Coverage")

        # Calculate specific metrics for the complete dataset analysis
        analysis_df = filtered_df

        # Banking emails in complete dataset
        banking_emails = 0
        business_hours_emails = 0
        attachment_emails = 0

        if not analysis_df.empty:
            # Banking email detection
            banking_keywords = [
                'financial', 'banking', 'credit', 'loan', 'investment', 'portfolio',
                'transaction', 'account', 'balance', 'statement', 'audit', 'compliance'
            ]

            banking_mask = pd.Series([False] * len(analysis_df), index=analysis_df.index)
            text_columns = ['subject']
            if 'body' in analysis_df.columns:
                text_columns.append('body')

            for col in text_columns:
                if col in analysis_df.columns:
                    for keyword in banking_keywords:
                        banking_mask |= analysis_df[col].str.contains(keyword, case=False, na=False)

            banking_emails = banking_mask.sum()

            # Business hours emails
            if 'time' in analysis_df.columns:
                time_df = pd.to_datetime(analysis_df['time'], errors='coerce')
                hour = time_df.dt.hour
                day_of_week = time_df.dt.dayofweek
                business_hours_emails = len(analysis_df[
                    (hour >= 9) & (hour <= 17) & (day_of_week.isin([0, 1, 2, 3, 4]))
                ])

            # Emails with attachments
            if 'attachments' in analysis_df.columns:
                attachment_emails = len(analysis_df[
                    analysis_df['attachments'].notna() & 
                    (analysis_df['attachments'] != '') & 
                    (analysis_df['attachments'].astype(str) != '0')
                ])

        # Display KPI metrics for complete dataset analysis coverage
        col1, col2, col3, col4, col5 = st.columns(5)

        with col1:
            st.metric(
                label="Analysis Dataset",
                value=f"{len(analysis_df):,}",
                help="Complete dataset analyzed for patterns and threats"
            )

        with col2:
            banking_pct = (banking_emails/len(analysis_df)*100) if len(analysis_df) > 0 else 0
            st.metric(
                label="Banking Content",
                value=f"{banking_emails:,}",
                delta=f"{banking_pct:.1f}% of dataset",
                help="All emails containing banking/financial keywords"
            )

        with col3:
            bh_pct = (business_hours_emails/len(analysis_df)*100) if len(analysis_df) > 0 else 0
            st.metric(
                label="Business Hours",
                value=f"{business_hours_emails:,}",
                delta=f"{bh_pct:.1f}% of dataset",
                help="All emails sent during business hours (9AM-5PM, Mon-Fri)"
            )

        with col4:
            att_pct = (attachment_emails/len(analysis_df)*100) if len(analysis_df) > 0 else 0
            st.metric(
                label="With Attachments",
                value=f"{attachment_emails:,}",
                delta=f"{att_pct:.1f}% of dataset",
                help="All emails containing file attachments"
            )

        with col5:
            unique_senders_filtered = analysis_df['sender'].nunique() if 'sender' in analysis_df.columns else 0
            st.metric(
                label="Unique Senders",
                value=f"{unique_senders_filtered:,}",
                help="Number of unique senders in complete dataset"
            )

        # Display results in tabs
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "Pattern Overview", 
            "Banking Context", 
            "Threat Detection", 
            "Anomalies", 
            "Recommendations"
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
            st.subheader("Threat Detection - Complete Dataset")

            ip_risks_df = analysis_results.get('ip_risks', pd.DataFrame())

            if not ip_risks_df.empty:
                st.warning(f"Found {len(ip_risks_df)} potentially sensitive emails in complete dataset")

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
                st.subheader("Top Threat Emails")
                display_cols = ['sender', 'subject', 'risk_score', 'banking_keywords', 'ip_keywords']
                available_cols = [col for col in display_cols if col in ip_risks_df.columns]

                top_risks = ip_risks_df.nlargest(10, 'risk_score')[available_cols]
                st.dataframe(top_risks, use_container_width=True)

                # Risk factors analysis
                st.subheader("Common Threat Indicators")
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
                st.success("No hidden threats detected in complete dataset")

        with tab4:
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
               - GDPR data protection compliance
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

if __name__ == "__main__":
    main()