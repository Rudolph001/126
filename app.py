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
    keyword_detector = KeywordDetector()

    # Sidebar navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.radio(
        "Select Page",
        ["📁 Data Upload", "⚠️ Threat Detection"]
    )

    if page == "📁 Data Upload":
        data_upload_page(data_processor, domain_classifier, keyword_detector)
    elif page == "⚠️ Threat Detection":
        dashboard_page(risk_engine, anomaly_detector, visualizer)

def data_upload_page(data_processor, domain_classifier, keyword_detector):
    st.header("📁 Data Upload")

    st.subheader("Email Data Upload")
    uploaded_file = st.file_uploader(
        "Upload Email Data (CSV)",
        type=['csv'],
        help="Required fields: _time, policy_name, sender, transmitter, recipients, subject, wordlist_subject, attachments, wordlist_attachment, justification, is_sensitive, bunit, department, business_pillar, domain, breach_prevented, user_response, tessian_message_shown, leaver, resignation_date"
    )

    if uploaded_file is not None:
        try:
            # Load and validate data
            df = pd.read_csv(uploaded_file)

            # Check required fields
            required_fields = [
                '_time', 'policy_name', 'sender', 'transmitter', 'recipients', 'subject', 'wordlist_subject',
                'attachments', 'wordlist_attachment', 'justification', 'is_sensitive', 'bunit', 'department',
                'business_pillar', 'domain', 'breach_prevented', 'user_response', 'tessian_message_shown',
                'leaver', 'resignation_date'
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
                pd.DataFrame()  # Empty whitelist
            )
            st.session_state.risk_scores = risk_scores

    df = st.session_state.processed_data.copy()

    # Recalculate risk scores for filtered data
    with st.spinner("🔄 Calculating risk scores..."):
        risk_scores = risk_engine.calculate_risk_scores(df, pd.DataFrame())

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

    # Calculate metrics
    total_emails = len(df)

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
            (df['leaver'].astype(str) != '-') &
            (df['wordlist_attachment'].astype(str) != '-') &
            (df['attachments'].astype(str) != '-') &
            (df['recipient_domain_type'] == 'free')
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
            (df['resignation_date'].notna()) &
            (df['attachments'].notna()) &
            (df['attachments'] != '') &
            (df['attachments'].astype(str) != '0')
        ])
        # Exclude critical alerts to avoid double counting
        critical_emails_mask = (
            (df['leaver'].astype(str) != '-') &
            (df['wordlist_attachment'].astype(str) != '-') &
            (df['attachments'].astype(str) != '-') &
            (df['recipient_domain_type'] == 'free')
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
            (df['has_attachments_bool']) &
            (((df['wordlist_subject'].notna() & (df['wordlist_subject'] != '')) | 
              (df['wordlist_attachment'].notna() & (df['wordlist_attachment'] != '')))) &
            (df['resignation_date'].isna()) &
            (df['recipient_domain_type'] != 'free')
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
            (df['leaver'].astype(str) != '-') &
            (df['wordlist_attachment'].astype(str) != '-') &
            (df['attachments'].astype(str) != '-') &
            (df['recipient_domain_type'] == 'free')
        ])

        high_security_alerts = len(df[
            (df['resignation_date'].notna()) &
            (df['attachments'].notna()) &
            (df['attachments'] != '') &
            (df['attachments'].astype(str) != '0')
        ]) - critical_alerts

        medium_risk_count = len(df[
            (df['has_attachments_bool']) &
            (((df['wordlist_subject'].notna() & (df['wordlist_subject'] != '')) | 
              (df['wordlist_attachment'].notna() & (df['wordlist_attachment'] != '')))) &
            (df['resignation_date'].isna()) &
            (df['recipient_domain_type'] != 'free')
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
        (df['leaver'].astype(str) != '-') &  # Leaver field must NOT equal "-"
        (df['wordlist_attachment'].astype(str) != '-') &  # Wordlist attachment must NOT equal "-"
        (df['attachments'].astype(str) != '-') &  # Attachments must NOT equal "-"
        (df['recipient_domain_type'] == 'free')  # Must be free email domain
    ]
    # Sort to show emails with resignation_date values at top
    high_risk_emails = high_risk_emails.copy()
    high_risk_emails['has_resignation_date_sort'] = high_risk_emails['resignation_date'].notna()
    high_risk_emails = high_risk_emails.sort_values(['has_resignation_date_sort', 'risk_score', '_time'], ascending=[False, False, False])

    st.markdown(f"""
    <div class="analysis-card" style="background: #fff5f5; border: 2px solid #dc3545;">
        <div class="analysis-header">
            <span class="analysis-icon">🚨</span>
            <h3 class="analysis-title" style="color: #dc3545;">Critical Risk Indicators</h3>
            <span class="count-badge" style="background: #f8d7da; color: #721c24;">{len(high_risk_emails)} emails</span>
        </div>
        <p style="color: #6c757d; margin-bottom: 1rem;">
            Emails that meet critical risk criteria, including:<br>
            • Departing employees (leaver field populated)<br>
            • Sensitive keywords in attachments<br>
            • Messages with file attachments<br>
            • Sent to free/public email domains (Gmail, Yahoo, etc.)
        </p>
    </div>
    """, unsafe_allow_html=True)

    if len(high_risk_emails) > 0:
        # Display with highlighting - include domain to show free email detection
        display_cols = ['_time', 'sender', 'recipients', 'domain', 'subject', 'risk_score', 'leaver', 'wordlist_attachment', 'attachments']
        available_cols = [col for col in display_cols if col in high_risk_emails.columns]

        def highlight_high_risk(row):
            styles = [''] * len(row)
            # Highlight leaver field (critical indicator)
            if 'leaver' in row.index and str(row['leaver']) != '-':
                leaver_idx = row.index.get_loc('leaver')
                styles[leaver_idx] = 'background-color: #ffcccc; color: #000000; font-weight: bold'
            # Highlight wordlist_attachment field (sensitive content indicator)
            if 'wordlist_attachment' in row.index and str(row['wordlist_attachment']) != '-':
                word_match_idx = row.index.get_loc('wordlist_attachment')
                styles[word_match_idx] = 'background-color: #ffcccc; color: #000000; font-weight: bold'
            # Highlight domain (free email indicator)
            if 'domain' in row.index:
                domain_idx = row.index.get_loc('domain')
                styles[domain_idx] = 'background-color: #fff3cd; color: #856404; font-weight: bold'
            # Highlight attachments (data exfiltration vector)
            if 'attachments' in row.index and str(row['attachments']) != '-':
                attachments_idx = row.index.get_loc('attachments')
                styles[attachments_idx] = 'background-color: #f8d7da; color: #721c24; font-weight: bold'
            return styles

        styled_high_risk = high_risk_emails[available_cols].style.apply(highlight_high_risk, axis=1)
        st.dataframe(styled_high_risk, use_container_width=True, height=400)
    else:
        st.success("✅ No critical security threats detected.")

    # View 2: High Security Alerts - Require both resignation_date and attachments
    high_security_emails = df[
        (df['resignation_date'].notna()) &  # Must have resignation_date value
        (df['attachments'].notna()) &       # Must have attachments value
        (df['attachments'] != '') &         # Attachments must not be empty
        (df['attachments'].astype(str) != '0') &  # Attachments must not be '0'
        (~df.index.isin(high_risk_emails.index))  # Exclude already classified as critical
    ]
    # Sort to show emails with resignation_date values at top
    high_security_emails = high_security_emails.copy()
    high_security_emails['has_resignation_date_sort'] = high_security_emails['resignation_date'].notna()
    high_security_emails = high_security_emails.sort_values(['has_resignation_date_sort', 'risk_score', '_time'], ascending=[False, False, False])

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
        display_cols = ['_time', 'sender', 'recipients', 'domain', 'subject', 'risk_score', 'resignation_date', 'attachments']
        available_cols = [col for col in display_cols if col in high_security_emails.columns]

        def highlight_high_security(row):
            styles = [''] * len(row)
            # Highlight resignation_date (key indicator)
            if 'resignation_date' in row.index and pd.notna(row['resignation_date']):
                resignation_idx = row.index.get_loc('resignation_date')
                styles[resignation_idx] = 'background-color: #fed7d7; color: #c53030; font-weight: bold'
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
        (((df['wordlist_subject'].notna() & (df['wordlist_subject'] != '')) | 
         (df['wordlist_attachment'].notna() & (df['wordlist_attachment'] != '')))) &  # Has wordlist matches
        (df['resignation_date'].isna()) &    # No resignation date
        (df['recipient_domain_type'] != 'free') &  # Not free email domains
        (~df.index.isin(high_risk_emails.index)) &  # Exclude critical alerts
        (~df.index.isin(high_security_emails.index))  # Exclude high security alerts
    ]
    # Sort to show emails with resignation_date values at top
    medium_risk_emails = medium_risk_emails.copy()
    medium_risk_emails['has_resignation_date_sort'] = medium_risk_emails['resignation_date'].notna()
    medium_risk_emails = medium_risk_emails.sort_values(['has_resignation_date_sort', 'risk_score', '_time'], ascending=[False, False, False])

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
        display_cols = ['_time', 'sender', 'recipients', 'subject', 'risk_score', 'resignation_date', 'wordlist_subject', 'wordlist_attachment', 'attachments']
        available_cols = [col for col in display_cols if col in medium_risk_emails.columns]

        def highlight_medium_risk(row):
            styles = [''] * len(row)
            # Highlight resignation_date if present (red)
            if 'resignation_date' in row.index and pd.notna(row['resignation_date']):
                resignation_idx = row.index.get_loc('resignation_date')
                styles[resignation_idx] = 'background-color: #ffcccc; color: #000000; font-weight: bold'
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
    # Sort to show emails with resignation_date values at top
    low_risk_emails = low_risk_emails.copy()
    low_risk_emails['has_resignation_date_sort'] = low_risk_emails['resignation_date'].notna()
    low_risk_emails = low_risk_emails.sort_values(['has_resignation_date_sort', 'risk_score', '_time'], ascending=[False, True, False])

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
        display_cols = ['_time', 'sender', 'recipients', 'subject', 'risk_score', 'attachments', 'resignation_date']
        available_cols = [col for col in display_cols if col in low_risk_emails.columns]

        def highlight_low_risk(row):
            styles = [''] * len(row)
            # Light green highlighting for low risk scores
            if 'risk_score' in row.index:
                risk_score_idx = row.index.get_loc('risk_score')
                styles[risk_score_idx] = 'background-color: #e8f5e8; color: #2e7d32; font-weight: bold'
            # Highlight resignation_date in red if present
            if 'resignation_date' in row.index and pd.notna(row['resignation_date']):
                resignation_idx = row.index.get_loc('resignation_date')
                styles[resignation_idx] = 'background-color: #ffcccc; color: #000000; font-weight: bold'
            return styles

        styled_low_risk = low_risk_emails[available_cols].style.apply(highlight_low_risk, axis=1)
        st.dataframe(styled_low_risk, use_container_width=True, height=400)
    else:
        st.info("No low-risk emails found.")

if __name__ == "__main__":
    main()