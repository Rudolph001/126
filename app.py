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

    # Calculate metrics
    total_emails = len(df)
    high_risk = len(df[df['risk_level'] == 'High Risk'])
    medium_risk = len(df[df['risk_level'] == 'Medium Risk'])
    low_risk = len(df[df['risk_level'] == 'Normal'])
    avg_risk = df['risk_score'].mean()

    # KPI Cards
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"""
        <div class="metric-card" style="border-left-color: #3498db;">
            <p class="metric-label">Total Emails Analyzed</p>
            <p class="metric-value" style="color: #3498db;">{total_emails:,}</p>
            <p class="metric-delta" style="color: #666;">📊 Dataset Overview</p>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        high_risk_pct = (high_risk/total_emails*100) if total_emails > 0 else 0
        st.markdown(f"""
        <div class="metric-card" style="border-left-color: #e74c3c;">
            <p class="metric-label">High Risk Alerts</p>
            <p class="metric-value" style="color: #e74c3c;">{high_risk}</p>
            <p class="metric-delta" style="color: #e74c3c;">🚨 {high_risk_pct:.1f}% of total</p>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        medium_risk_pct = (medium_risk/total_emails*100) if total_emails > 0 else 0
        st.markdown(f"""
        <div class="metric-card" style="border-left-color: #f39c12;">
            <p class="metric-label">Medium Risk</p>
            <p class="metric-value" style="color: #f39c12;">{medium_risk}</p>
            <p class="metric-delta" style="color: #f39c12;">⚠️ {medium_risk_pct:.1f}% of total</p>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        low_risk_count = len(df[df['risk_level'] == 'Normal'])
        low_risk_pct = (low_risk_count/total_emails*100) if total_emails > 0 else 0
        st.markdown(f"""
        <div class="metric-card" style="border-left-color: #27ae60;">
            <p class="metric-label">Low Risk Score</p>
            <p class="metric-value" style="color: #27ae60;">{low_risk_count}</p>
            <p class="metric-delta" style="color: #27ae60;">✅ {low_risk_pct:.1f}% of total</p>
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

    # Prepare email data with attachment status
    df['has_attachments_bool'] = df['attachments'].notna() & (df['attachments'] != '') & (df['attachments'].astype(str) != '0')
    df['has_last_working_day'] = df['last_working_day'].notna()
    
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
    ].sort_values(['risk_score', 'time'], ascending=[False, False])
    
    st.markdown(f"""
    <div class="analysis-card high-risk">
        <div class="analysis-header">
            <span class="analysis-icon">🚨</span>
            <h3 class="analysis-title">Critical Security Alerts</h3>
            <span class="count-badge">{len(high_risk_emails)} emails</span>
        </div>
        <p style="color: #6c757d; margin-bottom: 1rem;">
            Critical alerts: Emails with attachments, word matches, sent on last working day to free email domains
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

    # View 3: Medium-Risk Emails
    medium_risk_emails = df[
        (df['has_attachments_bool']) & 
        (
            (df['has_last_working_day']) |  # Has last working day
            (df['word_match_score'] == 2)   # Medium word match score
        ) &
        (~df.index.isin(high_risk_emails.index))  # Exclude already classified as high risk
    ].sort_values(['risk_score', 'time'], ascending=[False, False])
    
    st.markdown(f"""
    <div class="analysis-card medium-risk">
        <div class="analysis-header">
            <span class="analysis-icon">⚠️</span>
            <h3 class="analysis-title">Moderate Risk Indicators</h3>
            <span class="count-badge">{len(medium_risk_emails)} emails</span>
        </div>
        <p style="color: #6c757d; margin-bottom: 1rem;">
            Potentially suspicious activity that warrants monitoring and review
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

    # View 4: Low-Risk Emails
    low_risk_emails = df[
        (df['has_attachments_bool']) & 
        (df['risk_score'] <= 30) &  # Low risk score
        (~df.index.isin(high_risk_emails.index)) &  # Exclude high risk
        (~df.index.isin(medium_risk_emails.index))  # Exclude medium risk
    ].sort_values(['risk_score', 'time'], ascending=[True, False])
    
    st.markdown(f"""
    <div class="analysis-card low-risk">
        <div class="analysis-header">
            <span class="analysis-icon">✅</span>
            <h3 class="analysis-title">Low Risk Communications</h3>
            <span class="count-badge">{len(low_risk_emails)} emails</span>
        </div>
        <p style="color: #6c757d; margin-bottom: 1rem;">
            Emails with attachments showing normal communication patterns
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    if len(low_risk_emails) > 0:
        # Display with minimal highlighting
        display_cols = ['time', 'sender', 'recipients', 'subject', 'risk_score', 'attachments']
        available_cols = [col for col in display_cols if col in low_risk_emails.columns]
        
        def highlight_low_risk(row):
            styles = [''] * len(row)
            # Light green highlighting for low risk scores
            if 'risk_score' in row.index:
                risk_score_idx = row.index.get_loc('risk_score')
                styles[risk_score_idx] = 'background-color: #e8f5e8; color: #2e7d32; font-weight: bold'
            return styles
        
        styled_low_risk = low_risk_emails[available_cols].style.apply(highlight_low_risk, axis=1)
        st.dataframe(styled_low_risk, use_container_width=True, height=400)
    else:
        st.info("No low-risk emails with attachments found.")

    # View 5: Standard Email Communications (moved below Low Risk)
    emails_no_attachments = df[~df['has_attachments_bool']]
    
    st.markdown(f"""
    <div class="analysis-card normal">
        <div class="analysis-header">
            <span class="analysis-icon">📄</span>
            <h3 class="analysis-title">Standard Email Communications</h3>
            <span class="count-badge">{len(emails_no_attachments)} emails</span>
        </div>
        <p style="color: #6c757d; margin-bottom: 1rem;">
            Email communications without file attachments - typically lower risk profile
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    if len(emails_no_attachments) > 0:
        # Show sample data in a professional way
        display_cols = ['time', 'sender', 'subject']
        available_cols = [col for col in display_cols if col in emails_no_attachments.columns]
        
        sample_df = emails_no_attachments[available_cols].head(10)
        st.dataframe(sample_df, use_container_width=True, height=300)
    else:
        st.info("✅ No standard email communications found.")

    # Risk Factor Analysis section with professional styling
    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 2rem; border-radius: 12px; margin: 2rem 0 1rem 0;">
        <h2 style="margin: 0; color: white; font-size: 1.8rem; font-weight: 600;">
            🔍 Advanced Risk Factor Analysis
        </h2>
        <p style="margin: 0.5rem 0 0 0; color: #e8f4fd; font-size: 1rem;">
            Deep-dive analysis of individual email threats and risk components
        </p>
    </div>
    """, unsafe_allow_html=True)

    if len(df) > 0:
        st.markdown("""
        <div style="background: white; padding: 1.5rem; border-radius: 10px; margin: 1rem 0; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
            <h4 style="color: #495057; margin-bottom: 1rem;">📧 Select Email for Analysis</h4>
        </div>
        """, unsafe_allow_html=True)
        
        # Select an email to analyze
        email_options = []
        for idx, row in df.iterrows():
            sender = row.get('sender', 'Unknown')
            subject = str(row.get('subject', 'No Subject'))[:50]
            risk_score = row.get('risk_score', 0)
            risk_level = row.get('risk_level', 'Normal')
            
            # Add risk level indicator
            if risk_level == 'High Risk':
                indicator = "🚨"
            elif risk_level == 'Medium Risk':
                indicator = "⚠️"
            else:
                indicator = "✅"
                
            email_options.append(f"{indicator} {sender} - {subject}... (Score: {risk_score:.1f})")

        selected_email_idx = st.selectbox(
            "Choose an email to analyze:",
            range(len(email_options)),
            format_func=lambda x: email_options[x],
            help="Select any email to view detailed risk factor breakdown and scoring analysis"
        )

        if selected_email_idx is not None:
            # Get the actual dataframe index
            email_row_idx = df.iloc[selected_email_idx].name
            email_row = st.session_state.processed_data.loc[email_row_idx]

            # Get risk breakdown
            risk_breakdown = risk_engine.get_risk_breakdown(
                email_row, 
                st.session_state.processed_data, 
                st.session_state.whitelist_data
            )

            # Email details card
            selected_email = df.iloc[selected_email_idx]
            st.markdown(f"""
            <div style="background: white; padding: 1.5rem; border-radius: 10px; margin: 1rem 0; box-shadow: 0 2px 8px rgba(0,0,0,0.1); border-left: 4px solid #495057;">
                <h4 style="color: #495057; margin-bottom: 1rem;">📧 Email Details</h4>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
                    <div><strong>From:</strong> {selected_email.get('sender', 'Unknown')}</div>
                    <div><strong>To:</strong> {selected_email.get('recipients', 'Unknown')}</div>
                    <div><strong>Time:</strong> {selected_email.get('time', 'Unknown')}</div>
                    <div><strong>Attachments:</strong> {selected_email.get('attachments', 'None')}</div>
                </div>
                <div><strong>Subject:</strong> {selected_email.get('subject', 'No Subject')}</div>
            </div>
            """, unsafe_allow_html=True)

            # Risk Score Dashboard
            risk_level = risk_engine.get_risk_level(risk_breakdown['total_score'])
            
            # Color coding for risk levels
            if risk_level == 'High Risk':
                risk_color = "#dc3545"
                risk_bg = "#f8d7da"
                risk_icon = "🚨"
                risk_explanation = "This email exhibits multiple high-risk patterns that may indicate potential data exfiltration."
            elif risk_level == 'Medium Risk':
                risk_color = "#fd7e14"
                risk_bg = "#fff3cd"
                risk_icon = "⚠️"
                risk_explanation = "This email shows some concerning patterns that warrant monitoring and review."
            else:
                risk_color = "#28a745"
                risk_bg = "#d4edda"
                risk_icon = "✅"
                risk_explanation = "This email appears to follow normal communication patterns with minimal risk indicators."

            st.markdown(f"""
            <div style="background: {risk_bg}; padding: 2rem; border-radius: 12px; margin: 1rem 0; border-left: 5px solid {risk_color};">
                <div style="display: flex; align-items: center; margin-bottom: 1rem;">
                    <span style="font-size: 2rem; margin-right: 1rem;">{risk_icon}</span>
                    <div>
                        <h3 style="margin: 0; color: {risk_color}; font-size: 1.8rem;">Risk Score: {risk_breakdown['total_score']:.1f}</h3>
                        <h4 style="margin: 0; color: {risk_color};">{risk_level}</h4>
                    </div>
                </div>
                <p style="color: {risk_color}; margin: 0; font-size: 1rem; font-weight: 500;">
                    {risk_explanation}
                </p>
            </div>
            """, unsafe_allow_html=True)

            # Risk Factors Analysis
            st.markdown("""
            <div style="background: white; padding: 1.5rem; border-radius: 10px; margin: 1rem 0; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                <h4 style="color: #495057; margin-bottom: 1rem;">🔍 Risk Factor Breakdown</h4>
            </div>
            """, unsafe_allow_html=True)

            if not risk_breakdown['factors']:
                st.info("✅ No specific risk factors detected for this email.")
            else:
                for i, factor in enumerate(risk_breakdown['factors']):
                    if factor['score'] > 0:
                        # Color code based on factor score
                        if factor['score'] >= 20:
                            factor_color = "#dc3545"
                            factor_bg = "#f8d7da"
                            factor_icon = "🔴"
                            impact_level = "High Impact"
                        elif factor['score'] >= 10:
                            factor_color = "#fd7e14"
                            factor_bg = "#fff3cd"
                            factor_icon = "🟡"
                            impact_level = "Medium Impact"
                        else:
                            factor_color = "#17a2b8"
                            factor_bg = "#d1ecf1"
                            factor_icon = "🔵"
                            impact_level = "Low Impact"
                    else:
                        factor_color = "#28a745"
                        factor_bg = "#d4edda"
                        factor_icon = "✅"
                        impact_level = "Protective Factor"

                    st.markdown(f"""
                    <div style="background: {factor_bg}; padding: 1rem; border-radius: 8px; margin: 0.5rem 0; border-left: 3px solid {factor_color};">
                        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
                            <div style="display: flex; align-items: center;">
                                <span style="margin-right: 0.5rem;">{factor_icon}</span>
                                <strong style="color: {factor_color};">{factor['factor']}</strong>
                            </div>
                            <div style="display: flex; align-items: center;">
                                <span style="background: {factor_color}; color: white; padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; font-weight: bold;">
                                    {'+' if factor['score'] > 0 else ''}{factor['score']} pts
                                </span>
                                <span style="margin-left: 0.5rem; font-size: 0.8rem; color: {factor_color}; font-weight: 500;">
                                    {impact_level}
                                </span>
                            </div>
                        </div>
                        <p style="margin: 0; color: #495057; font-size: 0.9rem;">
                            {factor['description']}
                        </p>
                    </div>
                    """, unsafe_allow_html=True)

            # Professional legend
            st.markdown("""
            <div style="background: #f8f9fa; padding: 1.5rem; border-radius: 10px; margin: 1rem 0; border: 1px solid #dee2e6;">
                <h5 style="color: #495057; margin-bottom: 1rem;">📊 Risk Assessment Guide</h5>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
                    <div style="display: flex; align-items: center;">
                        <span style="margin-right: 0.5rem;">🔴</span>
                        <span style="font-size: 0.9rem;"><strong>High Impact (20+ pts)</strong> - Critical threats</span>
                    </div>
                    <div style="display: flex; align-items: center;">
                        <span style="margin-right: 0.5rem;">🟡</span>
                        <span style="font-size: 0.9rem;"><strong>Medium Impact (10-19 pts)</strong> - Moderate risks</span>
                    </div>
                    <div style="display: flex; align-items: center;">
                        <span style="margin-right: 0.5rem;">🔵</span>
                        <span style="font-size: 0.9rem;"><strong>Low Impact (1-9 pts)</strong> - Minor indicators</span>
                    </div>
                    <div style="display: flex; align-items: center;">
                        <span style="margin-right: 0.5rem;">✅</span>
                        <span style="font-size: 0.9rem;"><strong>Protective</strong> - Risk mitigation</span>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No emails match the current filters. Adjust filters to see risk analysis.")

def analytics_page(visualizer, anomaly_detector):
    st.header("📈 Advanced Analytics")

    if st.session_state.processed_data is None:
        st.warning("Please upload email data first in the Data Upload page.")
        return

    df = st.session_state.processed_data.copy()

    if st.session_state.risk_scores is not None:
        df['risk_score'] = st.session_state.risk_scores

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