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
    page_title="ExfilEye - Email Security Monitor",
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
    st.title("🔍 ExfilEye - Email Security Monitor")
    st.markdown("### AI-Powered Data Exfiltration Risk Detection")

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
    st.header("📊 Security Dashboard")

    if st.session_state.processed_data is None:
        st.warning("Please upload email data first in the Data Upload page.")
        return

    # Calculate risk scores
    if st.session_state.risk_scores is None:
        with st.spinner("Calculating risk scores..."):
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

    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        total_emails = len(df)
        st.metric("Total Emails", total_emails)

    with col2:
        high_risk = len(df[df['risk_level'] == 'High Risk'])
        st.metric("High Risk", high_risk, delta=f"{high_risk/total_emails*100:.1f}%")

    with col3:
        medium_risk = len(df[df['risk_level'] == 'Medium Risk'])
        st.metric("Medium Risk", medium_risk, delta=f"{medium_risk/total_emails*100:.1f}%")

    with col4:
        avg_risk = df['risk_score'].mean()
        st.metric("Avg Risk Score", f"{avg_risk:.1f}")

    # Risk level distribution chart
    col1, col2 = st.columns(2)

    with col1:
        risk_dist_fig = visualizer.create_risk_distribution_chart(df)
        st.plotly_chart(risk_dist_fig, use_container_width=True)

    with col2:
        timeline_fig = visualizer.create_timeline_chart(df)
        st.plotly_chart(timeline_fig, use_container_width=True)

    # Email Details with Risk Analysis - Suggested Views
    st.subheader("📧 Email Details with Risk Analysis — Suggested Views")

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

    # View 1: Emails Without Attachments
    st.subheader("📄 1. Emails Without Attachments")
    
    emails_no_attachments = df[~df['has_attachments_bool']]
    
    col1, col2 = st.columns([1, 3])
    with col1:
        st.metric("Count", len(emails_no_attachments))
    
    with col2:
        if len(emails_no_attachments) > 0:
            # Show sample data
            display_cols = ['time', 'sender', 'subject']
            available_cols = [col for col in display_cols if col in emails_no_attachments.columns]
            
            st.write("**Sample emails (showing first 10):**")
            sample_df = emails_no_attachments[available_cols].head(10)
            st.dataframe(sample_df, use_container_width=True)
        else:
            st.info("No emails without attachments found.")

    # View 2: High-Risk Emails (Red)
    st.subheader("🔴 2. High-Risk Emails")
    
    high_risk_emails = df[
        (df['has_attachments_bool']) & 
        (
            (df['has_last_working_day']) |  # Has last working day
            (df['word_match_score'] >= 3)   # High word match score
        )
    ].sort_values(['risk_score', 'time'], ascending=[False, False])
    
    col1, col2 = st.columns([1, 3])
    with col1:
        st.metric("Count", len(high_risk_emails))
    
    with col2:
        if len(high_risk_emails) > 0:
            # Display with highlighting
            display_cols = ['time', 'sender', 'recipients', 'subject', 'risk_score', 'last_working_day', 'word_list_match', 'attachments']
            available_cols = [col for col in display_cols if col in high_risk_emails.columns]
            
            def highlight_high_risk(row):
                styles = [''] * len(row)
                # Highlight last_working_day if present
                if 'last_working_day' in row.index and pd.notna(row['last_working_day']):
                    last_working_idx = row.index.get_loc('last_working_day')
                    styles[last_working_idx] = 'background-color: #ffcccc; color: #000000; font-weight: bold'
                # Highlight word_list_match if high score
                if 'word_list_match' in row.index:
                    word_match_idx = row.index.get_loc('word_list_match')
                    if pd.notna(row['word_list_match']) and str(row['word_list_match']).strip():
                        original_idx = row.name
                        if original_idx in df.index:
                            score = df.loc[original_idx, 'word_match_score']
                            if score >= 3:
                                styles[word_match_idx] = 'background-color: #ffcccc; color: #000000; font-weight: bold'
                return styles
            
            styled_high_risk = high_risk_emails[available_cols].style.apply(highlight_high_risk, axis=1)
            st.dataframe(styled_high_risk, use_container_width=True)
        else:
            st.info("No high-risk emails found.")

    # View 3: Medium-Risk Emails (Yellow)
    st.subheader("🟡 3. Medium-Risk Emails")
    
    medium_risk_emails = df[
        (df['has_attachments_bool']) & 
        (
            (df['has_last_working_day']) |  # Has last working day
            (df['word_match_score'] == 2)   # Medium word match score
        ) &
        (~df.index.isin(high_risk_emails.index))  # Exclude already classified as high risk
    ].sort_values(['risk_score', 'time'], ascending=[False, False])
    
    col1, col2 = st.columns([1, 3])
    with col1:
        st.metric("Count", len(medium_risk_emails))
    
    with col2:
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
            st.dataframe(styled_medium_risk, use_container_width=True)
        else:
            st.info("No medium-risk emails found.")

    # Risk breakdown section
    st.subheader("📊 Risk Factor Analysis")

    if len(df) > 0:
        # Select an email to analyze
        email_options = []
        for idx, row in df.iterrows():
            sender = row.get('sender', 'Unknown')
            subject = str(row.get('subject', 'No Subject'))[:50]
            risk_score = row.get('risk_score', 0)
            email_options.append(f"{sender} - {subject}... (Score: {risk_score:.1f})")

        selected_email_idx = st.selectbox(
            "Select an email to see detailed risk breakdown:",
            range(len(email_options)),
            format_func=lambda x: email_options[x]
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

            # Display risk breakdown
            col1, col2 = st.columns([1, 2])

            with col1:
                st.metric("Total Risk Score", f"{risk_breakdown['total_score']:.1f}")

                risk_level = risk_engine.get_risk_level(risk_breakdown['total_score'])
                if risk_level == 'High Risk':
                    st.error(f"🔴 **{risk_level}**")
                    st.write("**Explanation:** This email exhibits multiple high-risk patterns that may indicate potential data exfiltration.")
                elif risk_level == 'Medium Risk':
                    st.warning(f"🟡 **{risk_level}**")
                    st.write("**Explanation:** This email shows some concerning patterns that warrant monitoring and review.")
                else:
                    st.success(f"🟢 **{risk_level}**")
                    st.write("**Explanation:** This email appears to follow normal communication patterns with minimal risk indicators.")

            with col2:
                st.write("**Risk Factors Detected:**")

                if not risk_breakdown['factors']:
                    st.info("No specific risk factors detected for this email.")
                else:
                    for factor in risk_breakdown['factors']:
                        if factor['score'] > 0:
                            # Color code based on factor score
                            if factor['score'] >= 20:
                                st.error(f"🔴 **{factor['factor']}** (+{factor['score']} points)")
                            elif factor['score'] >= 10:
                                st.warning(f"🟡 **{factor['factor']}** (+{factor['score']} points)")
                            else:
                                st.info(f"🔵 **{factor['factor']}** (+{factor['score']} points)")

                            st.write(f"   ↳ {factor['description']}")
                        else:
                            st.success(f"✅ **{factor['factor']}**")
                            st.write(f"   ↳ {factor['description']}")

                # Risk factor legend
                st.write("---")
                st.write("**Risk Factor Legend:**")
                st.write("🔴 High Impact (20+ points) - Significant risk indicators")
                st.write("🟡 Medium Impact (10-19 points) - Moderate risk indicators") 
                st.write("🔵 Low Impact (1-9 points) - Minor risk indicators")
                st.write("✅ Protective Factor - Reduces or negates risk")
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