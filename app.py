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
        ["📁 Data Upload", "📊 Dashboard", "📈 Analytics", "🌐 Network View", "📧 Follow-up Actions", "🔄 App Flow Dashboard"]
    )

    if page == "📁 Data Upload":
        data_upload_page(data_processor, domain_classifier, keyword_detector)
    elif page == "📊 Dashboard":
        dashboard_page(risk_engine, anomaly_detector, visualizer)
    elif page == "📈 Analytics":
        analytics_page(visualizer, anomaly_detector)
    elif page == "🌐 Network View":

    elif page == "🔄 App Flow Dashboard":
        app_flow_dashboard_page()

        network_view_page(visualizer)
    elif page == "📧 Follow-up Actions":
        follow_up_actions_page(email_generator)

def network_view_page(visualizer):
    st.header("🌐 Network View - Domain Analysis")
    
    if st.session_state.processed_data is None:
        st.warning("Please upload email data first in the Data Upload page.")
        return
    
    df = st.session_state.processed_data.copy()
    
    if st.session_state.risk_scores is not None:
        df['risk_score'] = st.session_state.risk_scores
        df['risk_level'] = df['risk_score'].apply(lambda x: 
            'High' if x >= 61 else 'Medium' if x >= 31 else 'Low'
        )
    
    # Navigation tabs for different views
    tab1, tab2 = st.tabs(["🏢 Domain Classification Analysis", "📧 Non-Standard Domain Analysis"])
    
    with tab1:
        st.subheader("📊 Complete Domain Classification Overview")
        st.info("🎯 **Purpose:** Comprehensive analysis of all email domains categorized by business type, free email providers, and industry sectors.")
        
        # Initialize domain classifier
        from utils.domain_classifier import DomainClassifier
        domain_classifier = DomainClassifier()
        
        # Ensure we have email_domain field
        if 'email_domain' not in df.columns:
            df['email_domain'] = df['sender'].apply(lambda x: str(x).split('@')[-1].lower().strip() if pd.notna(x) and '@' in str(x) else '')
        
        # Apply domain classification if not already done (this will now include internal detection)
        if 'email_domain_type' not in df.columns:
            df = domain_classifier.classify_domains(df)
        
        # Debug: Show sample classification results
        if st.sidebar.button("🔍 Debug Domain Classification"):
            st.write("**Debug: Sample Domain Classification Results**")
            debug_cols = ['sender', 'email_domain', 'recipients', 'recipient_domain', 'email_domain_type']
            available_cols = [col for col in debug_cols if col in df.columns]
            st.dataframe(df[available_cols].head(10), use_container_width=True)
        
        # Overall Statistics
        st.subheader("📈 Domain Type Distribution")
        
        # Get domain type counts
        domain_type_counts = df['email_domain_type'].value_counts()
        total_emails = len(df)
        
        # Create metrics row
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            business_count = domain_type_counts.get('business', 0)
            business_pct = (business_count / total_emails * 100) if total_emails > 0 else 0
            st.metric("🏢 Business Domains", f"{business_count:,}", f"{business_pct:.1f}%")
        
        with col2:
            free_count = domain_type_counts.get('free', 0)
            free_pct = (free_count / total_emails * 100) if total_emails > 0 else 0
            st.metric("📧 Free Email Domains", f"{free_count:,}", f"{free_pct:.1f}%")
        
        with col3:
            internal_count = domain_type_counts.get('internal', 0)
            internal_pct = (internal_count / total_emails * 100) if total_emails > 0 else 0
            st.metric("🏠 Internal Domains", f"{internal_count:,}", f"{internal_pct:.1f}%")
        
        with col4:
            public_count = domain_type_counts.get('public', 0)
            public_pct = (public_count / total_emails * 100) if total_emails > 0 else 0
            st.metric("🌐 Public Domains", f"{public_count:,}", f"{public_pct:.1f}%")
        
        with col5:
            unknown_count = domain_type_counts.get('unknown', 0)
            unknown_pct = (unknown_count / total_emails * 100) if total_emails > 0 else 0
            st.metric("❓ Unknown Domains", f"{unknown_count:,}", f"{unknown_pct:.1f}%")
        
        # Visual Distribution Chart
        st.subheader("📊 Domain Type Visualization")
        
        # Create distribution charts
        import plotly.express as px
        import plotly.graph_objects as go
        from plotly.subplots import make_subplots
        
        # Prepare data for charts
        domain_labels = []
        domain_values = []
        domain_colors = []
        
        color_map = {
            'business': '#2E8B57',      # Sea Green
            'free': '#DC143C',          # Crimson  
            'internal': '#4169E1',      # Royal Blue
            'public': '#FF8C00',        # Dark Orange
            'unknown': '#708090'        # Slate Gray
        }
        
        for domain_type, count in domain_type_counts.items():
            if count > 0:
                percentage = (count / total_emails * 100)
                domain_labels.append(f"{domain_type.title()} ({count:,} - {percentage:.1f}%)")
                domain_values.append(count)
                domain_colors.append(color_map.get(domain_type, '#708090'))
        
        # Create subplot with pie chart and bar chart
        fig = make_subplots(
            rows=1, cols=2,
            specs=[[{"type": "domain"}, {"type": "xy"}]],
            subplot_titles=("Distribution by Count", "Distribution by Percentage"),
            column_widths=[0.5, 0.5]
        )
        
        # Add pie chart
        fig.add_trace(
            go.Pie(
                labels=domain_labels,
                values=domain_values,
                marker_colors=domain_colors,
                textinfo='label+percent',
                textposition='auto',
                hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
            ),
            row=1, col=1
        )
        
        # Add bar chart
        fig.add_trace(
            go.Bar(
                x=[label.split(' (')[0] for label in domain_labels],
                y=[(val/total_emails*100) for val in domain_values],
                marker_color=domain_colors,
                text=[f"{val/total_emails*100:.1f}%" for val in domain_values],
                textposition='auto',
                hovertemplate='<b>%{x}</b><br>Percentage: %{y:.1f}%<br>Count: %{customdata}<extra></extra>',
                customdata=domain_values
            ),
            row=1, col=2
        )
        
        # Update layout
        fig.update_layout(
            title_text="Email Domain Distribution Analysis",
            title_x=0.5,
            height=500,
            showlegend=False
        )
        
        # Update bar chart axes
        fig.update_xaxes(title_text="Domain Type", row=1, col=2)
        fig.update_yaxes(title_text="Percentage (%)", row=1, col=2)
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Detailed Domain Analysis by Type
        st.subheader("🔍 Detailed Domain Analysis by Type")
        
        # Create tabs for each domain type
        domain_tabs = st.tabs(["🏢 Business", "📧 Free Email", "🏠 Internal", "🌐 Public", "❓ Unknown"])
        
        with domain_tabs[0]:  # Business Domains
            business_domains_df = df[df['email_domain_type'] == 'business']
            if not business_domains_df.empty:
                st.write(f"**{len(business_domains_df):,} emails from business domains**")
                
                # Industry breakdown
                if 'email_domain_industry' in business_domains_df.columns:
                    industry_counts = business_domains_df['email_domain_industry'].value_counts()
                    
                    st.write("**Industry Distribution:**")
                    industry_col1, industry_col2, industry_col3 = st.columns(3)
                    
                    with industry_col1:
                        banking_count = industry_counts.get('banking', 0)
                        st.metric("🏦 Banking/Financial", banking_count)
                        
                        education_count = industry_counts.get('education', 0)
                        st.metric("🎓 Education", education_count)
                    
                    with industry_col2:
                        healthcare_count = industry_counts.get('healthcare', 0)
                        st.metric("🏥 Healthcare", healthcare_count)
                        
                        tech_count = industry_counts.get('technology', 0)
                        st.metric("💻 Technology", tech_count)
                    
                    with industry_col3:
                        gov_count = industry_counts.get('government', 0)
                        st.metric("🏛️ Government", gov_count)
                        
                        other_count = industry_counts.get('business_other', 0)
                        st.metric("🏢 Other Business", other_count)
                
                # Top business domains
                top_business_domains = business_domains_df['email_domain'].value_counts().head(15)
                
                business_display = []
                for rank, (domain, count) in enumerate(top_business_domains.items(), 1):
                    percentage = (count / len(business_domains_df) * 100)
                    industry = business_domains_df[business_domains_df['email_domain'] == domain]['email_domain_industry'].iloc[0] if 'email_domain_industry' in business_domains_df.columns else 'Unknown'
                    
                    business_display.append({
                        'Rank': f"#{rank}",
                        'Domain': domain,
                        'Email Count': f"{count:,}",
                        'Percentage': f"{percentage:.1f}%",
                        'Industry': industry.replace('_', ' ').title()
                    })
                
                if business_display:
                    business_df = pd.DataFrame(business_display)
                    st.dataframe(business_df, use_container_width=True, height=400)
            else:
                st.info("No business domains found in the dataset")
        
        with domain_tabs[1]:  # Free Email Domains
            free_domains_df = df[df['email_domain_type'] == 'free']
            if not free_domains_df.empty:
                st.write(f"**{len(free_domains_df):,} emails from free email domains**")
                
                # Security analysis for free domains
                if 'risk_score' in free_domains_df.columns:
                    avg_risk = free_domains_df['risk_score'].mean()
                    high_risk_count = len(free_domains_df[free_domains_df['risk_score'] >= 61])
                    
                    risk_col1, risk_col2, risk_col3 = st.columns(3)
                    with risk_col1:
                        st.metric("Average Risk Score", f"{avg_risk:.1f}/100")
                    with risk_col2:
                        st.metric("High Risk Emails", high_risk_count)
                    with risk_col3:
                        risk_pct = (high_risk_count / len(free_domains_df) * 100) if len(free_domains_df) > 0 else 0
                        st.metric("High Risk %", f"{risk_pct:.1f}%")
                
                # Top free email domains
                top_free_domains = free_domains_df['email_domain'].value_counts().head(15)
                
                free_display = []
                for rank, (domain, count) in enumerate(top_free_domains.items(), 1):
                    percentage = (count / len(free_domains_df) * 100)
                    domain_data = free_domains_df[free_domains_df['email_domain'] == domain]
                    avg_risk = domain_data['risk_score'].mean() if 'risk_score' in domain_data.columns else 0
                    
                    free_display.append({
                        'Rank': f"#{rank}",
                        'Domain': domain,
                        'Email Count': f"{count:,}",
                        'Percentage': f"{percentage:.1f}%",
                        'Avg Risk Score': f"{avg_risk:.1f}/100"
                    })
                
                if free_display:
                    free_df = pd.DataFrame(free_display)
                    
                    # Color code based on risk
                    def highlight_free_risk(row):
                        styles = [''] * len(row)
                        try:
                            risk_score = float(str(row['Avg Risk Score']).split('/')[0])
                            if risk_score >= 61:
                                styles[4] = 'background-color: #ffebee; color: #c62828; font-weight: bold'
                            elif risk_score >= 31:
                                styles[4] = 'background-color: #fff3e0; color: #ef6c00; font-weight: bold'
                        except:
                            pass
                        return styles
                    
                    styled_free_df = free_df.style.apply(highlight_free_risk, axis=1)
                    st.dataframe(styled_free_df, use_container_width=True, height=400)
            else:
                st.info("No free email domains found in the dataset")
        
        with domain_tabs[2]:  # Internal Domains
            internal_domains_df = df[df['email_domain_type'] == 'internal']
            if not internal_domains_df.empty:
                st.write(f"**{len(internal_domains_df):,} emails from internal domains**")
                st.info("ℹ️ **Internal Domain Definition:** Emails where the sender domain matches the recipient domain field, indicating internal organizational communication.")
                
                # Internal domain analysis with sender-recipient matching details
                top_internal_domains = internal_domains_df['email_domain'].value_counts().head(10)
                
                internal_display = []
                for rank, (domain, count) in enumerate(top_internal_domains.items(), 1):
                    percentage = (count / len(internal_domains_df) * 100)
                    
                    # Get unique senders and recipients for this domain
                    domain_data = internal_domains_df[internal_domains_df['email_domain'] == domain]
                    unique_senders = domain_data['sender'].nunique()
                    
                    # Count recipient instances of this domain using recipient_domain field
                    recipient_matches = 0
                    for _, row in domain_data.iterrows():
                        # Primary check: Use recipient_domain field
                        recipient_domain = row.get('recipient_domain', '')
                        if recipient_domain and domain == recipient_domain.lower().strip():
                            recipient_matches += 1
                        else:
                            # Fallback: Check recipient_domains list
                            recipient_domains = row.get('recipient_domains', [])
                            if isinstance(recipient_domains, list) and domain in recipient_domains:
                                recipient_matches += 1
                    
                    internal_display.append({
                        'Rank': f"#{rank}",
                        'Domain': domain,
                        'Email Count': f"{count:,}",
                        'Percentage': f"{percentage:.1f}%",
                        'Unique Senders': unique_senders,
                        'Sender-Recipient Matches': recipient_matches
                    })
                
                if internal_display:
                    internal_df = pd.DataFrame(internal_display)
                    st.dataframe(internal_df, use_container_width=True, height=300)
                    
                    # Additional insights for internal communications
                    st.write("**Internal Communication Insights:**")
                    total_internal_senders = internal_domains_df['sender'].nunique()
                    avg_emails_per_sender = len(internal_domains_df) / total_internal_senders if total_internal_senders > 0 else 0
                    
                    insights_col1, insights_col2 = st.columns(2)
                    with insights_col1:
                        st.write(f"• **Total Internal Senders:** {total_internal_senders:,}")
                        st.write(f"• **Avg Emails per Sender:** {avg_emails_per_sender:.1f}")
                    
                    with insights_col2:
                        # Show top internal communicating domain
                        if len(top_internal_domains) > 0:
                            top_domain = top_internal_domains.index[0]
                            top_count = top_internal_domains.iloc[0]
                            st.write(f"• **Most Active Domain:** {top_domain}")
                            st.write(f"• **Internal Emails:** {top_count:,}")
            else:
                st.info("No internal domains found in the dataset")
                st.write("**What this means:** No emails were detected where the sender domain matches the recipient domain field value.")
        
        with domain_tabs[3]:  # Public Domains
            public_domains_df = df[df['email_domain_type'] == 'public']
            if not public_domains_df.empty:
                st.write(f"**{len(public_domains_df):,} emails from public domains**")
                
                # Public domain analysis
                top_public_domains = public_domains_df['email_domain'].value_counts().head(10)
                
                public_display = []
                for rank, (domain, count) in enumerate(top_public_domains.items(), 1):
                    percentage = (count / len(public_domains_df) * 100)
                    domain_data = public_domains_df[public_domains_df['email_domain'] == domain]
                    avg_risk = domain_data['risk_score'].mean() if 'risk_score' in domain_data.columns else 0
                    
                    public_display.append({
                        'Rank': f"#{rank}",
                        'Domain': domain,
                        'Email Count': f"{count:,}",
                        'Percentage': f"{percentage:.1f}%",
                        'Avg Risk Score': f"{avg_risk:.1f}/100"
                    })
                
                if public_display:
                    public_df = pd.DataFrame(public_display)
                    st.dataframe(public_df, use_container_width=True, height=300)
            else:
                st.info("No public domains found in the dataset")
        
        with domain_tabs[4]:  # Unknown Domains
            unknown_domains_df = df[df['email_domain_type'] == 'unknown']
            if not unknown_domains_df.empty:
                st.write(f"**{len(unknown_domains_df):,} emails from unknown domains**")
                st.warning("⚠️ Unknown domains require investigation to determine their classification")
                
                # Unknown domain analysis
                top_unknown_domains = unknown_domains_df['email_domain'].value_counts().head(10)
                
                unknown_display = []
                for rank, (domain, count) in enumerate(top_unknown_domains.items(), 1):
                    percentage = (count / len(unknown_domains_df) * 100)
                    domain_data = unknown_domains_df[unknown_domains_df['email_domain'] == domain]
                    avg_risk = domain_data['risk_score'].mean() if 'risk_score' in domain_data.columns else 0
                    
                    unknown_display.append({
                        'Rank': f"#{rank}",
                        'Domain': domain,
                        'Email Count': f"{count:,}",
                        'Percentage': f"{percentage:.1f}%",
                        'Avg Risk Score': f"{avg_risk:.1f}/100"
                    })
                
                if unknown_display:
                    unknown_df = pd.DataFrame(unknown_display)
                    st.dataframe(unknown_df, use_container_width=True, height=300)
            else:
                st.success("✅ All domains have been classified")
        
        # Domain Security Summary
        st.subheader("🔒 Domain Security Summary")
        
        security_col1, security_col2 = st.columns(2)
        
        with security_col1:
            st.write("**Security Risk Assessment:**")
            
            # Calculate security metrics
            if 'risk_score' in df.columns:
                high_risk_business = len(df[(df['email_domain_type'] == 'business') & (df['risk_score'] >= 61)])
                high_risk_free = len(df[(df['email_domain_type'] == 'free') & (df['risk_score'] >= 61)])
                high_risk_unknown = len(df[(df['email_domain_type'] == 'unknown') & (df['risk_score'] >= 61)])
                
                st.write(f"• High-risk business domains: **{high_risk_business}** emails")
                st.write(f"• High-risk free email domains: **{high_risk_free}** emails")
                st.write(f"• High-risk unknown domains: **{high_risk_unknown}** emails")
                
                total_high_risk = high_risk_business + high_risk_free + high_risk_unknown
                if total_high_risk > 0:
                    st.error(f"🚨 **{total_high_risk}** total high-risk emails require attention")
                else:
                    st.success("✅ No high-risk domain communications detected")
        
        with security_col2:
            st.write("**Recommendations:**")
            
            # Provide recommendations based on analysis
            if free_count > business_count:
                st.warning("⚠️ High volume of free email communications detected")
                st.write("• Review free email domain policies")
                st.write("• Consider additional monitoring for free domains")
            
            if unknown_count > 0:
                st.warning("⚠️ Unknown domains require classification")
                st.write("• Investigate unknown domain origins")
                st.write("• Update domain classification rules")
            
            if public_count > 0:
                st.info("ℹ️ Public domains detected")
                st.write("• Verify legitimacy of public domain communications")
                st.write("• Consider domain whitelist updates")
    
    with tab2:
        st.subheader("📧 Non-Standard Domain Analysis")
        st.info("🎯 **Purpose:** Identify emails sent to domains that are neither business domains nor free email domains to assess Business-As-Usual (BAU) patterns and detect potential anomalies.")
    
    # Initialize domain classifier
    from utils.domain_classifier import DomainClassifier
    domain_classifier = DomainClassifier()
    
    # Prepare recipient domains for analysis - prioritize recipient_domain field
    if 'recipient_domain' in df.columns:
        # Use recipient_domain field as primary source
        def get_recipient_domains_from_field(row):
            recipient_domain = row.get('recipient_domain', '')
            if pd.notna(recipient_domain) and recipient_domain.strip():
                return [recipient_domain.strip().lower()]
            
            # Fallback to extracting from recipients field
            recipients_str = row.get('recipients', '')
            if pd.isna(recipients_str):
                return []
            domains = []
            import re
            emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', str(recipients_str))
            for email in emails:
                domain = email.split('@')[-1].lower()
                domains.append(domain)
            return list(set(domains))  # Remove duplicates
        
        df['recipient_domains'] = df.apply(get_recipient_domains_from_field, axis=1)
    elif 'recipient_domains' not in df.columns:
        # Extract from recipients field as fallback
        def extract_domains_from_recipients(recipients_str):
            if pd.isna(recipients_str):
                return []
            domains = []
            # Split by common delimiters and extract domains
            import re
            emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', str(recipients_str))
            for email in emails:
                domain = email.split('@')[-1].lower()
                domains.append(domain)
            return list(set(domains))  # Remove duplicates
        
        df['recipient_domains'] = df['recipients'].apply(extract_domains_from_recipients)
    
    # Classify all unique recipient domains
    all_recipient_domains = set()
    for domains_list in df['recipient_domains'].dropna():
        if isinstance(domains_list, list):
            all_recipient_domains.update(domains_list)
        elif isinstance(domains_list, str):
            # Handle case where it might be a string
            all_recipient_domains.add(domains_list)
    
    # Classify domains
    domain_classifications = {}
    for domain in all_recipient_domains:
        if domain:
            classification = domain_classifier._classify_single_domain(domain)
            domain_classifications[domain] = classification
    
    # Filter emails with recipient domains that are neither business nor free
    def has_non_standard_domains(domains_list):
        if not isinstance(domains_list, list):
            return False
        
        for domain in domains_list:
            classification = domain_classifications.get(domain, 'unknown')
            if classification not in ['business', 'free']:
                return True
        return False
    
    # Get emails with non-standard recipient domains
    non_standard_emails = df[df['recipient_domains'].apply(has_non_standard_domains)].copy()
    
    # Add domain classification details
    def get_non_standard_domains(domains_list):
        non_standard = []
        if isinstance(domains_list, list):
            for domain in domains_list:
                classification = domain_classifications.get(domain, 'unknown')
                if classification not in ['business', 'free']:
                    non_standard.append(f"{domain} ({classification})")
        return "; ".join(non_standard)
    
    non_standard_emails['non_standard_domains'] = non_standard_emails['recipient_domains'].apply(get_non_standard_domains)
    
    # Statistics Overview
    st.subheader("📊 Domain Classification Overview")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_emails = len(df)
        st.metric("Total Emails", f"{total_emails:,}")
    
    with col2:
        business_count = sum(1 for d in domain_classifications.values() if d == 'business')
        st.metric("Business Domains", business_count)
    
    with col3:
        free_count = sum(1 for d in domain_classifications.values() if d == 'free')
        st.metric("Free Email Domains", free_count)
    
    with col4:
        non_standard_count = sum(1 for d in domain_classifications.values() if d not in ['business', 'free'])
        st.metric("Non-Standard Domains", non_standard_count)
    
    # Main Analysis Results
    st.subheader("🔍 Emails to Non-Standard Domains")
    
    if len(non_standard_emails) > 0:
        st.write(f"**Found {len(non_standard_emails)} emails sent to domains that are neither business nor free email domains**")
        
        # Summary metrics
        col1, col2, col3 = st.columns(3)
        
        with col1:
            unique_senders = non_standard_emails['sender'].nunique()
            st.metric("Unique Senders", unique_senders)
        
        with col2:
            avg_risk = non_standard_emails['risk_score'].mean() if 'risk_score' in non_standard_emails.columns else 0
            st.metric("Average Risk Score", f"{avg_risk:.1f}")
        
        with col3:
            if 'risk_level' in non_standard_emails.columns:
                high_risk_count = len(non_standard_emails[non_standard_emails['risk_level'] == 'High'])
            else:
                high_risk_count = 0
            st.metric("High Risk Emails", high_risk_count)
        
        # Detailed table
        st.subheader("📋 Detailed Analysis")
        
        # Prepare display data
        display_data = []
        for idx, (_, row) in enumerate(non_standard_emails.iterrows()):
            # Format time
            time_str = str(row.get('time', 'N/A'))
            if 'T' in time_str:
                time_str = time_str.split('T')[0] + ' ' + time_str.split('T')[1][:8]
            
            display_data.append({
                '#': idx + 1,
                'Date/Time': time_str,
                'Sender': str(row.get('sender', 'Unknown'))[:40] + ('...' if len(str(row.get('sender', ''))) > 40 else ''),
                'Subject': str(row.get('subject', 'No Subject'))[:50] + ('...' if len(str(row.get('subject', ''))) > 50 else ''),
                'Non-Standard Domains': str(row.get('non_standard_domains', ''))[:60] + ('...' if len(str(row.get('non_standard_domains', ''))) > 60 else ''),
                'Risk Score': f"{row.get('risk_score', 0):.1f}/100" if row.get('risk_score') else 'N/A',
                'Risk Level': str(row.get('risk_level', 'N/A')),
                'Business Unit': str(row.get('bunit', 'N/A'))[:20] + ('...' if len(str(row.get('bunit', ''))) > 20 else ''),
                'Department': str(row.get('department', 'N/A'))[:20] + ('...' if len(str(row.get('department', ''))) > 20 else '')
            })
        
        # Create dataframe and apply styling
        display_df = pd.DataFrame(display_data)
        
        # Color coding based on risk level
        def highlight_risk(row):
            styles = [''] * len(row)
            risk_level = str(row.get('Risk Level', ''))
            if 'High' in risk_level:
                # Highlight risk level column in red
                risk_idx = row.index.get_loc('Risk Level') if 'Risk Level' in row.index else -1
                if risk_idx >= 0:
                    styles[risk_idx] = 'background-color: #ffebee; color: #c62828; font-weight: bold'
                # Highlight risk score in red
                score_idx = row.index.get_loc('Risk Score') if 'Risk Score' in row.index else -1
                if score_idx >= 0:
                    styles[score_idx] = 'background-color: #ffebee; color: #c62828; font-weight: bold'
            elif 'Medium' in risk_level:
                risk_idx = row.index.get_loc('Risk Level') if 'Risk Level' in row.index else -1
                if risk_idx >= 0:
                    styles[risk_idx] = 'background-color: #fff3e0; color: #ef6c00; font-weight: bold'
            
            # Highlight non-standard domains column
            domain_idx = row.index.get_loc('Non-Standard Domains') if 'Non-Standard Domains' in row.index else -1
            if domain_idx >= 0:
                styles[domain_idx] = 'background-color: #e3f2fd; color: #1565c0; font-weight: bold'
            
            return styles
        
        styled_df = display_df.style.apply(highlight_risk, axis=1)
        st.dataframe(styled_df, use_container_width=True, height=500)
        
        # Domain Analysis
        st.subheader("🌐 Non-Standard Domain Analysis")
        
        # Count occurrences of each non-standard domain
        domain_counts = {}
        for domains_str in non_standard_emails['non_standard_domains']:
            if pd.notna(domains_str) and str(domains_str).strip():
                domains = str(domains_str).split(';')
                for domain_info in domains:
                    domain_info = domain_info.strip()
                    if domain_info:
                        # Extract domain name (before parentheses)
                        domain_name = domain_info.split('(')[0].strip()
                        domain_counts[domain_name] = domain_counts.get(domain_name, 0) + 1
        
        if domain_counts:
            # Sort by frequency
            sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Top Non-Standard Domains by Frequency:**")
                domain_freq_data = []
                for rank, (domain, count) in enumerate(sorted_domains[:15], 1):
                    classification = domain_classifications.get(domain, 'unknown')
                    percentage = (count / len(non_standard_emails) * 100)
                    
                    domain_freq_data.append({
                        'Rank': f"#{rank}",
                        'Domain': domain,
                        'Classification': classification.title(),
                        'Email Count': count,
                        'Percentage': f"{percentage:.1f}%"
                    })
                
                freq_df = pd.DataFrame(domain_freq_data)
                st.dataframe(freq_df, use_container_width=True, height=400)
            
            with col2:
                st.write("**Domain Classification Breakdown:**")
                classification_counts = {}
                for domain in domain_counts.keys():
                    classification = domain_classifications.get(domain, 'unknown')
                    classification_counts[classification] = classification_counts.get(classification, 0) + 1
                
                for classification, count in sorted(classification_counts.items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / len(domain_counts) * 100)
                    st.write(f"• **{classification.title()}**: {count} domains ({percentage:.1f}%)")
                
                st.write("**Business Assessment:**")
                if 'internal' in classification_counts:
                    st.success(f"✅ {classification_counts['internal']} internal domains detected - likely BAU")
                if 'public' in classification_counts:
                    st.warning(f"⚠️ {classification_counts['public']} public domains - review for legitimacy")
                if 'unknown' in classification_counts:
                    st.error(f"❗ {classification_counts['unknown']} unknown domains - requires investigation")
        
        # BAU Assessment
        st.subheader("📈 Business-As-Usual Assessment")
        
        # Analyze patterns to determine if this is normal business activity
        assessment_points = []
        
        # Check sender patterns
        sender_counts = non_standard_emails['sender'].value_counts()
        if len(sender_counts) > 0:
            most_active_sender = sender_counts.iloc[0]
            if most_active_sender > len(non_standard_emails) * 0.5:
                assessment_points.append(f"⚠️ Single sender ({sender_counts.index[0]}) responsible for {most_active_sender} emails ({most_active_sender/len(non_standard_emails)*100:.1f}%)")
            else:
                assessment_points.append(f"✅ Distributed sender pattern - {len(sender_counts)} unique senders")
        
        # Check business unit distribution
        if 'bunit' in non_standard_emails.columns:
            bunit_counts = non_standard_emails['bunit'].value_counts()
            if len(bunit_counts) > 0:
                assessment_points.append(f"📊 Activity across {len(bunit_counts)} business units")
                if len(bunit_counts) >= 3:
                    assessment_points.append("✅ Multi-unit activity suggests legitimate business operations")
        
        # Check time patterns
        if 'time' in non_standard_emails.columns:
            time_analysis = non_standard_emails.copy()
            time_analysis['hour'] = pd.to_datetime(time_analysis['time'], errors='coerce').dt.hour
            business_hours = len(time_analysis[(time_analysis['hour'] >= 9) & (time_analysis['hour'] <= 17)])
            business_hours_pct = (business_hours / len(time_analysis) * 100) if len(time_analysis) > 0 else 0
            
            if business_hours_pct >= 70:
                assessment_points.append(f"✅ {business_hours_pct:.1f}% during business hours - normal pattern")
            else:
                assessment_points.append(f"⚠️ Only {business_hours_pct:.1f}% during business hours - investigate timing")
        
        # Display assessment
        st.write("**Assessment Results:**")
        for point in assessment_points:
            st.write(point)
        
        # Overall recommendation
        if len(assessment_points) > 0:
            warning_count = sum(1 for point in assessment_points if '⚠️' in point or '❗' in point)
            if warning_count == 0:
                st.success("🎯 **Assessment: Likely Business-As-Usual** - Patterns indicate normal business operations")
            elif warning_count <= len(assessment_points) / 2:
                st.warning("🔍 **Assessment: Mixed Indicators** - Some patterns warrant closer review")
            else:
                st.error("🚨 **Assessment: Potential Anomaly** - Multiple risk indicators detected")
    
    else:
        st.success("✅ **All emails are sent to either business domains or free email domains**")
        st.info("This indicates that all communications follow standard business patterns to recognized domain types.")
        
        # Show breakdown of standard domains
        st.subheader("📊 Standard Domain Distribution")
        
        business_emails = 0
        free_emails = 0
        
        for _, row in df.iterrows():
            domains_list = row.get('recipient_domains', [])
            if isinstance(domains_list, list):
                for domain in domains_list:
                    classification = domain_classifications.get(domain, 'unknown')
                    if classification == 'business':
                        business_emails += 1
                    elif classification == 'free':
                        free_emails += 1
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Business Domain Communications", business_emails)
        with col2:
            st.metric("Free Email Communications", free_emails)

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

    # Email Domain Classification Section
    st.markdown("""
    <div style="background: linear-gradient(90deg, #e3f2fd 0%, #bbdefb 100%); padding: 1.5rem; border-radius: 10px; margin: 2rem 0 1rem 0; border-left: 5px solid #1976d2;">
        <h2 style="margin: 0; color: #1976d2; font-size: 1.8rem; font-weight: 600;">
            🌐 Email Domain Classification
        </h2>
        <p style="margin: 0.5rem 0 0 0; color: #424242; font-size: 1rem;">
            Distribution of email traffic by domain type and security classification
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Domain Type Distribution Metrics
    domain_type_counts = df['email_domain_type'].value_counts()
    
    # Get top domain categories for display
    top_categories = domain_type_counts.head(6)
    
    # Create dynamic columns based on categories
    num_cols = min(len(top_categories), 6)
    cols = st.columns(num_cols)
    
    # Define colors for different categories
    category_colors = {
        'business': ('#2E8B57', '#f0fff4', '🏢'),
        'internal': ('#4169E1', '#f0f8ff', '🏠'),
        'Major Email Providers': ('#DC143C', '#fff5f5', '📧'),
        'Microsoft Email Domains': ('#0078D4', '#f0f8ff', '🔷'),
        'Google Email Domains': ('#4285F4', '#e8f0fe', '🔍'),
        'Yahoo Email Domains': ('#720E9E', '#f5f0ff', '📮'),
        'Disposable Email Services': ('#FF6B35', '#fff8f0', '🗑️'),
        'Educational (but free)': ('#28a745', '#f0fff4', '🎓'),
        'Privacy-Focused Email': ('#6F42C1', '#f8f0ff', '🔒'),
        'European Email Providers': ('#FD7E14', '#fff8f0', '🌍'),
        'Asian Email Providers': ('#20C997', '#f0fff8', '🌏'),
        'Other Free Email Providers': ('#E83E8C', '#fff5f8', '📬'),
        'unknown': ('#708090', '#f8f8ff', '❓'),
        'public': ('#FF8C00', '#fff8f0', '🌐')
    }
    
    for idx, (category, count) in enumerate(top_categories.items()):
        if idx < len(cols):
            with cols[idx]:
                color, bg_color, icon = category_colors.get(category, ('#666666', '#f0f0f0', '📁'))
                pct = (count / total_emails * 100) if total_emails > 0 else 0
                
                # Truncate long category names for display
                display_name = category if len(category) <= 15 else category[:12] + '...'
                
                st.markdown(f"""
                <div class="metric-card" style="border-left-color: {color}; background-color: {bg_color};">
                    <p class="metric-label">{display_name}</p>
                    <p class="metric-value" style="color: {color};">{count:,}</p>
                    <p class="metric-delta" style="color: {color};">{icon} {pct:.1f}% of total</p>
                </div>
                """, unsafe_allow_html=True)

    # Domain Classification Visualization
    if len(domain_type_counts) > 0:
        import plotly.graph_objects as go
        
        # Prepare data for visualization
        domain_colors = {
            'business': '#2E8B57',
            'internal': '#4169E1',
            'Major Email Providers': '#DC143C',
            'Microsoft Email Domains': '#0078D4',
            'Google Email Domains': '#4285F4',
            'Yahoo Email Domains': '#720E9E',
            'Disposable Email Services': '#FF6B35',
            'Educational (but free)': '#28a745',
            'Privacy-Focused Email': '#6F42C1',
            'European Email Providers': '#FD7E14',
            'Asian Email Providers': '#20C997',
            'Other Free Email Providers': '#E83E8C',
            'public': '#FF8C00',
            'unknown': '#708090'
        }
        
        colors = [domain_colors.get(dtype, '#708090') for dtype in domain_type_counts.index]
        
        # Create donut chart
        fig_domain = go.Figure(data=[go.Pie(
            labels=[f"{dtype.title()}<br>({count:,})" for dtype, count in domain_type_counts.items()],
            values=domain_type_counts.values,
            hole=0.4,
            marker_colors=colors,
            textinfo='label+percent',
            textposition='auto',
            hovertemplate='<b>%{label}</b><br>Percentage: %{percent}<br>Count: %{value}<extra></extra>'
        )])
        
        fig_domain.update_layout(
            title="Email Distribution by Domain Type",
            title_x=0.5,
            height=400,
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
        )
        
        st.plotly_chart(fig_domain, use_container_width=True)

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
            High risk indicators: Emails with attachments, leaver to free email domains
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
            Emailswith attachments and sensitive keywords, sent to non-free domains (no leaver status)
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
        ["Overview", "Anomaly Detection", "Risk Analysis", "Domain Analysis", "Security Tool Coverage", "Advanced Analytics - Low Risk BAU"]
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

    elif analysis_type == "Domain Analysis":
        st.subheader("Email Domain Classification & Distribution Analysis")

        # Apply domain classification if not already done
        from utils.domain_classifier import DomainClassifier
        domain_classifier = DomainClassifier()
        if 'email_domain_type' not in df.columns:
            df = domain_classifier.classify_domains(df)

        # Overall Domain Distribution
        st.subheader("📊 Domain Type Distribution Overview")
        
        domain_type_counts = df['email_domain_type'].value_counts()
        total_emails = len(df)
        
        # Create distribution metrics
        domain_col1, domain_col2, domain_col3, domain_col4, domain_col5 = st.columns(5)
        
        with domain_col1:
            business_count = domain_type_counts.get('business', 0)
            business_pct = (business_count / total_emails * 100) if total_emails > 0 else 0
            st.metric("Business Domains", f"{business_count:,}", f"{business_pct:.1f}%")
        
        with domain_col2:
            free_count = domain_type_counts.get('free', 0)
            free_pct = (free_count / total_emails * 100) if total_emails > 0 else 0
            st.metric("Free Email", f"{free_count:,}", f"{free_pct:.1f}%")
        
        with domain_col3:
            internal_count = domain_type_counts.get('internal', 0)
            internal_pct = (internal_count / total_emails * 100) if total_emails > 0 else 0
            st.metric("Internal", f"{internal_count:,}", f"{internal_pct:.1f}%")
        
        with domain_col4:
            public_count = domain_type_counts.get('public', 0)
            public_pct = (public_count / total_emails * 100) if total_emails > 0 else 0
            st.metric("Public", f"{public_count:,}", f"{public_pct:.1f}%")
        
        with domain_col5:
            unknown_count = domain_type_counts.get('unknown', 0)
            unknown_pct = (unknown_count / total_emails * 100) if total_emails > 0 else 0
            st.metric("Unknown", f"{unknown_count:,}", f"{unknown_pct:.1f}%")

        # Domain Type Analysis Tabs
        domain_tab1, domain_tab2, domain_tab3, domain_tab4 = st.tabs([
            "📈 Visual Distribution", 
            "🏢 Business Domain Analysis", 
            "📧 Free Email Analysis", 
            "🔒 Risk by Domain Type"
        ])
        
        with domain_tab1:
            # Create comprehensive domain visualization
            import plotly.graph_objects as go
            from plotly.subplots import make_subplots
            
            # Domain colors
            domain_colors = {
                'business': '#2E8B57',
                'free': '#DC143C', 
                'internal': '#4169E1',
                'public': '#FF8C00',
                'unknown': '#708090'
            }
            
            # Create subplots for different visualizations
            fig = make_subplots(
                rows=2, cols=2,
                specs=[[{"type": "domain"}, {"type": "xy"}],
                       [{"type": "xy", "colspan": 2}, None]],
                subplot_titles=("Distribution by Type", "Email Volume", "Top Domains by Category"),
                vertical_spacing=0.15
            )
            
            # Pie chart
            colors = [domain_colors.get(dtype, '#708090') for dtype in domain_type_counts.index]
            fig.add_trace(
                go.Pie(
                    labels=domain_type_counts.index,
                    values=domain_type_counts.values,
                    marker_colors=colors,
                    textinfo='label+percent',
                    hole=0.3
                ),
                row=1, col=1
            )
            
            # Bar chart
            fig.add_trace(
                go.Bar(
                    x=domain_type_counts.index,
                    y=domain_type_counts.values,
                    marker_color=colors,
                    text=[f"{val:,}" for val in domain_type_counts.values],
                    textposition='auto'
                ),
                row=1, col=2
            )
            
            # Top domains by category
            top_domains_data = []
            top_domains_labels = []
            top_domains_colors = []
            
            for domain_type in ['business', 'free', 'internal', 'public']:
                if domain_type in domain_type_counts.index and domain_type_counts[domain_type] > 0:
                    type_data = df[df['email_domain_type'] == domain_type]
                    top_domain_counts = type_data['email_domain'].value_counts().head(3)
                    
                    for domain, count in top_domain_counts.items():
                        top_domains_data.append(count)
                        top_domains_labels.append(f"{domain_type.title()}: {domain}")
                        top_domains_colors.append(domain_colors.get(domain_type, '#708090'))
            
            if top_domains_data:
                fig.add_trace(
                    go.Bar(
                        x=top_domains_labels[:10],  # Limit to top 10
                        y=top_domains_data[:10],
                        marker_color=top_domains_colors[:10],
                        text=[f"{val:,}" for val in top_domains_data[:10]],
                        textposition='auto'
                    ),
                    row=2, col=1
                )
            
            fig.update_layout(
                title="Comprehensive Domain Analysis",
                height=800,
                showlegend=False
            )
            
            # Update axes
            fig.update_xaxes(title_text="Domain Type", row=1, col=2)
            fig.update_yaxes(title_text="Email Count", row=1, col=2)
            fig.update_xaxes(title_text="Top Domains", row=2, col=1, tickangle=45)
            fig.update_yaxes(title_text="Email Count", row=2, col=1)
            
            st.plotly_chart(fig, use_container_width=True)
        
        with domain_tab2:
            # Business Domain Analysis
            business_domains_df = df[df['email_domain_type'] == 'business']
            
            if not business_domains_df.empty:
                st.write(f"**{len(business_domains_df):,} emails from business domains**")
                
                # Industry breakdown if available
                if 'email_domain_industry' in business_domains_df.columns:
                    industry_counts = business_domains_df['email_domain_industry'].value_counts()
                    
                    st.subheader("Industry Distribution")
                    industry_col1, industry_col2, industry_col3 = st.columns(3)
                    
                    with industry_col1:
                        banking_count = industry_counts.get('banking', 0)
                        st.metric("Banking/Financial", banking_count)
                        education_count = industry_counts.get('education', 0)
                        st.metric("Education", education_count)
                    
                    with industry_col2:
                        healthcare_count = industry_counts.get('healthcare', 0)
                        st.metric("Healthcare", healthcare_count)
                        tech_count = industry_counts.get('technology', 0)
                        st.metric("Technology", tech_count)
                    
                    with industry_col3:
                        gov_count = industry_counts.get('government', 0)
                        st.metric("Government", gov_count)
                        other_count = industry_counts.get('business_other', 0)
                        st.metric("Other Business", other_count)
                
                # Top business domains
                top_business_domains = business_domains_df['email_domain'].value_counts().head(15)
                
                st.subheader("Top Business Domains")
                business_display = []
                for rank, (domain, count) in enumerate(top_business_domains.items(), 1):
                    percentage = (count / len(business_domains_df) * 100)
                    industry = business_domains_df[business_domains_df['email_domain'] == domain]['email_domain_industry'].iloc[0] if 'email_domain_industry' in business_domains_df.columns else 'Unknown'
                    
                    business_display.append({
                        'Rank': f"#{rank}",
                        'Domain': domain,
                        'Email Count': f"{count:,}",
                        'Percentage': f"{percentage:.1f}%",
                        'Industry': industry.replace('_', ' ').title()
                    })
                
                if business_display:
                    business_df = pd.DataFrame(business_display)
                    st.dataframe(business_df, use_container_width=True, height=400)
            else:
                st.info("No business domains found in the dataset")
        
        with domain_tab3:
            # Free Email Analysis
            free_domains_df = df[df['email_domain_type'] == 'free']
            
            if not free_domains_df.empty:
                st.write(f"**{len(free_domains_df):,} emails from free email providers**")
                
                # Security analysis for free domains
                if 'risk_score' in free_domains_df.columns:
                    avg_risk = free_domains_df['risk_score'].mean()
                    high_risk_count = len(free_domains_df[free_domains_df['risk_score'] >= 61])
                    
                    risk_col1, risk_col2, risk_col3 = st.columns(3)
                    with risk_col1:
                        st.metric("Average Risk Score", f"{avg_risk:.1f}/100")
                    with risk_col2:
                        st.metric("High Risk Emails", high_risk_count)
                    with risk_col3:
                        risk_pct = (high_risk_count / len(free_domains_df) * 100) if len(free_domains_df) > 0 else 0
                        st.metric("High Risk %", f"{risk_pct:.1f}%")
                
                # Top free email providers
                top_free_domains = free_domains_df['email_domain'].value_counts().head(10)
                
                st.subheader("Top Free Email Providers")
                free_display = []
                for rank, (domain, count) in enumerate(top_free_domains.items(), 1):
                    percentage = (count / len(free_domains_df) * 100)
                    domain_data = free_domains_df[free_domains_df['email_domain'] == domain]
                    avg_risk = domain_data['risk_score'].mean() if 'risk_score' in domain_data.columns else 0
                    
                    free_display.append({
                        'Rank': f"#{rank}",
                        'Provider': domain,
                        'Email Count': f"{count:,}",
                        'Percentage': f"{percentage:.1f}%",
                        'Avg Risk Score': f"{avg_risk:.1f}/100"
                    })
                
                if free_display:
                    free_df = pd.DataFrame(free_display)
                    st.dataframe(free_df, use_container_width=True, height=300)
            else:
                st.info("No free email domains found in the dataset")
        
        with domain_tab4:
            # Risk Analysis by Domain Type
            st.subheader("Security Risk Analysis by Domain Type")
            
            if 'risk_score' in df.columns:
                # Calculate risk statistics by domain type
                risk_by_domain = df.groupby('email_domain_type')['risk_score'].agg([
                    'count', 'mean', 'min', 'max'
                ]).round(1)
                
                # Add high risk counts
                high_risk_by_domain = df[df['risk_score'] >= 61].groupby('email_domain_type').size()
                risk_by_domain['high_risk_count'] = high_risk_by_domain
                risk_by_domain['high_risk_count'] = risk_by_domain['high_risk_count'].fillna(0).astype(int)
                
                # Calculate high risk percentage
                risk_by_domain['high_risk_pct'] = (risk_by_domain['high_risk_count'] / risk_by_domain['count'] * 100).round(1)
                
                # Display risk metrics
                st.subheader("Risk Metrics by Domain Type")
                
                risk_display = []
                for domain_type in risk_by_domain.index:
                    row = risk_by_domain.loc[domain_type]
                    risk_display.append({
                        'Domain Type': domain_type.title(),
                        'Total Emails': f"{int(row['count']):,}",
                        'Avg Risk Score': f"{row['mean']:.1f}/100",
                        'Min Risk': f"{row['min']:.1f}",
                        'Max Risk': f"{row['max']:.1f}",
                        'High Risk Emails': f"{int(row['high_risk_count']):,}",
                        'High Risk %': f"{row['high_risk_pct']:.1f}%"
                    })
                
                risk_summary_df = pd.DataFrame(risk_display)
                
                # Style the risk table
                def highlight_high_risk(row):
                    styles = [''] * len(row)
                    try:
                        risk_pct = float(str(row['High Risk %']).replace('%', ''))
                        if risk_pct >= 20:
                            styles[6] = 'background-color: #ffebee; color: #c62828; font-weight: bold'
                        elif risk_pct >= 10:
                            styles[6] = 'background-color: #fff3e0; color: #ef6c00; font-weight: bold'
                    except:
                        pass
                    return styles
                
                styled_risk_df = risk_summary_df.style.apply(highlight_high_risk, axis=1)
                st.dataframe(styled_risk_df, use_container_width=True)
                
                # Risk distribution visualization
                st.subheader("Risk Score Distribution by Domain Type")
                
                import plotly.express as px
                
                # Create box plot for risk distribution
                fig_risk = px.box(
                    df, 
                    x='email_domain_type', 
                    y='risk_score',
                    color='email_domain_type',
                    title="Risk Score Distribution by Domain Type",
                    labels={'email_domain_type': 'Domain Type', 'risk_score': 'Risk Score'}
                )
                
                fig_risk.update_layout(
                    height=400,
                    showlegend=False
                )
                
                st.plotly_chart(fig_risk, use_container_width=True)
            else:
                st.warning("Risk analysis not available. Please ensure risk scores are calculated in the Dashboard page first.")

        # Domain statistics with business and free email classification
        st.subheader("Detailed Domain Statistics")

        # Get domain counts for backward compatibility
        if 'sender_domain' not in df.columns:
            df['sender_domain'] = df['sender'].apply(lambda x: str(x).split('@')[-1].lower().strip() if pd.notna(x) and '@' in str(x) else '')

        domain_counts = df['sender_domain'].value_counts()

        # Classify domains for legacy display
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

        # Industry Analysis for Business Domains
        st.subheader("🏛️ Business Domain Industry Analysis")
        
        if 'email_domain_industry' in df.columns:
            # Filter for business domains only
            business_domain_df = df[df['email_domain_type'].isin(['business', 'internal'])]
            
            if not business_domain_df.empty:
                industry_counts = business_domain_df['email_domain_industry'].value_counts()
                
                # Display industry metrics
                st.write("**Industry Distribution of Business Domains:**")
                
                industry_col1, industry_col2, industry_col3 = st.columns(3)
                
                with industry_col1:
                    banking_count = industry_counts.get('banking', 0)
                    banking_pct = (banking_count / len(business_domain_df) * 100) if len(business_domain_df) > 0 else 0
                    st.metric("🏦 Banking/Financial", f"{banking_count:,}", f"{banking_pct:.1f}%")
                
                with industry_col2:
                    education_count = industry_counts.get('education', 0)
                    education_pct = (education_count / len(business_domain_df) * 100) if len(business_domain_df) > 0 else 0
                    st.metric("🎓 Education", f"{education_count:,}", f"{education_pct:.1f}%")
                
                with industry_col3:
                    healthcare_count = industry_counts.get('healthcare', 0)
                    healthcare_pct = (healthcare_count / len(business_domain_df) * 100) if len(business_domain_df) > 0 else 0
                    st.metric("🏥 Healthcare", f"{healthcare_count:,}", f"{healthcare_pct:.1f}%")
                
                # Additional industries in a second row
                industry_col4, industry_col5, industry_col6 = st.columns(3)
                
                with industry_col4:
                    tech_count = industry_counts.get('technology', 0)
                    tech_pct = (tech_count / len(business_domain_df) * 100) if len(business_domain_df) > 0 else 0
                    st.metric("💻 Technology", f"{tech_count:,}", f"{tech_pct:.1f}%")
                
                with industry_col5:
                    gov_count = industry_counts.get('government', 0)
                    gov_pct = (gov_count / len(business_domain_df) * 100) if len(business_domain_df) > 0 else 0
                    st.metric("🏛️ Government", f"{gov_count:,}", f"{gov_pct:.1f}%")
                
                with industry_col6:
                    other_count = industry_counts.get('business_other', 0)
                    other_pct = (other_count / len(business_domain_df) * 100) if len(business_domain_df) > 0 else 0
                    st.metric("🏢 Other Business", f"{other_count:,}", f"{other_pct:.1f}%")
                
                # Detailed industry breakdown table
                st.subheader("📋 Detailed Industry Breakdown")
                
                # Create detailed breakdown by industry
                industry_details = []
                for industry, count in industry_counts.items():
                    if count > 0:
                        industry_data = business_domain_df[business_domain_df['email_domain_industry'] == industry]
                        unique_domains = industry_data['email_domain'].nunique()
                        unique_senders = industry_data['sender'].nunique()
                        
                        # Get top 3 domains for this industry
                        top_domains = industry_data['email_domain'].value_counts().head(3)
                        top_domains_str = ', '.join([f"{domain} ({count})" for domain, count in top_domains.items()])
                        
                        industry_display_name = {
                            'banking': '🏦 Banking/Financial',
                            'education': '🎓 Education',
                            'healthcare': '🏥 Healthcare',
                            'technology': '💻 Technology',
                            'government': '🏛️ Government',
                            'business_other': '🏢 Other Business'
                        }.get(industry, industry.title())
                        
                        industry_details.append({
                            'Industry': industry_display_name,
                            'Email Count': f"{count:,}",
                            'Percentage': f"{(count/len(business_domain_df)*100):.1f}%",
                            'Unique Domains': unique_domains,
                            'Unique Senders': unique_senders,
                            'Top Domains (Count)': top_domains_str[:80] + ('...' if len(top_domains_str) > 80 else '')
                        })
                
                if industry_details:
                    industry_df = pd.DataFrame(industry_details)
                    
                    # Style the industry table
                    def highlight_industry(row):
                        styles = [''] * len(row)
                        industry = str(row['Industry'])
                        if '🏦' in industry:  # Banking
                            styles[0] = 'background-color: #e8f5e8; color: #2e7d32; font-weight: bold'
                        elif '🎓' in industry:  # Education
                            styles[0] = 'background-color: #e3f2fd; color: #1565c0; font-weight: bold'
                        elif '🏥' in industry:  # Healthcare
                            styles[0] = 'background-color: #fce4ec; color: #ad1457; font-weight: bold'
                        elif '💻' in industry:  # Technology
                            styles[0] = 'background-color: #f3e5f5; color: #7b1fa2; font-weight: bold'
                        elif '🏛️' in industry:  # Government
                            styles[0] = 'background-color: #fff3e0; color: #ef6c00; font-weight: bold'
                        return styles
                    
                    styled_industry_df = industry_df.style.apply(highlight_industry, axis=1)
                    st.dataframe(styled_industry_df, use_container_width=True, height=300)
                    
                    # Industry insights
                    st.subheader("💡 Industry Analysis Insights")
                    
                    # Banking analysis
                    if banking_count > 0:
                        banking_data = business_domain_df[business_domain_df['email_domain_industry'] == 'banking']
                        banking_domains = banking_data['email_domain'].value_counts()
                        st.write(f"**🏦 Banking/Financial Sector:**")
                        st.write(f"• {banking_count:,} emails from {banking_domains.nunique()} banking institutions")
                        if not banking_domains.empty:
                            st.write(f"• Top banking domain: {banking_domains.index[0]} ({banking_domains.iloc[0]} emails)")
                        
                        # Check for potential compliance concerns
                        if 'word_list_match' in banking_data.columns:
                            banking_word_matches = len(banking_data[
                                (banking_data['word_list_match'].notna()) & 
                                (banking_data['word_list_match'] != '') & 
                                (banking_data['word_list_match'].astype(str) != '0')
                            ])
                            if banking_word_matches > 0:
                                st.warning(f"⚠️ {banking_word_matches} banking emails contain sensitive keywords")
                    
                    # Education analysis
                    if education_count > 0:
                        education_data = business_domain_df[business_domain_df['email_domain_industry'] == 'education']
                        education_domains = education_data['email_domain'].value_counts()
                        st.write(f"**🎓 Education Sector:**")
                        st.write(f"• {education_count:,} emails from {education_domains.nunique()} educational institutions")
                        if not education_domains.empty:
                            st.write(f"• Top education domain: {education_domains.index[0]} ({education_domains.iloc[0]} emails)")
                    
                    # Technology analysis
                    if tech_count > 0:
                        tech_data = business_domain_df[business_domain_df['email_domain_industry'] == 'technology']
                        tech_domains = tech_data['email_domain'].value_counts()
                        st.write(f"**💻 Technology Sector:**")
                        st.write(f"• {tech_count:,} emails from {tech_domains.nunique()} technology companies")
                        if not tech_domains.empty:
                            st.write(f"• Top tech domain: {tech_domains.index[0]} ({tech_domains.iloc[0]} emails)")
                
            else:
                st.info("No business domains found for industry analysis")
        else:
            st.info("Industry classification not available. Please reprocess the data to include industry analysis.")

    elif analysis_type == "Security Tool Coverage":
        st.subheader("🛡️ Security Tool Coverage Analysis")
        st.write("**Complete Dataset Analysis** - Analysis of Tessian Policy and Mimecast security tool coverage across ALL email events in the dataset")
        
        # Add explanatory note about Tessian coverage
        st.info("""
        ℹ️ **Important Note About Tessian Coverage:** 
        Tessian is policy-driven and only monitors specific types of email events based on configured security policies. 
        It focuses on detecting sensitive information patterns, suspicious attachments, and high-risk communications. 
        Not all email events will have Tessian coverage as it selectively analyzes emails that match its predefined 
        security criteria and organizational policies. This targeted approach allows Tessian to focus computational 
        resources on emails most likely to contain security risks.
        """)
        
        # Use complete dataset for analysis (no filtering)
        analysis_df = df.copy()
        
        # Display dataset scope
        st.info(f"📊 **Analysis Scope:** Using complete dataset of {len(analysis_df):,} emails for comprehensive security tool coverage analysis")
        
        # Check if the required fields exist
        has_tessian = 'tessian_policy' in analysis_df.columns
        has_mimecast = 'mimecast' in analysis_df.columns
        
        if not has_tessian and not has_mimecast:
            st.warning("Neither 'tessian_policy' nor 'mimecast' fields found in the dataset.")
            st.info("Please ensure your email data includes these security tool fields for coverage analysis.")
        elif not has_tessian:
            st.warning("'tessian_policy' field not found in the dataset.")
        elif not has_mimecast:
            st.warning("'mimecast' field not found in the dataset.")
        else:
            # Analyze coverage using complete dataset
            def has_data(value):
                return pd.notna(value) and str(value).strip() not in ['', '0', 'nan', 'None']
            
            analysis_df['has_tessian_data'] = analysis_df['tessian_policy'].apply(has_data)
            analysis_df['has_mimecast_data'] = analysis_df['mimecast'].apply(has_data)
            
            # Coverage statistics from complete dataset
            total_emails = len(analysis_df)
            tessian_coverage = analysis_df['has_tessian_data'].sum()
            mimecast_coverage = analysis_df['has_mimecast_data'].sum()
            both_coverage = (analysis_df['has_tessian_data'] & analysis_df['has_mimecast_data']).sum()
            neither_coverage = (~analysis_df['has_tessian_data'] & ~analysis_df['has_mimecast_data']).sum()
            
            # Display overview metrics
            st.subheader("📊 Coverage Overview")
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Emails", f"{total_emails:,}")
            with col2:
                tessian_pct = (tessian_coverage / total_emails * 100) if total_emails > 0 else 0
                st.metric("Tessian Coverage", f"{tessian_coverage:,}", f"{tessian_pct:.1f}%")
            with col3:
                mimecast_pct = (mimecast_coverage / total_emails * 100) if total_emails > 0 else 0
                st.metric("Mimecast Coverage", f"{mimecast_coverage:,}", f"{mimecast_pct:.1f}%")
            with col4:
                both_pct = (both_coverage / total_emails * 100) if total_emails > 0 else 0
                st.metric("Both Tools", f"{both_coverage:,}", f"{both_pct:.1f}%")
            
            # Coverage gap analysis
            st.subheader("🔍 Coverage Gap Analysis")
            
            # Coverage gap analysis using complete dataset
            tessian_only = analysis_df[analysis_df['has_tessian_data'] & ~analysis_df['has_mimecast_data']]
            mimecast_only = analysis_df[~analysis_df['has_tessian_data'] & analysis_df['has_mimecast_data']]
            no_coverage = analysis_df[~analysis_df['has_tessian_data'] & ~analysis_df['has_mimecast_data']]
            
            tab1, tab2, tab3 = st.tabs(["Tessian Only", "Mimecast Only", "No Coverage"])
            
            with tab1:
                st.write(f"**{len(tessian_only)} emails have Tessian Policy data but no Mimecast data**")
                if not tessian_only.empty:
                    # Create display table
                    tessian_display = []
                    for idx, (_, row) in enumerate(tessian_only.head(50).iterrows()):
                        time_str = str(row.get('time', 'N/A'))
                        if 'T' in time_str:
                            time_str = time_str.split('T')[0] + ' ' + time_str.split('T')[1][:8]
                        
                        tessian_display.append({
                            '#': idx + 1,
                            'Date/Time': time_str,
                            'Sender': str(row.get('sender', 'Unknown'))[:40] + ('...' if len(str(row.get('sender', ''))) > 40 else ''),
                            'Subject': str(row.get('subject', 'No Subject'))[:50] + ('...' if len(str(row.get('subject', ''))) > 50 else ''),
                            'Tessian Policy': str(row.get('tessian_policy', ''))[:60] + ('...' if len(str(row.get('tessian_policy', ''))) > 60 else ''),
                            'Risk Score': f"{row.get('risk_score', 0):.1f}/100" if row.get('risk_score') else 'N/A'
                        })
                    
                    tessian_df = pd.DataFrame(tessian_display)
                    st.dataframe(tessian_df, use_container_width=True, height=400)
                    
                    # Summary stats for Tessian-only
                    st.write("**Summary Statistics:**")
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        avg_risk = tessian_only['risk_score'].mean() if 'risk_score' in tessian_only.columns else 0
                        st.metric("Avg Risk Score", f"{avg_risk:.1f}/100")
                    with col2:
                        if 'risk_level' in tessian_only.columns:
                            high_risk_count = len(tessian_only[tessian_only['risk_level'] == 'High'])
                        else:
                            high_risk_count = 0
                        st.metric("High Risk Emails", high_risk_count)
                    with col3:
                        unique_senders = tessian_only['sender'].nunique()
                        st.metric("Unique Senders", unique_senders)
                else:
                    st.info("No emails found with Tessian data only.")
            
            with tab2:
                st.write(f"**{len(mimecast_only)} emails have Mimecast data but no Tessian Policy data**")
                if not mimecast_only.empty:
                    # Create display table
                    mimecast_display = []
                    for idx, (_, row) in enumerate(mimecast_only.head(50).iterrows()):
                        time_str = str(row.get('time', 'N/A'))
                        if 'T' in time_str:
                            time_str = time_str.split('T')[0] + ' ' + time_str.split('T')[1][:8]
                        
                        mimecast_display.append({
                            '#': idx + 1,
                            'Date/Time': time_str,
                            'Sender': str(row.get('sender', 'Unknown'))[:40] + ('...' if len(str(row.get('sender', ''))) > 40 else ''),
                            'Subject': str(row.get('subject', 'No Subject'))[:50] + ('...' if len(str(row.get('subject', ''))) > 50 else ''),
                            'Mimecast': str(row.get('mimecast', ''))[:60] + ('...' if len(str(row.get('mimecast', ''))) > 60 else ''),
                            'Risk Score': f"{row.get('risk_score', 0):.1f}/100" if row.get('risk_score') else 'N/A'
                        })
                    
                    mimecast_df = pd.DataFrame(mimecast_display)
                    st.dataframe(mimecast_df, use_container_width=True, height=400)
                    
                    # Summary stats for Mimecast-only
                    st.write("**Summary Statistics:**")
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        avg_risk = mimecast_only['risk_score'].mean() if 'risk_score' in mimecast_only.columns else 0
                        st.metric("Avg Risk Score", f"{avg_risk:.1f}/100")
                    with col2:
                        if 'risk_level' in mimecast_only.columns:
                            high_risk_count = len(mimecast_only[mimecast_only['risk_level'] == 'High'])
                        else:
                            high_risk_count = 0
                        st.metric("High Risk Emails", high_risk_count)
                    with col3:
                        unique_senders = mimecast_only['sender'].nunique()
                        st.metric("Unique Senders", unique_senders)
                else:
                    st.info("No emails found with Mimecast data only.")
            
            with tab3:
                st.write(f"**{len(no_coverage)} emails have no security tool coverage**")
                if not no_coverage.empty:
                    # Create display table
                    no_coverage_display = []
                    for idx, (_, row) in enumerate(no_coverage.head(50).iterrows()):
                        time_str = str(row.get('time', 'N/A'))
                        if 'T' in time_str:
                            time_str = time_str.split('T')[0] + ' ' + time_str.split('T')[1][:8]
                        
                        no_coverage_display.append({
                            '#': idx + 1,
                            'Date/Time': time_str,
                            'Sender': str(row.get('sender', 'Unknown'))[:40] + ('...' if len(str(row.get('sender', ''))) > 40 else ''),
                            'Subject': str(row.get('subject', 'No Subject'))[:60] + ('...' if len(str(row.get('subject', ''))) > 60 else ''),
                            'Risk Score': f"{row.get('risk_score', 0):.1f}/100" if row.get('risk_score') else 'N/A',
                            'Risk Level': str(row.get('risk_level', 'N/A'))
                        })
                    
                    no_coverage_df = pd.DataFrame(no_coverage_display)
                    
                    # Color code by risk level
                    def highlight_risk_level(val):
                        if 'High' in str(val):
                            return 'background-color: #ffebee; color: #c62828'
                        elif 'Medium' in str(val):
                            return 'background-color: #fff3e0; color: #ef6c00'
                        return ''
                    
                    styled_no_coverage = no_coverage_df.style.map(highlight_risk_level)
                    st.dataframe(styled_no_coverage, use_container_width=True, height=400)
                    
                    # Summary stats for no coverage
                    st.write("**Summary Statistics:**")
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        avg_risk = no_coverage['risk_score'].mean() if 'risk_score' in no_coverage.columns else 0
                        st.metric("Avg Risk Score", f"{avg_risk:.1f}/100")
                    with col2:
                        if 'risk_level' in no_coverage.columns:
                            high_risk_count = len(no_coverage[no_coverage['risk_level'] == 'High'])
                        else:
                            high_risk_count = 0
                        st.metric("High Risk Emails", high_risk_count)
                    with col3:
                        if 'risk_level' in no_coverage.columns:
                            medium_risk_count = len(no_coverage[no_coverage['risk_level'] == 'Medium'])
                        else:
                            medium_risk_count = 0
                        st.metric("Medium Risk Emails", medium_risk_count)
                    with col4:
                        unique_senders = no_coverage['sender'].nunique()
                        st.metric("Unique Senders", unique_senders)
                    
                    if high_risk_count > 0:
                        st.warning(f"⚠️ {high_risk_count} high-risk emails lack security tool coverage!")
                else:
                    st.success("All emails have some form of security tool coverage.")
            
            # Recommendations section
            st.subheader("💡 Security Coverage Recommendations")
            
            if neither_coverage > 0:
                neither_pct = (neither_coverage / total_emails * 100)
                st.error(f"**Critical Gap:** {neither_coverage:,} emails ({neither_pct:.1f}%) have no security tool coverage")
            
            if len(tessian_only) > 0:
                tessian_only_pct = (len(tessian_only) / total_emails * 100)
                st.warning(f"**Mimecast Gap:** {len(tessian_only):,} emails ({tessian_only_pct:.1f}%) only covered by Tessian")
            
            if len(mimecast_only) > 0:
                mimecast_only_pct = (len(mimecast_only) / total_emails * 100)
                st.warning(f"**Tessian Gap:** {len(mimecast_only):,} emails ({mimecast_only_pct:.1f}%) only covered by Mimecast")
            
            if both_coverage > 0:
                st.success(f"**Good Coverage:** {both_coverage:,} emails ({both_pct:.1f}%) have dual tool protection")

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
    st.header("🔄 ExfilEye Application Flow Dashboard")
    
    # Custom CSS for better styling
    st.markdown("""
    <style>
    .flow-box {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin: 0.5rem 0;
        text-align: center;
        font-weight: bold;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .process-box {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin: 0.5rem 0;
        text-align: center;
        font-weight: bold;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .output-box {
        background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin: 0.5rem 0;
        text-align: center;
        font-weight: bold;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .analysis-box {
        background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin: 0.5rem 0;
        text-align: center;
        font-weight: bold;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .arrow {
        text-align: center;
        font-size: 2rem;
        color: #666;
        margin: 0.5rem 0;
    }
    .section-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
        font-size: 1.5rem;
        font-weight: bold;
        margin: 1rem 0;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Introduction
    st.markdown("""
    <div class="section-header">
        📊 ExfilEye: Data Loss Prevention Email Monitor - Application Architecture
    </div>
    """, unsafe_allow_html=True)
    
    st.write("""
    **ExfilEye** is a comprehensive email security monitoring system designed to detect potential data exfiltration 
    and insider threats through advanced email analysis. Below is the complete application flow:
    """)
    
    # Main Application Flow
    st.markdown("""
    <div class="section-header">
        🔄 Main Application Flow
    </div>
    """, unsafe_allow_html=True)
    
    # Create tabs for different views
    tab1, tab2, tab3, tab4 = st.tabs(["📋 Overall Flow", "⚙️ Processing Engine", "📊 Analytics Engine", "🎯 Security Features"])
    
    with tab1:
        st.subheader("📋 Complete Application Workflow")
        
        col1, col2, col3 = st.columns([1, 8, 1])
        with col2:
            st.markdown("""
            <div class="flow-box">
                🏁 START: User Accesses ExfilEye Dashboard
            </div>
            <div class="arrow">⬇️</div>
            <div class="flow-box">
                📁 Step 1: Data Upload Page
                <br><small>Upload email data CSV + optional whitelist</small>
            </div>
            <div class="arrow">⬇️</div>
            <div class="process-box">
                ⚙️ Step 2: Data Processing Engine
                <br><small>Validate, clean, and enrich email data</small>
            </div>
            <div class="arrow">⬇️</div>
            <div class="process-box">
                🔍 Step 3: Domain Classification
                <br><small>Classify email domains (business, free, internal, etc.)</small>
            </div>
            <div class="arrow">⬇️</div>
            <div class="process-box">
                🎯 Step 4: Keyword Detection
                <br><small>Identify sensitive content patterns</small>
            </div>
            <div class="arrow">⬇️</div>
            <div class="analysis-box">
                🧠 Step 5: Risk Scoring Engine
                <br><small>Calculate threat scores using ML algorithms</small>
            </div>
            <div class="arrow">⬇️</div>
            <div class="output-box">
                📊 Step 6: Security Dashboard
                <br><small>Display critical, high, medium, low risk emails</small>
            </div>
            <div class="arrow">⬇️</div>
            <div class="output-box">
                📈 Step 7: Advanced Analytics
                <br><small>Anomaly detection, patterns, trends</small>
            </div>
            <div class="arrow">⬇️</div>
            <div class="output-box">
                🌐 Step 8: Network View
                <br><small>Domain relationships and communication patterns</small>
            </div>
            <div class="arrow">⬇️</div>
            <div class="output-box">
                📧 Step 9: Follow-up Actions
                <br><small>Generate security alerts and recommendations</small>
            </div>
            <div class="arrow">⬇️</div>
            <div class="flow-box">
                🏆 END: Security Team Takes Action
            </div>
            """, unsafe_allow_html=True)
    
    with tab2:
        st.subheader("⚙️ Data Processing Engine Details")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            <div class="section-header">📥 Input Processing</div>
            <div class="process-box">
                📄 CSV File Validation
                <br><small>Check required fields</small>
            </div>
            <div class="arrow">⬇️</div>
            <div class="process-box">
                🧹 Data Cleaning
                <br><small>Standardize emails, parse timestamps</small>
            </div>
            <div class="arrow">⬇️</div>
            <div class="process-box">
                📧 Email Parsing
                <br><small>Extract domains, recipients, attachments</small>
            </div>
            <div class="arrow">⬇️</div>
            <div class="process-box">
                ⏰ Temporal Analysis
                <br><small>Business hours, after-hours detection</small>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="section-header">🔧 Enhancement Engine</div>
            <div class="analysis-box">
                🏢 Domain Classification
                <br><small>Business, Free, Internal, Public domains</small>
            </div>
            <div class="arrow">⬇️</div>
            <div class="analysis-box">
                🎯 Keyword Detection
                <br><small>IP-sensitive content identification</small>
            </div>
            <div class="arrow">⬇️</div>
            <div class="analysis-box">
                📎 Attachment Analysis
                <br><small>File types, sizes, risk assessment</small>
            </div>
            <div class="arrow">⬇️</div>
            <div class="analysis-box">
                👤 Leaver Detection
                <br><small>Identify departing employees</small>
            </div>
            """, unsafe_allow_html=True)
        
        # Processing Components
        st.markdown("""
        <div class="section-header">🔍 Key Processing Components</div>
        """, unsafe_allow_html=True)
        
        comp_col1, comp_col2, comp_col3 = st.columns(3)
        
        with comp_col1:
            st.markdown("""
            **🏗️ DataProcessor**
            - Field validation
            - Email parsing
            - Time analysis
            - Recipient counting
            - Domain extraction
            """)
        
        with comp_col2:
            st.markdown("""
            **🏢 DomainClassifier**
            - Business domains
            - Free email providers
            - Educational institutions
            - Government domains
            - Unknown classification
            """)
        
        with comp_col3:
            st.markdown("""
            **🔍 KeywordDetector**
            - Sensitive keywords
            - IP-related terms
            - Financial data
            - Legal documents
            - Confidential content
            """)
    
    with tab3:
        st.subheader("📊 Analytics and Risk Assessment Engine")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            <div class="section-header">🧠 Risk Scoring System</div>
            <div class="analysis-box">
                🚨 Critical Risk (70+ points)
                <br><small>Leaver + Attachments + Keywords + Free Email</small>
            </div>
            <div class="analysis-box">
                🔴 High Risk (61-69 points)
                <br><small>Leaver + Attachments activity</small>
            </div>
            <div class="analysis-box">
                🟡 Medium Risk (31-60 points)
                <br><small>Attachments + Keywords (no leaver)</small>
            </div>
            <div class="analysis-box">
                🟢 Low Risk (0-30 points)
                <br><small>Normal business communications</small>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="section-header">🔬 Anomaly Detection</div>
            <div class="process-box">
                📈 Volume Spikes
                <br><small>Unusual email frequency patterns</small>
            </div>
            <div class="process-box">
                🌙 Off-Hours Activity
                <br><small>Communications outside business hours</small>
            </div>
            <div class="process-box">
                📎 Attachment Anomalies
                <br><small>Unusual file types or sizes</small>
            </div>
            <div class="process-box">
                🌐 New Domain Communications
                <br><small>First-time external domain contacts</small>
            </div>
            """, unsafe_allow_html=True)
        
        # Risk Factors Visualization
        st.markdown("""
        <div class="section-header">⚖️ Risk Calculation Factors</div>
        """, unsafe_allow_html=True)
        
        risk_col1, risk_col2, risk_col3, risk_col4 = st.columns(4)
        
        with risk_col1:
            st.markdown("""
            **🏃‍♂️ Leaver Activity**
            - Weight: 70 points
            - Last working day detected
            - Highest priority indicator
            """)
        
        with risk_col2:
            st.markdown("""
            **🎯 IP Keywords**
            - Weight: 25 points
            - Sensitive content
            - Confidential information
            """)
        
        with risk_col3:
            st.markdown("""
            **📧 Free Email Domains**
            - Weight: 20 points
            - Gmail, Yahoo, Hotmail
            - External communications
            """)
        
        with risk_col4:
            st.markdown("""
            **📎 Unusual Attachments**
            - Weight: 15 points
            - Risky file types
            - Large file sizes
            """)
    
    with tab4:
        st.subheader("🛡️ Security Features & Capabilities")
        
        # Security Tool Coverage
        st.markdown("""
        <div class="section-header">🔧 Security Tool Integration</div>
        """, unsafe_allow_html=True)
        
        sec_col1, sec_col2 = st.columns(2)
        
        with sec_col1:
            st.markdown("""
            <div class="analysis-box">
                🛡️ Tessian Integration
                <br><small>Policy-driven email security monitoring</small>
            </div>
            <div class="analysis-box">
                📬 Mimecast Integration
                <br><small>Email gateway security analysis</small>
            </div>
            <div class="analysis-box">
                📊 Coverage Analysis
                <br><small>Identify security gaps and blind spots</small>
            </div>
            """, unsafe_allow_html=True)
        
        with sec_col2:
            st.markdown("""
            <div class="output-box">
                ✅ Full Coverage
                <br><small>Both Tessian & Mimecast protection</small>
            </div>
            <div class="output-box">
                ⚠️ Partial Coverage
                <br><small>Only one security tool active</small>
            </div>
            <div class="output-box">
                🚨 No Coverage
                <br><small>Security blind spots requiring attention</small>
            </div>
            """, unsafe_allow_html=True)
        
        # Advanced Analytics Features
        st.markdown("""
        <div class="section-header">📈 Advanced Analytics Features</div>
        """, unsafe_allow_html=True)
        
        feat_col1, feat_col2, feat_col3 = st.columns(3)
        
        with feat_col1:
            st.markdown("""
            **🔍 Anomaly Detection**
            - Machine learning algorithms
            - Behavioral pattern analysis
            - Statistical outlier detection
            - Cluster analysis
            """)
        
        with feat_col2:
            st.markdown("""
            **🌐 Network Analysis**
            - Domain relationship mapping
            - Communication pattern visualization
            - External domain tracking
            - Business unit analysis
            """)
        
        with feat_col3:
            st.markdown("""
            **📊 Business Intelligence**
            - Word frequency analysis
            - Department communication patterns
            - Time-based trend analysis
            - BAU pattern recognition
            """)
    
    # Data Flow Diagram
    st.markdown("""
    <div class="section-header">
        📊 Data Flow Architecture
    </div>
    """, unsafe_allow_html=True)
    
    # Create a flow diagram using columns
    flow_col1, flow_col2, flow_col3, flow_col4 = st.columns(4)
    
    with flow_col1:
        st.markdown("""
        <div class="flow-box">
            📥 INPUT LAYER
        </div>
        <br>
        • Email CSV Data
        • Whitelist Files
        • Configuration Settings
        """, unsafe_allow_html=True)
    
    with flow_col2:
        st.markdown("""
        <div class="process-box">
            ⚙️ PROCESSING LAYER
        </div>
        <br>
        • Data Validation
        • Email Parsing
        • Domain Classification
        • Keyword Detection
        """, unsafe_allow_html=True)
    
    with flow_col3:
        st.markdown("""
        <div class="analysis-box">
            🧠 ANALYSIS LAYER
        </div>
        <br>
        • Risk Scoring
        • Anomaly Detection
        • Pattern Recognition
        • Threat Assessment
        """, unsafe_allow_html=True)
    
    with flow_col4:
        st.markdown("""
        <div class="output-box">
            📊 OUTPUT LAYER
        </div>
        <br>
        • Security Dashboard
        • Risk Reports
        • Analytics Charts
        • Action Items
        """, unsafe_allow_html=True)
    
    # Technical Architecture
    st.markdown("""
    <div class="section-header">
        🏗️ Technical Architecture & Components
    </div>
    """, unsafe_allow_html=True)
    
    arch_col1, arch_col2 = st.columns(2)
    
    with arch_col1:
        st.markdown("""
        **🔧 Core Components:**
        
        📦 **utils/data_processor.py**
        - Email data validation and cleaning
        - Temporal analysis and parsing
        - Attachment and recipient processing
        
        🏢 **utils/domain_classifier.py**
        - Business domain identification
        - Free email provider detection
        - Educational and government classification
        
        🧠 **utils/risk_engine.py**
        - Multi-factor risk scoring algorithm
        - Leaver activity detection (70 points)
        - IP keyword analysis (25 points)
        - Free email domain flagging (20 points)
        
        🔍 **utils/anomaly_detector.py**
        - Machine learning anomaly detection
        - Behavioral pattern analysis
        - Statistical outlier identification
        """)
    
    with arch_col2:
        st.markdown("""
        **📊 Visualization & Analysis:**
        
        📈 **utils/visualization.py**
        - Interactive charts and graphs
        - Network relationship diagrams
        - Risk factor visualizations
        
        🎯 **utils/keyword_detector.py**
        - Sensitive content identification
        - IP-related keyword matching
        - Content pattern analysis
        
        📧 **utils/email_generator.py**
        - Security alert generation
        - Follow-up action recommendations
        - Incident response templates
        
        🔬 **utils/bau_analyzer.py**
        - Business-as-usual pattern analysis
        - Word frequency analysis
        - Department communication trends
        """)
    
    # Security Workflow
    st.markdown("""
    <div class="section-header">
        🛡️ Security Analysis Workflow
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    The ExfilEye application follows a sophisticated security analysis workflow:
    
    1. **📥 Data Ingestion**: Secure upload and validation of email data
    2. **🔍 Content Analysis**: Deep inspection of email content, attachments, and metadata
    3. **🏢 Domain Intelligence**: Classification and risk assessment of email domains
    4. **🧠 Risk Calculation**: Multi-factor scoring using weighted algorithms
    5. **🚨 Threat Detection**: Real-time identification of high-risk communications
    6. **📊 Visualization**: Interactive dashboards for security team analysis
    7. **⚡ Action Generation**: Automated alert generation and response recommendations
    8. **📈 Continuous Monitoring**: Ongoing pattern analysis and trend detection
    
    This comprehensive approach ensures that potential data exfiltration attempts and insider threats 
    are quickly identified and addressed before they can cause damage to the organization.
    """)
    
    # Interactive Features
    st.markdown("""
    <div class="section-header">
        🎮 Interactive Features
    </div>
    """, unsafe_allow_html=True)
    
    feature_col1, feature_col2, feature_col3 = st.columns(3)
    
    with feature_col1:
        st.markdown("""
        **📊 Real-time Dashboards**
        - Live risk metrics
        - Dynamic filtering
        - Interactive charts
        - Drill-down capabilities
        """)
    
    with feature_col2:
        st.markdown("""
        **🔍 Advanced Search**
        - Multi-criteria filtering
        - Anomaly exploration
        - Pattern investigation
        - Historical analysis
        """)
    
    with feature_col3:
        st.markdown("""
        **📈 Predictive Analytics**
        - Trend forecasting
        - Risk probability scoring
        - Behavioral modeling
        - Threat intelligence
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