import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np
import networkx as nx
from datetime import datetime, timedelta

class Visualizer:
    """Creates interactive visualizations for email security analysis"""
    
    def __init__(self):
        self.color_palette = {
            'high_risk': '#FF4444',
            'medium_risk': '#FF8800',
            'normal': '#44AA44',
            'unknown': '#888888'
        }
    
    def create_risk_distribution_chart(self, df):
        """Create pie chart showing risk level distribution"""
        if 'risk_level' not in df.columns:
            # Create empty chart
            fig = go.Figure()
            fig.add_annotation(
                text="No risk data available",
                xref="paper", yref="paper",
                x=0.5, y=0.5, xanchor='center', yanchor='middle',
                showarrow=False, font=dict(size=16)
            )
            fig.update_layout(title="Risk Level Distribution")
            return fig
        
        risk_counts = df['risk_level'].value_counts()
        
        colors = [
            self.color_palette.get(level.lower().replace(' ', '_'), '#888888')
            for level in risk_counts.index
        ]
        
        fig = go.Figure(data=[go.Pie(
            labels=risk_counts.index,
            values=risk_counts.values,
            marker_colors=colors,
            textinfo='label+percent',
            hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
        )])
        
        fig.update_layout(
            title="Risk Level Distribution",
            showlegend=True,
            height=400
        )
        
        return fig
    
    def create_timeline_chart(self, df):
        """Create timeline chart showing email activity over time"""
        if 'time' not in df.columns:
            # Create empty chart
            fig = go.Figure()
            fig.add_annotation(
                text="No time data available",
                xref="paper", yref="paper",
                x=0.5, y=0.5, xanchor='center', yanchor='middle',
                showarrow=False, font=dict(size=16)
            )
            fig.update_layout(title="Email Activity Timeline")
            return fig
        
        df_temp = df.copy()
        df_temp['time'] = pd.to_datetime(df_temp['time'], errors='coerce')
        df_temp = df_temp.dropna(subset=['time'])
        
        if df_temp.empty:
            fig = go.Figure()
            fig.add_annotation(
                text="No valid time data available",
                xref="paper", yref="paper",
                x=0.5, y=0.5, xanchor='center', yanchor='middle',
                showarrow=False, font=dict(size=16)
            )
            fig.update_layout(title="Email Activity Timeline")
            return fig
        
        # Group by date
        df_temp['date'] = df_temp['time'].dt.date
        timeline_data = df_temp.groupby(['date', 'risk_level']).size().reset_index(name='count')
        
        fig = go.Figure()
        
        for risk_level in timeline_data['risk_level'].unique():
            risk_data = timeline_data[timeline_data['risk_level'] == risk_level]
            
            fig.add_trace(go.Scatter(
                x=risk_data['date'],
                y=risk_data['count'],
                mode='lines+markers',
                name=risk_level,
                line=dict(color=self.color_palette.get(risk_level.lower().replace(' ', '_'), '#888888')),
                hovertemplate='<b>%{fullData.name}</b><br>Date: %{x}<br>Count: %{y}<extra></extra>'
            ))
        
        fig.update_layout(
            title="Email Activity Timeline",
            xaxis_title="Date",
            yaxis_title="Email Count",
            hovermode='x unified',
            height=400
        )
        
        return fig
    
    def create_anomaly_chart(self, df, anomalies):
        """Create scatter plot showing anomalies"""
        if df.empty or len(anomalies) == 0:
            fig = go.Figure()
            fig.add_annotation(
                text="No anomaly data available",
                xref="paper", yref="paper",
                x=0.5, y=0.5, xanchor='center', yanchor='middle',
                showarrow=False, font=dict(size=16)
            )
            fig.update_layout(title="Anomaly Detection")
            return fig
        
        df_temp = df.copy()
        df_temp['is_anomaly'] = anomalies
        df_temp['time'] = pd.to_datetime(df_temp['time'], errors='coerce')
        
        # Use risk score if available, otherwise use index
        y_values = df_temp.get('risk_score', range(len(df_temp)))
        
        normal_data = df_temp[~df_temp['is_anomaly']]
        anomaly_data = df_temp[df_temp['is_anomaly']]
        
        fig = go.Figure()
        
        # Normal emails
        if len(normal_data) > 0:
            fig.add_trace(go.Scatter(
                x=normal_data['time'],
                y=y_values[~df_temp['is_anomaly']],
                mode='markers',
                name='Normal',
                marker=dict(color='lightblue', size=6),
                hovertemplate='<b>Normal Email</b><br>Time: %{x}<br>Risk Score: %{y:.1f}<extra></extra>'
            ))
        
        # Anomalous emails
        if len(anomaly_data) > 0:
            fig.add_trace(go.Scatter(
                x=anomaly_data['time'],
                y=y_values[df_temp['is_anomaly']],
                mode='markers',
                name='Anomaly',
                marker=dict(color='red', size=10, symbol='diamond'),
                hovertemplate='<b>Anomalous Email</b><br>Time: %{x}<br>Risk Score: %{y:.1f}<extra></extra>'
            ))
        
        fig.update_layout(
            title="Anomaly Detection Results",
            xaxis_title="Time",
            yaxis_title="Risk Score" if 'risk_score' in df.columns else "Email Index",
            height=400
        )
        
        return fig
    
    def create_behavior_analysis_chart(self, df):
        """Create chart showing behavioral patterns"""
        if df.empty:
            fig = go.Figure()
            fig.add_annotation(
                text="No data available for behavior analysis",
                xref="paper", yref="paper",
                x=0.5, y=0.5, xanchor='center', yanchor='middle',
                showarrow=False, font=dict(size=16)
            )
            fig.update_layout(title="Behavioral Analysis")
            return fig
        
        df_temp = df.copy()
        df_temp['time'] = pd.to_datetime(df_temp['time'], errors='coerce')
        df_temp['hour'] = df_temp['time'].dt.hour
        
        # Email activity by hour
        hourly_activity = df_temp['hour'].value_counts().sort_index()
        
        fig = go.Figure()
        
        fig.add_trace(go.Bar(
            x=hourly_activity.index,
            y=hourly_activity.values,
            name='Email Activity',
            marker_color='lightblue',
            hovertemplate='<b>Hour %{x}:00</b><br>Email Count: %{y}<extra></extra>'
        ))
        
        # Highlight after-hours
        after_hours = [h for h in hourly_activity.index if h < 8 or h >= 18]
        if after_hours:
            after_hours_activity = hourly_activity[after_hours]
            fig.add_trace(go.Bar(
                x=after_hours_activity.index,
                y=after_hours_activity.values,
                name='After Hours',
                marker_color='orange',
                hovertemplate='<b>Hour %{x}:00 (After Hours)</b><br>Email Count: %{y}<extra></extra>'
            ))
        
        fig.update_layout(
            title="Email Activity by Hour",
            xaxis_title="Hour of Day",
            yaxis_title="Email Count",
            barmode='overlay',
            height=400
        )
        
        return fig
    
    def create_volume_trend_chart(self, df):
        """Create chart showing email volume trends"""
        if df.empty or 'time' not in df.columns:
            fig = go.Figure()
            fig.add_annotation(
                text="No time data available for volume trends",
                xref="paper", yref="paper",
                x=0.5, y=0.5, xanchor='center', yanchor='middle',
                showarrow=False, font=dict(size=16)
            )
            fig.update_layout(title="Volume Trends")
            return fig
        
        df_temp = df.copy()
        df_temp['time'] = pd.to_datetime(df_temp['time'], errors='coerce')
        df_temp['date'] = df_temp['time'].dt.date
        
        daily_volume = df_temp.groupby('date').size().reset_index(name='count')
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=daily_volume['date'],
            y=daily_volume['count'],
            mode='lines+markers',
            name='Daily Volume',
            line=dict(color='blue'),
            hovertemplate='<b>Date: %{x}</b><br>Email Count: %{y}<extra></extra>'
        ))
        
        # Add moving average if enough data
        if len(daily_volume) >= 7:
            daily_volume['ma7'] = daily_volume['count'].rolling(window=7, center=True).mean()
            
            fig.add_trace(go.Scatter(
                x=daily_volume['date'],
                y=daily_volume['ma7'],
                mode='lines',
                name='7-day Average',
                line=dict(color='red', dash='dash'),
                hovertemplate='<b>Date: %{x}</b><br>7-day Average: %{y:.1f}<extra></extra>'
            ))
        
        fig.update_layout(
            title="Email Volume Trends",
            xaxis_title="Date",
            yaxis_title="Email Count",
            height=400
        )
        
        return fig
    
    def create_domain_analysis_chart(self, df):
        """Create chart analyzing domain patterns"""
        if 'domain_type' not in df.columns:
            fig = go.Figure()
            fig.add_annotation(
                text="No domain data available",
                xref="paper", yref="paper",
                x=0.5, y=0.5, xanchor='center', yanchor='middle',
                showarrow=False, font=dict(size=16)
            )
            fig.update_layout(title="Domain Analysis")
            return fig
        
        domain_counts = df['domain_type'].value_counts()
        
        fig = go.Figure(data=[go.Bar(
            x=domain_counts.index,
            y=domain_counts.values,
            marker_color=['lightgreen', 'lightblue', 'orange', 'lightcoral'][:len(domain_counts)],
            hovertemplate='<b>%{x}</b><br>Count: %{y}<extra></extra>'
        )])
        
        fig.update_layout(
            title="Email Distribution by Domain Type",
            xaxis_title="Domain Type",
            yaxis_title="Email Count",
            height=400
        )
        
        return fig
    
    def create_risk_factors_chart(self, df):
        """Create chart showing top risk factors"""
        if 'risk_score' not in df.columns:
            fig = go.Figure()
            fig.add_annotation(
                text="No risk score data available",
                xref="paper", yref="paper",
                x=0.5, y=0.5, xanchor='center', yanchor='middle',
                showarrow=False, font=dict(size=16)
            )
            fig.update_layout(title="Risk Factors Analysis")
            return fig
        
        # Analyze risk factors based on available columns
        risk_factors = []
        
        if 'is_after_hours' in df.columns:
            after_hours_risk = df[df['is_after_hours']]['risk_score'].mean()
            risk_factors.append(('After Hours', after_hours_risk))
        
        if 'is_leaver' in df.columns:
            leaver_risk = df[df['is_leaver']]['risk_score'].mean()
            risk_factors.append(('Leaver Activity', leaver_risk))
        
        if 'has_attachments' in df.columns:
            attachment_risk = df[df['has_attachments']]['risk_score'].mean()
            risk_factors.append(('Has Attachments', attachment_risk))
        
        if 'domain_type' in df.columns:
            for domain_type in df['domain_type'].unique():
                if pd.notna(domain_type):
                    domain_risk = df[df['domain_type'] == domain_type]['risk_score'].mean()
                    risk_factors.append((f'{domain_type.title()} Domain', domain_risk))
        
        if not risk_factors:
            fig = go.Figure()
            fig.add_annotation(
                text="Insufficient data for risk factor analysis",
                xref="paper", yref="paper",
                x=0.5, y=0.5, xanchor='center', yanchor='middle',
                showarrow=False, font=dict(size=16)
            )
            fig.update_layout(title="Risk Factors Analysis")
            return fig
        
        # Sort by risk score
        risk_factors.sort(key=lambda x: x[1], reverse=True)
        
        factors, scores = zip(*risk_factors)
        
        colors = ['red' if score > 50 else 'orange' if score > 30 else 'green' for score in scores]
        
        fig = go.Figure(data=[go.Bar(
            x=list(factors),
            y=list(scores),
            marker_color=colors,
            hovertemplate='<b>%{x}</b><br>Average Risk Score: %{y:.1f}<extra></extra>'
        )])
        
        fig.update_layout(
            title="Average Risk Scores by Factor",
            xaxis_title="Risk Factor",
            yaxis_title="Average Risk Score",
            xaxis_tickangle=-45,
            height=400
        )
        
        return fig
    
    def create_network_graph(self, df, max_nodes=50, layout_type='spring'):
        """Create network graph showing email relationships"""
        if df.empty or 'sender' not in df.columns:
            fig = go.Figure()
            fig.add_annotation(
                text="No network data available",
                xref="paper", yref="paper",
                x=0.5, y=0.5, xanchor='center', yanchor='middle',
                showarrow=False, font=dict(size=16)
            )
            fig.update_layout(title="Email Network")
            return fig
        
        # Create network graph
        G = nx.Graph()
        
        # Add nodes and edges
        node_data = {}
        edge_data = []
        
        # Sample data if too large
        if len(df) > max_nodes * 2:
            df_sample = df.sample(n=max_nodes * 2, random_state=42)
        else:
            df_sample = df
        
        for _, row in df_sample.iterrows():
            sender = row['sender']
            recipients = row.get('recipient_domains', [])
            risk_level = row.get('risk_level', 'Normal')
            
            # Add sender node
            if sender not in node_data:
                node_data[sender] = {
                    'type': 'sender',
                    'risk_level': risk_level,
                    'email_count': 1
                }
                G.add_node(sender)
            else:
                node_data[sender]['email_count'] += 1
            
            # Add recipient domain nodes and edges
            if isinstance(recipients, list):
                for recipient in recipients[:3]:  # Limit to first 3 recipients
                    if recipient and recipient != sender:
                        if recipient not in node_data:
                            node_data[recipient] = {
                                'type': 'domain',
                                'risk_level': 'Normal',
                                'email_count': 1
                            }
                            G.add_node(recipient)
                        else:
                            node_data[recipient]['email_count'] += 1
                        
                        # Add edge
                        if G.has_edge(sender, recipient):
                            edge_data = G.get_edge_data(sender, recipient)
                            if edge_data and 'weight' in edge_data:
                                G.edges[sender, recipient]['weight'] += 1
                            else:
                                G.edges[sender, recipient]['weight'] = 2
                        else:
                            G.add_edge(sender, recipient, weight=1)
        
        if G.number_of_nodes() == 0:
            fig = go.Figure()
            fig.add_annotation(
                text="No network connections found",
                xref="paper", yref="paper",
                x=0.5, y=0.5, xanchor='center', yanchor='middle',
                showarrow=False, font=dict(size=16)
            )
            fig.update_layout(title="Email Network")
            return fig
        
        # Limit nodes
        if G.number_of_nodes() > max_nodes:
            # Keep nodes with highest degree
            node_degrees = dict(G.degree())
            top_nodes = sorted(node_degrees.items(), key=lambda x: x[1], reverse=True)[:max_nodes]
            nodes_to_keep = [node for node, degree in top_nodes]
            G = G.subgraph(nodes_to_keep)
        
        # Calculate layout
        if layout_type == 'spring':
            pos = nx.spring_layout(G, k=1, iterations=50)
        elif layout_type == 'circular':
            pos = nx.circular_layout(G)
        else:
            pos = nx.random_layout(G)
        
        # Create edge traces
        edge_x = []
        edge_y = []
        
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
        
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=1, color='lightgray'),
            hoverinfo='none',
            mode='lines'
        )
        
        # Create node traces
        node_x = []
        node_y = []
        node_text = []
        node_colors = []
        node_sizes = []
        
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            
            node_info = node_data.get(node, {})
            risk_level = node_info.get('risk_level', 'Normal')
            email_count = node_info.get('email_count', 1)
            node_type = node_info.get('type', 'unknown')
            
            node_text.append(f"{node}<br>Type: {node_type}<br>Emails: {email_count}<br>Risk: {risk_level}")
            
            # Color by risk level
            color = self.color_palette.get(risk_level.lower().replace(' ', '_'), '#888888')
            node_colors.append(color)
            
            # Size by email count
            size = min(10 + email_count * 2, 30)
            node_sizes.append(size)
        
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            hoverinfo='text',
            text=[node.split('@')[0] for node in G.nodes()],  # Show username only
            hovertext=node_text,
            textposition="middle center",
            marker=dict(
                size=node_sizes,
                color=node_colors,
                line=dict(width=1, color='white')
            )
        )
        
        fig = go.Figure(data=[edge_trace, node_trace])
        
        fig.update_layout(
            title=dict(text="Email Network Graph", font=dict(size=16)),
            showlegend=False,
            hovermode='closest',
            margin=dict(b=20,l=5,r=5,t=40),
            annotations=[dict(
                text="Node size = email volume, Color = risk level",
                showarrow=False,
                xref="paper", yref="paper",
                x=0.005, y=-0.002, xanchor='left', yanchor='bottom',
                font=dict(color='gray', size=12)
            )],
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=500
        )
        
        return fig
