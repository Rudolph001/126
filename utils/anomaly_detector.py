import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
from datetime import datetime, timedelta

class AnomalyDetector:
    """Detects anomalies in email behavior using machine learning"""
    
    def __init__(self):
        self.isolation_forest = IsolationForest(
            contamination=0.1,  # Expect 10% anomalies
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_fitted = False
    
    def detect_anomalies(self, df):
        """Detect anomalies in email data"""
        if df.empty:
            return np.array([])
        
        # Prepare features for anomaly detection
        features = self._prepare_features(df)
        
        if features.empty:
            return np.array([False] * len(df))
        
        # Fit and predict anomalies
        try:
            # Scale features
            features_scaled = self.scaler.fit_transform(features)
            
            # Detect anomalies
            anomaly_labels = self.isolation_forest.fit_predict(features_scaled)
            
            # Convert to boolean (True = anomaly)
            anomalies = anomaly_labels == -1
            
            self.is_fitted = True
            
            return anomalies
            
        except Exception as e:
            print(f"Error in anomaly detection: {e}")
            return np.array([False] * len(df))
    
    def _prepare_features(self, df):
        """Prepare numerical features for anomaly detection"""
        features = pd.DataFrame()
        
        # Time-based features
        if 'time' in df.columns:
            df_temp = df.copy()
            df_temp['time'] = pd.to_datetime(df_temp['time'], errors='coerce')
            
            features['hour'] = df_temp['time'].dt.hour
            features['day_of_week'] = df_temp['time'].dt.dayofweek
            features['is_weekend'] = (df_temp['time'].dt.dayofweek >= 5).astype(int)
        
        # Volume features
        features['recipient_count'] = pd.Series(df.get('recipient_count', [0] * len(df)))
        features['has_attachments'] = pd.Series(df.get('has_attachments', [False] * len(df))).astype(int)
        
        # Behavioral features
        features['is_after_hours'] = pd.Series(df.get('is_after_hours', [False] * len(df))).astype(int)
        features['is_leaver'] = pd.Series(df.get('is_leaver', [False] * len(df))).astype(int)
        features['has_new_domain'] = pd.Series(df.get('has_new_domain', [False] * len(df))).astype(int)
        features['has_burst_pattern'] = pd.Series(df.get('has_burst_pattern', [False] * len(df))).astype(int)
        
        # Domain features
        if 'domain_type' in df.columns:
            # One-hot encode domain types
            domain_dummies = pd.get_dummies(df['domain_type'], prefix='domain')
            features = pd.concat([features, domain_dummies], axis=1)
        
        # Department features (if available)
        if 'department' in df.columns:
            dept_counts = df['department'].value_counts()
            features['dept_frequency'] = df['department'].map(dept_counts).fillna(0)
        
        # Sender frequency features
        if 'sender' in df.columns:
            sender_counts = df['sender'].value_counts()
            features['sender_frequency'] = df['sender'].map(sender_counts)
        
        # Fill missing values
        features = features.fillna(0)
        
        return features
    
    def detect_behavioral_anomalies(self, df, sender_col='sender'):
        """Detect behavioral anomalies for individual senders"""
        if df.empty or sender_col not in df.columns:
            return np.array([False] * len(df))
        
        anomalies = np.array([False] * len(df))
        
        # Group by sender and detect anomalies within each group
        for sender in df[sender_col].unique():
            sender_mask = df[sender_col] == sender
            sender_df = df[sender_mask]
            
            if len(sender_df) < 5:  # Need minimum data points
                continue
            
            # Detect anomalies for this sender
            sender_anomalies = self._detect_sender_anomalies(sender_df)
            
            # Update main anomalies array
            anomalies[sender_mask] = sender_anomalies
        
        return anomalies
    
    def _detect_sender_anomalies(self, sender_df):
        """Detect anomalies for a specific sender"""
        if len(sender_df) < 5:
            return np.array([False] * len(sender_df))
        
        # Time-based anomalies
        time_anomalies = self._detect_time_anomalies(sender_df)
        
        # Volume anomalies
        volume_anomalies = self._detect_volume_anomalies(sender_df)
        
        # Content anomalies
        content_anomalies = self._detect_content_anomalies(sender_df)
        
        # Combine anomalies (any type = anomaly)
        combined_anomalies = time_anomalies | volume_anomalies | content_anomalies
        
        return combined_anomalies
    
    def _detect_time_anomalies(self, df):
        """Detect unusual timing patterns"""
        if 'time' not in df.columns:
            return np.array([False] * len(df))
        
        df_temp = df.copy()
        df_temp['time'] = pd.to_datetime(df_temp['time'], errors='coerce')
        df_temp['hour'] = df_temp['time'].dt.hour
        
        # Calculate sender's typical hours
        hour_counts = df_temp['hour'].value_counts()
        typical_hours = set(hour_counts[hour_counts >= 2].index)  # Hours with 2+ emails
        
        # Flag emails outside typical hours
        anomalies = ~df_temp['hour'].isin(typical_hours)
        
        return anomalies.values
    
    def _detect_volume_anomalies(self, df):
        """Detect unusual email volume patterns"""
        if 'time' not in df.columns:
            return np.array([False] * len(df))
        
        df_temp = df.copy()
        df_temp['time'] = pd.to_datetime(df_temp['time'], errors='coerce')
        df_temp['date'] = df_temp['time'].dt.date
        
        # Calculate daily email counts
        daily_counts = df_temp.groupby('date').size()
        
        if len(daily_counts) < 3:
            return np.array([False] * len(df))
        
        # Calculate z-scores for daily counts
        mean_count = daily_counts.mean()
        std_count = daily_counts.std()
        
        if std_count == 0:
            return np.array([False] * len(df))
        
        # Map back to individual emails
        df_temp['daily_count'] = df_temp['date'].map(daily_counts)
        df_temp['volume_zscore'] = (df_temp['daily_count'] - mean_count) / std_count
        
        # Flag high volume days (z-score > 2)
        volume_anomalies = df_temp['volume_zscore'] > 2
        
        return volume_anomalies.values
    
    def _detect_content_anomalies(self, df):
        """Detect unusual content patterns"""
        anomalies = np.array([False] * len(df))
        
        # Check for unusual recipient patterns
        if 'recipient_count' in df.columns:
            recipient_counts = df['recipient_count']
            if len(recipient_counts) > 3:
                mean_recipients = recipient_counts.mean()
                std_recipients = recipient_counts.std()
                
                if std_recipients > 0:
                    recipient_zscore = (recipient_counts - mean_recipients) / std_recipients
                    anomalies |= (recipient_zscore > 2)
        
        # Check for unusual attachment patterns
        if 'has_attachments' in df.columns:
            attachment_rate = df['has_attachments'].mean()
            
            # If sender rarely sends attachments, flag attachment emails
            if attachment_rate < 0.1:
                anomalies |= df['has_attachments'].astype(bool)
        
        return anomalies
    
    def cluster_anomalies(self, df, anomaly_mask):
        """Cluster anomalous emails to identify patterns"""
        if not any(anomaly_mask):
            return np.array([])
        
        anomalous_df = df[anomaly_mask]
        features = self._prepare_features(anomalous_df)
        
        if features.empty or len(features) < 3:
            return np.array([0] * sum(anomaly_mask))
        
        try:
            # Scale features
            features_scaled = self.scaler.fit_transform(features)
            
            # Cluster anomalies
            clustering = DBSCAN(eps=0.5, min_samples=2)
            cluster_labels = clustering.fit_predict(features_scaled)
            
            return cluster_labels
            
        except Exception as e:
            print(f"Error in anomaly clustering: {e}")
            return np.array([0] * sum(anomaly_mask))
    
    def get_anomaly_score(self, df):
        """Get anomaly scores for each email"""
        if df.empty:
            return np.array([])
        
        features = self._prepare_features(df)
        
        if features.empty:
            return np.array([0.0] * len(df))
        
        try:
            # Scale features
            features_scaled = self.scaler.fit_transform(features)
            
            # Get anomaly scores
            scores = self.isolation_forest.fit(features_scaled).decision_function(features_scaled)
            
            # Normalize scores to 0-100 range
            scores_normalized = ((scores - scores.min()) / (scores.max() - scores.min()) * 100)
            
            return scores_normalized
            
        except Exception as e:
            print(f"Error calculating anomaly scores: {e}")
            return np.array([0.0] * len(df))
    
    def analyze_anomaly_patterns(self, df, anomaly_mask):
        """Analyze patterns in detected anomalies"""
        if not any(anomaly_mask):
            return {}
        
        anomalous_df = df[anomaly_mask]
        normal_df = df[~anomaly_mask]
        
        analysis = {}
        
        # Time patterns
        if 'time' in df.columns:
            df_temp = df.copy()
            df_temp['time'] = pd.to_datetime(df_temp['time'], errors='coerce')
            df_temp['hour'] = df_temp['time'].dt.hour
            
            anomalous_hours = df_temp[anomaly_mask]['hour'].value_counts()
            normal_hours = df_temp[~anomaly_mask]['hour'].value_counts()
            
            analysis['time_patterns'] = {
                'anomalous_peak_hours': anomalous_hours.head(3).to_dict(),
                'normal_peak_hours': normal_hours.head(3).to_dict()
            }
        
        # Volume patterns
        if 'recipient_count' in df.columns:
            analysis['volume_patterns'] = {
                'anomalous_avg_recipients': anomalous_df['recipient_count'].mean(),
                'normal_avg_recipients': normal_df['recipient_count'].mean()
            }
        
        # Department patterns
        if 'department' in df.columns:
            anomalous_depts = anomalous_df['department'].value_counts()
            analysis['department_patterns'] = anomalous_depts.head(5).to_dict()
        
        return analysis
