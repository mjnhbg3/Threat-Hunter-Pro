"""
Intelligent log clustering and cluster-level summarization.

This module implements sophisticated clustering algorithms to group related security logs
and generate high-quality summaries for each cluster. It uses multiple clustering
approaches including semantic similarity, temporal proximity, and entity relationships
to create coherent clusters that can be effectively summarized.
"""

import asyncio
import logging
import hashlib
import json
import numpy as np
from typing import List, Dict, Any, Optional, Tuple, Set
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import re

from sklearn.cluster import DBSCAN, KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
import hdbscan

from ..rag_interface.contracts import SummaryResult
from ..ai_logic import get_ai_response
from ..ner_utils import extract_entities
from .models import (
    ClusterSummary, SecurityPattern, EntityActivity, SummaryMetadata, 
    SummaryLevel, SummaryConfig
)

logger = logging.getLogger(__name__)


class LogCluster:
    """Represents a cluster of related logs with metadata."""
    
    def __init__(self, cluster_id: str, logs: List[Dict[str, Any]]):
        self.cluster_id = cluster_id
        self.logs = logs
        self.centroid_embedding: Optional[np.ndarray] = None
        self.coherence_score: float = 0.0
        self.temporal_span: timedelta = timedelta(0)
        self.common_entities: Set[str] = set()
        self.common_rules: Set[str] = set()
        self.risk_score: float = 0.0
        
    def calculate_metadata(self, embeddings: List[np.ndarray]):
        """Calculate cluster metadata from logs and embeddings."""
        if not self.logs or not embeddings:
            return
            
        # Calculate centroid embedding
        if embeddings:
            self.centroid_embedding = np.mean(embeddings, axis=0)
            
        # Calculate coherence score (inverse of variance)
        if len(embeddings) > 1:
            distances = [np.linalg.norm(emb - self.centroid_embedding) for emb in embeddings]
            self.coherence_score = 1.0 / (1.0 + np.var(distances))
        else:
            self.coherence_score = 1.0
            
        # Calculate temporal span
        timestamps = []
        for log in self.logs:
            try:
                if 'timestamp' in log:
                    if isinstance(log['timestamp'], str):
                        # Parse timestamp string
                        timestamp = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                    else:
                        timestamp = log['timestamp']
                    timestamps.append(timestamp)
            except Exception as e:
                logger.warning(f"Failed to parse timestamp: {e}")
                
        if timestamps:
            self.temporal_span = max(timestamps) - min(timestamps)
            
        # Extract common entities and rules
        all_entities = set()
        all_rules = set()
        
        for log in self.logs:
            # Extract entities from log content
            content = json.dumps(log)
            try:
                entities = extract_entities(content)
                all_entities.update(entities)
            except Exception:
                pass
                
            # Extract rule information
            if 'rule' in log and isinstance(log['rule'], dict):
                rule_id = log['rule'].get('id', '')
                rule_description = log['rule'].get('description', '')
                if rule_id:
                    all_rules.add(f"{rule_id}: {rule_description}")
                    
        # Find common entities and rules (appear in >50% of logs)
        entity_counts = Counter()
        rule_counts = Counter()
        
        for log in self.logs:
            content = json.dumps(log)
            try:
                entities = extract_entities(content)
                for entity in entities:
                    if entity in all_entities:
                        entity_counts[entity] += 1
            except Exception:
                pass
                
            if 'rule' in log and isinstance(log['rule'], dict):
                rule_id = log['rule'].get('id', '')
                rule_description = log['rule'].get('description', '')
                rule_key = f"{rule_id}: {rule_description}"
                if rule_key in all_rules:
                    rule_counts[rule_key] += 1
                    
        threshold = len(self.logs) * 0.5
        self.common_entities = {entity for entity, count in entity_counts.items() if count >= threshold}
        self.common_rules = {rule for rule, count in rule_counts.items() if count >= threshold}
        
        # Calculate risk score based on rule severity and frequency
        risk_factors = []
        for log in self.logs:
            if 'rule' in log and isinstance(log['rule'], dict):
                level = log['rule'].get('level', 0)
                risk_factors.append(int(level))
                
        if risk_factors:
            self.risk_score = np.mean(risk_factors) / 15.0  # Normalize to 0-1 scale
        else:
            self.risk_score = 0.5  # Default moderate risk


class ClusterSummarizer:
    """Handles intelligent clustering and summarization of security logs."""
    
    def __init__(self, config: SummaryConfig):
        self.config = config
        self.embedding_model = None
        self.clustering_history: Dict[str, Any] = {}
        
    async def initialize(self, embedding_model):
        """Initialize the cluster summarizer with embedding model."""
        self.embedding_model = embedding_model
        logger.info("ClusterSummarizer initialized")
        
    async def cluster_logs(self, logs: List[Dict[str, Any]], 
                          time_window_hours: Optional[int] = None) -> List[LogCluster]:
        """
        Cluster logs using intelligent multi-factor clustering.
        
        Args:
            logs: List of log entries to cluster
            time_window_hours: Optional time window for temporal clustering
            
        Returns:
            List of LogCluster objects
        """
        if not logs:
            return []
            
        if len(logs) < self.config.cluster_size_min:
            # Create single cluster if too few logs
            cluster_id = f"single_{hashlib.md5(json.dumps(logs, sort_keys=True).encode()).hexdigest()[:8]}"
            return [LogCluster(cluster_id, logs)]
            
        # Step 1: Generate embeddings for semantic clustering
        embeddings = await self._generate_embeddings(logs)
        if not embeddings:
            logger.error("Failed to generate embeddings for clustering")
            return []
            
        # Step 2: Apply temporal filtering if specified
        filtered_logs = logs
        if time_window_hours:
            filtered_logs = self._filter_by_time_window(logs, time_window_hours)
            
        # Step 3: Multi-factor clustering
        clusters = await self._multi_factor_clustering(filtered_logs, embeddings)
        
        # Step 4: Post-process clusters
        processed_clusters = await self._post_process_clusters(clusters, embeddings)
        
        logger.info(f"Clustered {len(logs)} logs into {len(processed_clusters)} clusters")
        return processed_clusters
        
    async def summarize_cluster(self, cluster: LogCluster) -> ClusterSummary:
        """
        Generate a comprehensive summary for a log cluster.
        
        Args:
            cluster: LogCluster to summarize
            
        Returns:
            ClusterSummary object
        """
        start_time = datetime.utcnow()
        
        # Extract key information from cluster
        security_patterns = await self._extract_security_patterns(cluster)
        entity_activities = await self._analyze_entity_activities(cluster)
        anomalies = await self._detect_anomalies(cluster)
        
        # Generate human-readable summary using AI
        summary_text = await self._generate_cluster_summary_text(cluster, security_patterns, entity_activities)
        key_insights = await self._extract_key_insights(cluster, security_patterns)
        
        # Create metadata
        time_range_start, time_range_end = self._get_cluster_time_range(cluster)
        metadata = SummaryMetadata(
            summary_id=f"cluster_{cluster.cluster_id}",
            level=SummaryLevel.CLUSTER,
            time_range_start=time_range_start,
            time_range_end=time_range_end,
            source_count=len(cluster.logs),
            token_count=len(summary_text.split()) * 1.3,  # Rough token estimate
            generation_time_ms=int((datetime.utcnow() - start_time).total_seconds() * 1000),
            quality_score=cluster.coherence_score,
            tags=self._generate_cluster_tags(cluster, security_patterns)
        )
        
        # Extract common elements
        common_elements = {
            "entities": list(cluster.common_entities),
            "rules": list(cluster.common_rules),
            "temporal_span_hours": cluster.temporal_span.total_seconds() / 3600,
            "geographic_spread": self._analyze_geographic_spread(cluster),
            "affected_systems": self._extract_affected_systems(cluster)
        }
        
        return ClusterSummary(
            metadata=metadata,
            cluster_id=cluster.cluster_id,
            summary_text=summary_text,
            key_insights=key_insights,
            security_patterns=security_patterns,
            entity_activities=entity_activities,
            common_elements=common_elements,
            anomalies=anomalies,
            risk_assessment=self._assess_cluster_risk(cluster, security_patterns),
            log_references=[log.get('sha256', '') for log in cluster.logs],
            clustering_method=self.config.clustering_algorithm,
            cluster_coherence=cluster.coherence_score
        )
        
    async def _generate_embeddings(self, logs: List[Dict[str, Any]]) -> List[np.ndarray]:
        """Generate embeddings for logs using the embedding model."""
        if not self.embedding_model:
            return []
            
        texts = []
        for log in logs:
            # Create embedding text from key log fields
            text_parts = []
            
            # Add rule information
            if 'rule' in log:
                rule = log['rule']
                if isinstance(rule, dict):
                    if 'description' in rule:
                        text_parts.append(rule['description'])
                    if 'groups' in rule:
                        text_parts.extend(rule['groups'])
                        
            # Add data information
            if 'data' in log:
                data = log['data']
                if isinstance(data, dict):
                    # Extract relevant data fields
                    for key, value in data.items():
                        if isinstance(value, str) and len(value) < 200:
                            text_parts.append(f"{key}: {value}")
                            
            # Add full_log if available and not too long
            if 'full_log' in log and len(str(log['full_log'])) < 500:
                text_parts.append(str(log['full_log']))
                
            texts.append(" ".join(text_parts))
            
        try:
            # Generate embeddings in batches
            embeddings = []
            batch_size = 32
            
            for i in range(0, len(texts), batch_size):
                batch = texts[i:i + batch_size]
                batch_embeddings = await asyncio.to_thread(
                    self.embedding_model.encode, batch, convert_to_numpy=True, batch_size=16
                )
                embeddings.extend(batch_embeddings)
                
            return embeddings
            
        except Exception as e:
            logger.error(f"Failed to generate embeddings: {e}")
            return []
            
    def _filter_by_time_window(self, logs: List[Dict[str, Any]], 
                              hours: int) -> List[Dict[str, Any]]:
        """Filter logs to those within the specified time window."""
        if not logs:
            return logs
            
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=hours)
        
        filtered_logs = []
        for log in logs:
            try:
                if 'timestamp' in log:
                    if isinstance(log['timestamp'], str):
                        timestamp = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                    else:
                        timestamp = log['timestamp']
                        
                    if timestamp >= cutoff:
                        filtered_logs.append(log)
            except Exception:
                # Include logs with unparseable timestamps
                filtered_logs.append(log)
                
        return filtered_logs
        
    async def _multi_factor_clustering(self, logs: List[Dict[str, Any]], 
                                     embeddings: List[np.ndarray]) -> List[LogCluster]:
        """Apply multi-factor clustering using semantic, temporal, and entity features."""
        if len(embeddings) != len(logs):
            logger.error("Mismatch between logs and embeddings count")
            return []
            
        # Convert embeddings to numpy array
        X = np.array(embeddings)
        
        # Add temporal features
        temporal_features = self._extract_temporal_features(logs)
        
        # Add entity similarity features  
        entity_features = self._extract_entity_features(logs)
        
        # Combine features
        if temporal_features is not None and entity_features is not None:
            # Normalize features
            scaler = StandardScaler()
            X_temporal = scaler.fit_transform(temporal_features)
            X_entity = scaler.fit_transform(entity_features)
            
            # Weight the features (70% semantic, 20% temporal, 10% entity)
            X_combined = np.hstack([
                X * 0.7,
                X_temporal * 0.2, 
                X_entity * 0.1
            ])
        else:
            X_combined = X
            
        # Apply clustering algorithm
        if self.config.clustering_algorithm == "hdbscan":
            clusters = await self._hdbscan_clustering(X_combined, logs)
        elif self.config.clustering_algorithm == "dbscan":
            clusters = await self._dbscan_clustering(X_combined, logs)
        elif self.config.clustering_algorithm == "kmeans":
            clusters = await self._kmeans_clustering(X_combined, logs)
        else:
            # Default to semantic clustering
            clusters = await self._semantic_clustering(X, logs)
            
        return clusters
        
    def _extract_temporal_features(self, logs: List[Dict[str, Any]]) -> Optional[np.ndarray]:
        """Extract temporal features for clustering."""
        features = []
        
        for log in logs:
            try:
                if 'timestamp' in log:
                    if isinstance(log['timestamp'], str):
                        timestamp = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                    else:
                        timestamp = log['timestamp']
                        
                    # Extract temporal features
                    hour_of_day = timestamp.hour / 24.0
                    day_of_week = timestamp.weekday() / 7.0
                    day_of_month = timestamp.day / 31.0
                    
                    # Time since epoch (normalized)
                    epoch_time = timestamp.timestamp() / (365 * 24 * 3600)  # Years since epoch
                    
                    features.append([hour_of_day, day_of_week, day_of_month, epoch_time])
                else:
                    features.append([0.0, 0.0, 0.0, 0.0])
                    
            except Exception:
                features.append([0.0, 0.0, 0.0, 0.0])
                
        return np.array(features) if features else None
        
    def _extract_entity_features(self, logs: List[Dict[str, Any]]) -> Optional[np.ndarray]:
        """Extract entity-based features for clustering."""
        # Collect all entities
        all_entities = set()
        log_entities = []
        
        for log in logs:
            content = json.dumps(log)
            try:
                entities = set(extract_entities(content))
                log_entities.append(entities)
                all_entities.update(entities)
            except Exception:
                log_entities.append(set())
                
        if not all_entities:
            return None
            
        # Create entity feature vectors (binary encoding)
        entity_list = sorted(list(all_entities))
        features = []
        
        for entities in log_entities:
            feature_vector = [1.0 if entity in entities else 0.0 for entity in entity_list]
            features.append(feature_vector)
            
        return np.array(features) if features else None
        
    async def _hdbscan_clustering(self, X: np.ndarray, logs: List[Dict[str, Any]]) -> List[LogCluster]:
        """Apply HDBSCAN clustering."""
        try:
            clusterer = hdbscan.HDBSCAN(
                min_cluster_size=max(self.config.cluster_size_min, 3),
                min_samples=max(self.config.cluster_size_min // 2, 2),
                cluster_selection_epsilon=0.1,
                metric='euclidean'
            )
            
            cluster_labels = await asyncio.to_thread(clusterer.fit_predict, X)
            return self._create_clusters_from_labels(cluster_labels, logs, X)
            
        except Exception as e:
            logger.error(f"HDBSCAN clustering failed: {e}")
            return await self._semantic_clustering(X, logs)
            
    async def _dbscan_clustering(self, X: np.ndarray, logs: List[Dict[str, Any]]) -> List[LogCluster]:
        """Apply DBSCAN clustering."""
        try:
            clusterer = DBSCAN(
                eps=0.3,
                min_samples=max(self.config.cluster_size_min, 3),
                metric='euclidean'
            )
            
            cluster_labels = await asyncio.to_thread(clusterer.fit_predict, X)
            return self._create_clusters_from_labels(cluster_labels, logs, X)
            
        except Exception as e:
            logger.error(f"DBSCAN clustering failed: {e}")
            return await self._semantic_clustering(X, logs)
            
    async def _kmeans_clustering(self, X: np.ndarray, logs: List[Dict[str, Any]]) -> List[LogCluster]:
        """Apply K-means clustering."""
        try:
            # Determine optimal number of clusters
            n_logs = len(logs)
            min_clusters = max(2, n_logs // self.config.cluster_size_max)
            max_clusters = min(10, n_logs // self.config.cluster_size_min)
            
            if min_clusters >= max_clusters:
                n_clusters = min_clusters
            else:
                # Use elbow method or silhouette analysis
                best_k = min_clusters
                best_score = -1
                
                for k in range(min_clusters, max_clusters + 1):
                    clusterer = KMeans(n_clusters=k, random_state=42, n_init=10)
                    labels = await asyncio.to_thread(clusterer.fit_predict, X)
                    
                    if len(set(labels)) > 1:  # More than one cluster
                        score = await asyncio.to_thread(silhouette_score, X, labels)
                        if score > best_score:
                            best_score = score
                            best_k = k
                            
                n_clusters = best_k
                
            clusterer = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
            cluster_labels = await asyncio.to_thread(clusterer.fit_predict, X)
            
            return self._create_clusters_from_labels(cluster_labels, logs, X)
            
        except Exception as e:
            logger.error(f"K-means clustering failed: {e}")
            return await self._semantic_clustering(X, logs)
            
    async def _semantic_clustering(self, X: np.ndarray, logs: List[Dict[str, Any]]) -> List[LogCluster]:
        """Fallback semantic clustering using simple similarity threshold."""
        clusters = []
        processed = set()
        
        for i, (log, embedding) in enumerate(zip(logs, X)):
            if i in processed:
                continue
                
            # Start new cluster
            cluster_logs = [log]
            cluster_embeddings = [embedding]
            processed.add(i)
            
            # Find similar logs
            for j, (other_log, other_embedding) in enumerate(zip(logs, X)):
                if j in processed or i == j:
                    continue
                    
                # Calculate similarity
                similarity = np.dot(embedding, other_embedding) / (
                    np.linalg.norm(embedding) * np.linalg.norm(other_embedding)
                )
                
                if similarity >= self.config.similarity_threshold:
                    cluster_logs.append(other_log)
                    cluster_embeddings.append(other_embedding)
                    processed.add(j)
                    
                    # Limit cluster size
                    if len(cluster_logs) >= self.config.cluster_size_max:
                        break
                        
            # Create cluster if it meets minimum size
            if len(cluster_logs) >= self.config.cluster_size_min:
                cluster_id = f"semantic_{hashlib.md5(json.dumps(cluster_logs, sort_keys=True).encode()).hexdigest()[:8]}"
                cluster = LogCluster(cluster_id, cluster_logs)
                cluster.calculate_metadata(cluster_embeddings)
                clusters.append(cluster)
                
        return clusters
        
    def _create_clusters_from_labels(self, labels: np.ndarray, logs: List[Dict[str, Any]], 
                                   X: np.ndarray) -> List[LogCluster]:
        """Create LogCluster objects from clustering labels."""
        clusters = []
        cluster_groups = defaultdict(list)
        cluster_embeddings = defaultdict(list)
        
        # Group logs by cluster label
        for i, label in enumerate(labels):
            if label != -1:  # -1 is noise in DBSCAN/HDBSCAN
                cluster_groups[label].append(logs[i])
                cluster_embeddings[label].append(X[i])
                
        # Create clusters that meet size requirements
        for label, cluster_logs in cluster_groups.items():
            if len(cluster_logs) >= self.config.cluster_size_min:
                cluster_id = f"cluster_{label}_{hashlib.md5(json.dumps(cluster_logs, sort_keys=True).encode()).hexdigest()[:8]}"
                cluster = LogCluster(cluster_id, cluster_logs)
                cluster.calculate_metadata(cluster_embeddings[label])
                clusters.append(cluster)
                
        return clusters
        
    async def _post_process_clusters(self, clusters: List[LogCluster], 
                                   all_embeddings: List[np.ndarray]) -> List[LogCluster]:
        """Post-process clusters to improve quality."""
        processed_clusters = []
        
        for cluster in clusters:
            # Split large clusters if they have low coherence
            if (len(cluster.logs) > self.config.cluster_size_max * 0.8 and 
                cluster.coherence_score < 0.5):
                
                sub_clusters = await self._split_cluster(cluster)
                processed_clusters.extend(sub_clusters)
            else:
                processed_clusters.append(cluster)
                
        return processed_clusters
        
    async def _split_cluster(self, cluster: LogCluster) -> List[LogCluster]:
        """Split a large, incoherent cluster into smaller clusters."""
        if len(cluster.logs) < self.config.cluster_size_min * 2:
            return [cluster]
            
        try:
            # Re-cluster the logs in this cluster
            sub_embeddings = await self._generate_embeddings(cluster.logs)
            if not sub_embeddings:
                return [cluster]
                
            X = np.array(sub_embeddings)
            n_clusters = min(3, len(cluster.logs) // self.config.cluster_size_min)
            
            clusterer = KMeans(n_clusters=n_clusters, random_state=42)
            labels = await asyncio.to_thread(clusterer.fit_predict, X)
            
            sub_clusters = self._create_clusters_from_labels(labels, cluster.logs, X)
            
            # Only return sub-clusters if they improve overall coherence
            if sub_clusters and len(sub_clusters) > 1:
                avg_coherence = np.mean([sc.coherence_score for sc in sub_clusters])
                if avg_coherence > cluster.coherence_score:
                    return sub_clusters
                    
        except Exception as e:
            logger.warning(f"Failed to split cluster: {e}")
            
        return [cluster]
        
    async def _extract_security_patterns(self, cluster: LogCluster) -> List[SecurityPattern]:
        """Extract security patterns from a cluster."""
        patterns = []
        
        # Analyze rule patterns
        rule_counter = Counter()
        severity_levels = []
        
        for log in cluster.logs:
            if 'rule' in log and isinstance(log['rule'], dict):
                rule = log['rule']
                rule_id = rule.get('id', '')
                rule_desc = rule.get('description', '')
                rule_level = rule.get('level', 0)
                
                if rule_id and rule_desc:
                    rule_counter[f"{rule_id}: {rule_desc}"] += 1
                    severity_levels.append(int(rule_level))
                    
        # Create patterns for common rules
        for rule, count in rule_counter.most_common(5):
            if count >= 2:  # At least 2 occurrences
                pattern = SecurityPattern(
                    pattern_type="rule_pattern",
                    description=f"Multiple occurrences of: {rule}",
                    confidence=min(0.9, count / len(cluster.logs)),
                    severity=self._map_level_to_severity(max(severity_levels) if severity_levels else 5),
                    occurrence_count=count,
                    first_seen=cluster.logs[0].get('timestamp', datetime.utcnow()),
                    last_seen=cluster.logs[-1].get('timestamp', datetime.utcnow()),
                    affected_systems=self._extract_affected_systems(cluster),
                    related_rules=[rule.split(':')[0]]
                )
                patterns.append(pattern)
                
        # Detect potential attack patterns
        attack_patterns = await self._detect_attack_patterns(cluster)
        patterns.extend(attack_patterns)
        
        return patterns
        
    async def _detect_attack_patterns(self, cluster: LogCluster) -> List[SecurityPattern]:
        """Detect specific attack patterns in the cluster."""
        patterns = []
        
        # Pattern detection logic
        entities = set()
        for log in cluster.logs:
            try:
                log_entities = extract_entities(json.dumps(log))  
                entities.update(log_entities)
            except Exception:
                pass
                
        # Brute force detection
        auth_failures = 0
        login_attempts = 0
        for log in cluster.logs:
            log_str = json.dumps(log).lower()
            if any(term in log_str for term in ['authentication failed', 'login failed', 'invalid password']):
                auth_failures += 1
            if any(term in log_str for term in ['login attempt', 'authentication', 'logon']):
                login_attempts += 1
                
        if auth_failures >= 5 or (login_attempts >= 10 and auth_failures >= 3):
            pattern = SecurityPattern(
                pattern_type="brute_force",
                description=f"Potential brute force attack: {auth_failures} authentication failures, {login_attempts} login attempts",
                confidence=min(0.9, (auth_failures + login_attempts) / 20),
                severity="high" if auth_failures >= 10 else "medium",
                occurrence_count=auth_failures + login_attempts,
                first_seen=cluster.logs[0].get('timestamp', datetime.utcnow()),
                last_seen=cluster.logs[-1].get('timestamp', datetime.utcnow()),
                affected_systems=list(entities)[:10],  # Limit to top 10
                related_rules=list(cluster.common_rules)[:5]
            )
            patterns.append(pattern)
            
        return patterns
        
    async def _analyze_entity_activities(self, cluster: LogCluster) -> List[EntityActivity]:
        """Analyze entity activities within the cluster."""
        entity_stats = defaultdict(lambda: {
            'events': 0,
            'rules': set(),
            'first_seen': None,
            'last_seen': None,
            'behaviors': [],
            'locations': set()
        })
        
        # Collect entity statistics
        for log in cluster.logs:
            try:
                entities = extract_entities(json.dumps(log))
                timestamp = log.get('timestamp', datetime.utcnow())
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    
                rule_id = ''
                if 'rule' in log and isinstance(log['rule'], dict):
                    rule_id = log['rule'].get('id', '')
                    
                for entity in entities:
                    stats = entity_stats[entity]
                    stats['events'] += 1
                    if rule_id:
                        stats['rules'].add(rule_id)
                    
                    if stats['first_seen'] is None or timestamp < stats['first_seen']:
                        stats['first_seen'] = timestamp
                    if stats['last_seen'] is None or timestamp > stats['last_seen']:
                        stats['last_seen'] = timestamp
                        
                    # Extract behavior information
                    log_str = json.dumps(log).lower()
                    if 'login' in log_str:
                        stats['behaviors'].append('login')
                    if 'file' in log_str:
                        stats['behaviors'].append('file_access')
                    if 'network' in log_str or 'connection' in log_str:
                        stats['behaviors'].append('network_activity')
                        
            except Exception as e:
                logger.debug(f"Failed to analyze entity activity: {e}")
                
        # Create EntityActivity objects
        activities = []
        for entity, stats in entity_stats.items():
            if stats['events'] >= 2:  # Only include entities with multiple events
                # Determine entity type
                entity_type = self._classify_entity_type(entity)
                
                # Calculate activity and risk scores
                activity_score = min(10.0, stats['events'] * len(stats['rules']))
                risk_score = min(1.0, len(stats['rules']) / 10.0)
                
                activity = EntityActivity(
                    entity=entity,
                    entity_type=entity_type,
                    activity_score=activity_score,
                    risk_score=risk_score,
                    event_count=stats['events'],
                    unique_rules=len(stats['rules']),
                    first_seen=stats['first_seen'] or datetime.utcnow(),
                    last_seen=stats['last_seen'] or datetime.utcnow(),
                    top_behaviors=list(set(stats['behaviors']))[:5],
                    geographic_locations=stats['locations']
                )
                activities.append(activity)
                
        # Sort by activity score and return top entities
        activities.sort(key=lambda x: x.activity_score, reverse=True)
        return activities[:10]
        
    def _classify_entity_type(self, entity: str) -> str:
        """Classify the type of an entity based on its format."""
        # IP address patterns
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', entity):
            return 'ip'
        if re.match(r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$', entity):
            return 'ipv6'
            
        # Domain/hostname patterns
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', entity):
            return 'hostname'
            
        # File path patterns
        if '/' in entity or '\\' in entity:
            return 'file_path'
            
        # Process patterns
        if '.exe' in entity.lower() or '.dll' in entity.lower():
            return 'process'
            
        # User patterns
        if '@' in entity:
            return 'email'
        if re.match(r'^[a-zA-Z][a-zA-Z0-9_-]*$', entity) and len(entity) < 50:
            return 'user'
            
        return 'unknown'
        
    async def _detect_anomalies(self, cluster: LogCluster) -> List[str]:
        """Detect anomalies within the cluster."""
        anomalies = []
        
        # Time-based anomalies
        timestamps = []
        for log in cluster.logs:
            try:
                if 'timestamp' in log:
                    if isinstance(log['timestamp'], str):
                        timestamp = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                    else:
                        timestamp = log['timestamp']
                    timestamps.append(timestamp)
            except Exception:
                pass
                
        if len(timestamps) > 3:
            # Check for unusual time patterns
            hours = [ts.hour for ts in timestamps]
            hour_counter = Counter(hours)
            
            # Night-time activity (11 PM - 5 AM)
            night_hours = [23, 0, 1, 2, 3, 4, 5]
            night_activity = sum(hour_counter[h] for h in night_hours)
            if night_activity > len(timestamps) * 0.7:
                anomalies.append(f"Unusual after-hours activity: {night_activity}/{len(timestamps)} events during night hours")
                
            # Weekend activity
            weekend_activity = sum(1 for ts in timestamps if ts.weekday() >= 5)
            if weekend_activity > len(timestamps) * 0.8:
                anomalies.append(f"High weekend activity: {weekend_activity}/{len(timestamps)} events on weekends")
                
        # Volume-based anomalies
        if len(cluster.logs) > self.config.cluster_size_max * 0.5:
            anomalies.append(f"High event volume: {len(cluster.logs)} events in cluster")
            
        # Severity-based anomalies
        high_severity = 0
        for log in cluster.logs:
            if 'rule' in log and isinstance(log['rule'], dict):
                level = log['rule'].get('level', 0)
                if int(level) >= 10:
                    high_severity += 1
                    
        if high_severity > len(cluster.logs) * 0.3:
            anomalies.append(f"High proportion of high-severity events: {high_severity}/{len(cluster.logs)}")
            
        return anomalies
        
    async def _generate_cluster_summary_text(self, cluster: LogCluster, 
                                           patterns: List[SecurityPattern],
                                           activities: List[EntityActivity]) -> str:
        """Generate human-readable summary text using AI."""
        # Prepare context for AI
        context = {
            "cluster_size": len(cluster.logs),
            "time_span_hours": cluster.temporal_span.total_seconds() / 3600,
            "common_entities": list(cluster.common_entities)[:10],
            "common_rules": list(cluster.common_rules)[:5],
            "security_patterns": [p.description for p in patterns[:3]],
            "top_entities": [f"{a.entity} ({a.entity_type})" for a in activities[:5]],
            "risk_score": cluster.risk_score
        }
        
        # Create AI prompt
        prompt = f"""
        Generate a concise security summary for a cluster of {context['cluster_size']} related log events spanning {context['time_span_hours']:.1f} hours.

        Key Information:
        - Common entities: {', '.join(context['common_entities'][:5]) if context['common_entities'] else 'None'}
        - Security patterns detected: {'; '.join(context['security_patterns']) if context['security_patterns'] else 'None'}
        - Top active entities: {', '.join(context['top_entities'][:3]) if context['top_entities'] else 'None'}
        - Risk assessment: {self._assess_cluster_risk(cluster, patterns)}

        Provide a 2-3 sentence summary that:
        1. Describes the main security event or pattern
        2. Identifies key entities involved
        3. Assesses the security implications
        
        Keep it concise, technical, and focused on security relevance.
        """
        
        try:
            response = await get_ai_response(prompt, model="flash-lite")
            if response and len(response) > 50:
                return response.strip()
        except Exception as e:
            logger.warning(f"AI summary generation failed: {e}")
            
        # Fallback to template-based summary
        return self._generate_template_summary(cluster, patterns, activities)
        
    def _generate_template_summary(self, cluster: LogCluster, 
                                 patterns: List[SecurityPattern],
                                 activities: List[EntityActivity]) -> str:
        """Generate template-based summary as fallback."""
        summary_parts = []
        
        # Basic cluster info
        summary_parts.append(f"Security cluster containing {len(cluster.logs)} events over {cluster.temporal_span.total_seconds() / 3600:.1f} hours.")
        
        # Patterns
        if patterns:
            top_pattern = patterns[0]
            summary_parts.append(f"Primary pattern: {top_pattern.description} (confidence: {top_pattern.confidence:.2f}).")
        
        # Entities
        if activities:
            top_entities = [a.entity for a in activities[:3]]
            summary_parts.append(f"Key entities involved: {', '.join(top_entities)}.")
            
        # Risk assessment
        risk = self._assess_cluster_risk(cluster, patterns)
        summary_parts.append(f"Risk level: {risk}.")
        
        return " ".join(summary_parts)
        
    async def _extract_key_insights(self, cluster: LogCluster, 
                                  patterns: List[SecurityPattern]) -> List[str]:
        """Extract key insights from the cluster."""
        insights = []
        
        # Pattern-based insights
        for pattern in patterns[:3]:
            insights.append(f"{pattern.pattern_type.title()} detected: {pattern.description}")
            
        # Entity-based insights
        if len(cluster.common_entities) > 0:
            insights.append(f"Common entities across events: {', '.join(list(cluster.common_entities)[:5])}")
            
        # Temporal insights
        if cluster.temporal_span.total_seconds() > 24 * 3600:
            insights.append(f"Extended activity period: {cluster.temporal_span.total_seconds() / 3600:.1f} hours")
        elif cluster.temporal_span.total_seconds() < 300:  # 5 minutes
            insights.append("Rapid sequence of events within 5 minutes")
            
        # Volume insights
        if len(cluster.logs) > 20:
            insights.append(f"High event volume: {len(cluster.logs)} related events")
            
        return insights[:5]  # Limit to top 5 insights
        
    def _assess_cluster_risk(self, cluster: LogCluster, patterns: List[SecurityPattern]) -> str:
        """Assess the overall risk level of the cluster."""
        risk_factors = []
        
        # Pattern-based risk
        if patterns:
            max_severity = max(self._map_severity_to_score(p.severity) for p in patterns)
            risk_factors.append(max_severity)
            
        # Volume-based risk
        if len(cluster.logs) > 30:
            risk_factors.append(0.8)
        elif len(cluster.logs) > 10:
            risk_factors.append(0.6)
        else:
            risk_factors.append(0.3)
            
        # Rule severity risk
        risk_factors.append(cluster.risk_score)
        
        # Calculate overall risk
        if risk_factors:
            avg_risk = np.mean(risk_factors)
            if avg_risk >= 0.8:
                return "critical"
            elif avg_risk >= 0.6:
                return "high"
            elif avg_risk >= 0.4:
                return "medium"
            else:
                return "low"
        else:
            return "medium"
            
    def _map_severity_to_score(self, severity: str) -> float:
        """Map severity string to numeric score."""
        severity_map = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.6,
            "low": 0.3
        }
        return severity_map.get(severity.lower(), 0.5)
        
    def _map_level_to_severity(self, level: int) -> str:
        """Map Wazuh rule level to severity string."""
        if level >= 12:
            return "critical"
        elif level >= 7:
            return "high"
        elif level >= 4:
            return "medium"
        else:
            return "low"
            
    def _get_cluster_time_range(self, cluster: LogCluster) -> Tuple[datetime, datetime]:
        """Get the time range covered by the cluster."""
        timestamps = []
        
        for log in cluster.logs:
            try:
                if 'timestamp' in log:
                    if isinstance(log['timestamp'], str):
                        timestamp = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                    else:
                        timestamp = log['timestamp']
                    timestamps.append(timestamp)
            except Exception:
                pass
                
        if timestamps:
            return min(timestamps), max(timestamps)
        else:
            now = datetime.utcnow()
            return now, now
            
    def _generate_cluster_tags(self, cluster: LogCluster, patterns: List[SecurityPattern]) -> Set[str]:
        """Generate tags for the cluster."""
        tags = set()
        
        # Pattern-based tags
        for pattern in patterns:
            tags.add(pattern.pattern_type)
            tags.add(pattern.severity)
            
        # Rule-based tags
        for rule in cluster.common_rules:
            if 'ssh' in rule.lower():
                tags.add('ssh')
            if 'web' in rule.lower() or 'http' in rule.lower():
                tags.add('web')
            if 'auth' in rule.lower() or 'login' in rule.lower():
                tags.add('authentication')
                
        # Volume-based tags
        if len(cluster.logs) > 50:
            tags.add('high_volume')
        elif len(cluster.logs) < 5:
            tags.add('low_volume')
            
        # Time-based tags
        if cluster.temporal_span.total_seconds() > 24 * 3600:
            tags.add('extended_duration')
        elif cluster.temporal_span.total_seconds() < 300:
            tags.add('rapid_sequence')
            
        return tags
        
    def _analyze_geographic_spread(self, cluster: LogCluster) -> Dict[str, Any]:
        """Analyze geographic spread of entities in the cluster."""
        # Placeholder for geographic analysis
        # In a real implementation, you might use IP geolocation services
        return {
            "countries": [],
            "regions": [],
            "analysis": "Geographic analysis not implemented"
        }
        
    def _extract_affected_systems(self, cluster: LogCluster) -> List[str]:
        """Extract affected systems from the cluster."""
        systems = set()
        
        for log in cluster.logs:
            # Extract system information from agent data
            if 'agent' in log and isinstance(log['agent'], dict):
                agent_name = log['agent'].get('name', '')
                if agent_name:
                    systems.add(agent_name)
                    
            # Extract from location
            if 'location' in log:
                location = log['location']
                if isinstance(location, str) and location:
                    systems.add(location.split('->')[0] if '->' in location else location)
                    
        return list(systems)[:10]  # Limit to top 10 systems