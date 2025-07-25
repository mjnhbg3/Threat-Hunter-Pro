"""
Enhanced comprehensive retrieval system for Threat Hunter.

This module provides sophisticated multi-stage retrieval capabilities that can
capture relevant logs even when they're not directly semantically similar to
the query. It uses entity-aware search strategies, expanded result sets, and
multiple search approaches to ensure comprehensive log coverage.
"""

from __future__ import annotations

import logging
import re
import json
from typing import List, Dict, Any, Set, Tuple, Optional
from collections import defaultdict, Counter

from . import state
from .vector_db import search_vector_db
from .ner_utils import extract_entities, extract_entities_with_labels


class ComprehensiveRetriever:
    """Enhanced retrieval system with multi-stage entity-aware search."""
    
    def __init__(self):
        self.entity_patterns = {
            'IP': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'HOST': r'\b[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,6}\b',
            'COMPUTER': r'\b[A-Za-z0-9\-]{2,15}-(PC|SERVER|WS|SRV|DC)\b|\b(DESKTOP|LAPTOP|SERVER|DC|WORKSTATION)-[A-Za-z0-9\-]+\b|\b[A-Za-z]{2,8}[0-9]{4,8}\b',
            'USER': r'\b(user_|admin_|service_|svc_)[A-Za-z0-9\-_]+\b|\b[A-Za-z0-9]{2,}\\[A-Za-z0-9\-_\.]+\b',
            'PROCESS': r'\b[A-Za-z0-9\-_]+\.(exe|dll|bat|cmd|ps1|sh)\b',
            'HASH': r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b',
        }
    
    async def comprehensive_search(self, query: str, max_results: int = 200) -> Dict[str, Any]:
        """
        Perform comprehensive multi-stage search to capture all relevant logs.
        
        Args:
            query: User query to search for
            max_results: Maximum total results to return
            
        Returns:
            Dictionary containing categorized search results and metadata
        """
        logging.info(f"Starting comprehensive search for: {query}")
        
        # Stage 1: Extract and analyze entities
        entities = await self._extract_and_analyze_entities(query)
        
        # Stage 2: Generate comprehensive search strategies
        search_strategies = await self._generate_search_strategies(query, entities)
        
        # Stage 3: Execute multi-stage searches
        all_results = await self._execute_multi_stage_search(search_strategies, max_results)
        
        # Stage 4: Organize and rank results
        organized_results = await self._organize_and_rank_results(all_results, query, entities)
        
        logging.info(f"Comprehensive search completed: {len(organized_results['results'])} total results")
        
        return organized_results
    
    async def _extract_and_analyze_entities(self, query: str) -> Dict[str, Any]:
        """Extract entities and generate related search terms."""
        try:
            # Extract basic entities
            basic_entities = extract_entities(query)
            labeled_entities = extract_entities_with_labels(query)
            
            # Categorize entities by type
            categorized = defaultdict(list)
            for entity, label in labeled_entities:
                categorized[label].append(entity)
            
            # Add pattern-based extraction for missed entities
            for pattern_name, pattern in self.entity_patterns.items():
                matches = re.findall(pattern, query, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0] if match[0] else str(match)
                    match = str(match).strip()
                    if match and match not in categorized[pattern_name]:
                        categorized[pattern_name].append(match)
            
            # Generate related terms for each entity
            related_terms = {}
            for entity_type, entity_list in categorized.items():
                for entity in entity_list:
                    related_terms[entity] = await self._generate_related_terms(entity, entity_type)
            
            return {
                'basic_entities': basic_entities,
                'categorized': dict(categorized),
                'related_terms': related_terms,
                'total_entities': len(basic_entities)
            }
        
        except Exception as e:
            logging.error(f"Entity extraction failed: {e}")
            return {
                'basic_entities': [],
                'categorized': {},
                'related_terms': {},
                'total_entities': 0
            }
    
    async def _generate_related_terms(self, entity: str, entity_type: str) -> List[str]:
        """Generate related search terms for an entity."""
        related_terms = [entity]  # Always include the original entity
        
        try:
            if entity_type in ['COMPUTER', 'HOST']:
                # For computers/hosts, add variations
                base_name = entity.split('.')[0].split('-')[0]
                related_terms.extend([
                    base_name,
                    f"{entity} login",
                    f"{entity} authentication",
                    f"{entity} cryptographic",
                    f"{entity} certificate",
                    f"{entity} failure",
                    f"{entity} error",
                ])
                
            elif entity_type == 'IP':
                # For IPs, add network-related terms
                ip_parts = entity.split('.')
                if len(ip_parts) == 4:
                    subnet = '.'.join(ip_parts[:3])
                    related_terms.extend([
                        f"{subnet}.*",
                        f"{entity} connection",
                        f"{entity} traffic",
                        f"{entity} suspicious",
                    ])
                    
            elif entity_type == 'USER':
                # For users, add authentication terms
                username = entity.split('\\')[-1] if '\\' in entity else entity
                related_terms.extend([
                    username,
                    f"{entity} login",
                    f"{entity} authentication",
                    f"{entity} access",
                    f"{entity} privilege",
                ])
            
            # Add generic security-related terms for all entities
            security_terms = [
                f"{entity} alert",
                f"{entity} warning",
                f"{entity} critical",
                f"{entity} suspicious activity",
                f"{entity} security event",
            ]
            related_terms.extend(security_terms)
            
        except Exception as e:
            logging.debug(f"Failed to generate related terms for {entity}: {e}")
        
        return list(set(related_terms))  # Remove duplicates
    
    async def _generate_search_strategies(self, query: str, entities: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate comprehensive search strategies."""
        strategies = []
        
        # Strategy 1: Entity-specific exact searches
        for entity_type, entity_list in entities['categorized'].items():
            for entity in entity_list:
                strategies.append({
                    'type': 'entity_exact',
                    'query': entity,
                    'keywords': [entity],
                    'k': 50,  # More results for exact matches
                    'priority': 'high',
                    'entity': entity,
                    'entity_type': entity_type
                })
        
        # Strategy 2: Related term searches
        for entity, related_terms in entities['related_terms'].items():
            for term in related_terms[:5]:  # Limit to top 5 related terms per entity
                if term != entity:  # Don't duplicate exact entity searches
                    strategies.append({
                        'type': 'related_term',
                        'query': term,
                        'keywords': [entity, term],
                        'k': 30,
                        'priority': 'medium',
                        'entity': entity,
                        'related_term': term
                    })
        
        # Strategy 3: Semantic searches with entity context
        entity_context_queries = []
        if entities['basic_entities']:
            entity_str = ' '.join(entities['basic_entities'][:5])
            entity_context_queries = [
                f"{query} {entity_str}",
                f"security events {entity_str}",
                f"authentication issues {entity_str}",
                f"cryptographic failures {entity_str}",
                f"suspicious activity {entity_str}",
            ]
        else:
            entity_context_queries = [query]
        
        for context_query in entity_context_queries:
            strategies.append({
                'type': 'semantic_context',
                'query': context_query,
                'keywords': entities['basic_entities'][:10],
                'k': 40,
                'priority': 'high',
                'context': 'entity_aware'
            })
        
        # Strategy 4: Broad contextual searches
        broad_searches = [
            query,
            f"issues problems {query}",
            f"failures errors {query}",
            f"security events {query}",
            f"alerts warnings {query}",
        ]
        
        for broad_query in broad_searches:
            strategies.append({
                'type': 'broad_context',
                'query': broad_query,
                'keywords': entities['basic_entities'][:5],
                'k': 35,
                'priority': 'medium',
                'context': 'broad'
            })
        
        # Strategy 5: Rule-based targeted searches
        rule_based_queries = self._generate_rule_based_queries(query, entities)
        for rule_query in rule_based_queries:
            strategies.append({
                'type': 'rule_based',
                'query': rule_query,
                'keywords': entities['basic_entities'][:8],
                'k': 40,
                'priority': 'high',
                'context': 'rule_targeted'
            })
        
        # Sort strategies by priority
        priority_order = {'high': 0, 'medium': 1, 'low': 2}
        strategies.sort(key=lambda x: priority_order.get(x['priority'], 2))
        
        logging.info(f"Generated {len(strategies)} search strategies")
        return strategies
    
    def _generate_rule_based_queries(self, query: str, entities: Dict[str, Any]) -> List[str]:
        """Generate targeted search queries using rule-based approach."""
        queries = []
        
        # Base security-focused queries
        security_patterns = [
            f"{query} error failure",
            f"{query} authentication login",
            f"{query} cryptographic certificate",
            f"{query} suspicious activity",
            f"{query} security event alert"
        ]
        queries.extend(security_patterns)
        
        # Entity-specific patterns
        for entity_type, entity_list in entities['categorized'].items():
            for entity in entity_list[:2]:  # Top 2 entities per type
                if entity_type in ['COMPUTER', 'HOST']:
                    queries.extend([
                        f"{entity} authentication failure",
                        f"{entity} cryptographic error",
                        f"{entity} certificate issue",
                        f"{entity} login problem"
                    ])
                elif entity_type == 'IP':
                    queries.extend([
                        f"{entity} connection suspicious",
                        f"{entity} network traffic",
                        f"{entity} security alert"
                    ])
                elif entity_type == 'USER':
                    queries.extend([
                        f"{entity} privilege escalation",
                        f"{entity} access denied",
                        f"{entity} authentication failure"
                    ])
        
        # Remove duplicates and limit
        unique_queries = list(set(queries))
        return unique_queries[:10]  # Limit to top 10 rule-based queries
    
    async def _execute_multi_stage_search(self, strategies: List[Dict[str, Any]], max_results: int) -> List[Dict[str, Any]]:
        """Execute all search strategies and collect results."""
        all_results = []
        seen_shas = set()
        results_per_strategy = max(10, max_results // len(strategies)) if strategies else max_results
        
        for i, strategy in enumerate(strategies):
            try:
                # Execute search with strategy parameters
                results = await search_vector_db(
                    strategy['query'],
                    k=min(strategy['k'], results_per_strategy),
                    keywords=strategy.get('keywords')
                )
                
                # Add strategy metadata to results
                for result in results:
                    sha = result.get('id', '')
                    if sha and sha not in seen_shas:
                        seen_shas.add(sha)
                        result['search_strategy'] = strategy['type']
                        result['search_priority'] = strategy['priority']
                        result['strategy_index'] = i
                        if 'entity' in strategy:
                            result['matched_entity'] = strategy['entity']
                        all_results.append(result)
                
                # Stop if we have enough results
                if len(all_results) >= max_results:
                    break
                    
            except Exception as e:
                logging.error(f"Search strategy failed: {strategy['type']} - {e}")
                continue
        
        logging.info(f"Executed {len(strategies)} strategies, collected {len(all_results)} unique results")
        return all_results[:max_results]
    
    async def _organize_and_rank_results(self, results: List[Dict[str, Any]], query: str, entities: Dict[str, Any]) -> Dict[str, Any]:
        """Organize and rank results by relevance and entity relationships."""
        
        # Group results by entity matches
        entity_groups = defaultdict(list)
        ungrouped_results = []
        
        for result in results:
            matched_entity = result.get('matched_entity')
            if matched_entity:
                entity_groups[matched_entity].append(result)
            else:
                ungrouped_results.append(result)
        
        # Score and rank results
        scored_results = []
        for result in results:
            score = self._calculate_relevance_score(result, query, entities)
            result['relevance_score'] = score
            scored_results.append(result)
        
        # Sort by relevance score
        scored_results.sort(key=lambda x: x['relevance_score'], reverse=True)
        
        # Create summary statistics
        strategy_stats = Counter(r['search_strategy'] for r in results)
        entity_stats = Counter(r.get('matched_entity', 'no_entity') for r in results)
        
        return {
            'results': scored_results,
            'entity_groups': dict(entity_groups),
            'ungrouped_results': ungrouped_results,
            'total_results': len(results),
            'strategy_stats': dict(strategy_stats),
            'entity_stats': dict(entity_stats),
            'search_metadata': {
                'entities_found': entities['total_entities'],
                'entity_types': list(entities['categorized'].keys()),
                'search_completeness': min(100, (len(results) / 200) * 100)
            }
        }
    
    def _calculate_relevance_score(self, result: Dict[str, Any], query: str, entities: Dict[str, Any]) -> float:
        """Calculate relevance score for a search result."""
        score = 0.0
        
        # Base score from search similarity
        base_score = result.get('hybrid_score', result.get('semantic_score', 0.5))
        score += base_score * 40  # Up to 40 points
        
        # Bonus for high-priority search strategies
        if result['search_priority'] == 'high':
            score += 20
        elif result['search_priority'] == 'medium':
            score += 10
        
        # Bonus for entity matches
        if result.get('matched_entity'):
            score += 15
        
        # Bonus for strategy type
        strategy_bonuses = {
            'entity_exact': 25,
            'ai_generated': 20,
            'semantic_context': 15,
            'related_term': 10,
            'broad_context': 5
        }
        score += strategy_bonuses.get(result['search_strategy'], 0)
        
        # Content-based scoring
        try:
            metadata = result.get('metadata', {})
            log_text = json.dumps(metadata).lower()
            
            # Bonus for security-related keywords
            security_keywords = ['error', 'failure', 'alert', 'warning', 'critical', 'suspicious', 'authentication', 'cryptographic']
            for keyword in security_keywords:
                if keyword in log_text:
                    score += 2
            
            # Bonus for entity mentions in log content
            for entity in entities['basic_entities']:
                if entity.lower() in log_text:
                    score += 5
                    
        except Exception:
            pass
        
        return min(100.0, score)  # Cap at 100


# Global retriever instance
comprehensive_retriever = ComprehensiveRetriever()


async def comprehensive_log_search(query: str, max_results: int = 200) -> Dict[str, Any]:
    """
    Main interface for comprehensive log search.
    
    Args:
        query: User query to search for
        max_results: Maximum results to return
        
    Returns:
        Comprehensive search results with metadata
    """
    return await comprehensive_retriever.comprehensive_search(query, max_results)


async def get_entity_focused_logs(entity: str, entity_type: str, max_results: int = 100) -> List[Dict[str, Any]]:
    """
    Get logs specifically focused on a particular entity.
    
    Args:
        entity: The entity to search for (e.g., computer name, IP, user)
        entity_type: Type of entity (COMPUTER, IP, USER, etc.)
        max_results: Maximum results to return
        
    Returns:
        List of relevant log entries
    """
    # Generate entity-specific search terms
    search_terms = [entity]
    
    if entity_type == 'COMPUTER':
        base_name = entity.split('.')[0].split('-')[0]
        search_terms.extend([
            f"{entity} authentication",
            f"{entity} login", 
            f"{entity} cryptographic",
            f"{entity} certificate",
            f"{entity} failure",
            f"{entity} error",
            f"{base_name} failure",
            f"{base_name} error",
        ])
    
    # Execute multiple targeted searches
    all_results = []
    seen_shas = set()
    
    for term in search_terms:
        try:
            results = await search_vector_db(term, k=20, keywords=[entity])
            for result in results:
                sha = result.get('id', '')
                if sha and sha not in seen_shas:
                    seen_shas.add(sha)
                    all_results.append(result)
                    
        except Exception as e:
            logging.error(f"Entity search failed for {term}: {e}")
    
    # Sort by relevance and return top results
    all_results.sort(key=lambda x: x.get('hybrid_score', x.get('semantic_score', 0)), reverse=True)
    return all_results[:max_results]