"""
Named Entity Recognition utilities for Threat Hunter.

This module provides NER functionality using spaCy with custom patterns
for cybersecurity-specific entities like IPs, hostnames, and usernames.
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional

# Try to import spaCy, fall back to regex-only if not available
try:
    import spacy
    from spacy.lang.en import English
    SPACY_AVAILABLE = True
except ImportError:
    logging.warning("spaCy not available. Using regex-only entity extraction.")
    SPACY_AVAILABLE = False
    spacy = None

# Global NLP pipeline instance
nlp: Optional = None

def initialize_ner() -> None:
    """Initialize the spaCy NLP pipeline with custom entity patterns."""
    global nlp
    
    if nlp is not None:
        return  # Already initialized
    
    if not SPACY_AVAILABLE:
        logging.info("spaCy not available, using regex-only entity extraction")
        nlp = "regex_only"  # Flag to indicate regex-only mode
        return
        
    try:
        # Load the English model
        logging.info("Loading spaCy NER model...")
        nlp = spacy.load("en_core_web_sm")
        
        # Add entity ruler with cybersecurity-specific patterns
        if "entity_ruler" not in nlp.pipe_names:
            ruler = nlp.add_pipe("entity_ruler", before="ner")
            
            # Define patterns for cybersecurity entities
            patterns = [
                # IP addresses (IPv4)
                {"label": "IP", "pattern": [{"TEXT": {"REGEX": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"}}]},
                
                # Hostnames and domains
                {"label": "HOST", "pattern": [{"TEXT": {"REGEX": r"\b[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,6}\b"}}]},
                
                # Computer/system names
                {"label": "HOST", "pattern": [{"TEXT": {"REGEX": r"\b[A-Za-z0-9\-]{2,15}-(PC|SERVER|WS|SRV|DC)\b"}}]},
                {"label": "HOST", "pattern": [{"TEXT": {"REGEX": r"\b(DESKTOP|LAPTOP|SERVER|DC|WORKSTATION)-[A-Za-z0-9\-]+\b"}}]},
                
                # Usernames with common prefixes
                {"label": "USER", "pattern": [{"TEXT": {"REGEX": r"\b(user_|admin_|service_|svc_)[A-Za-z0-9\-_]+\b"}}]},
                {"label": "USER", "pattern": [{"TEXT": {"REGEX": r"\b[A-Za-z0-9]{2,}\\[A-Za-z0-9\-_\.]+\b"}}]},  # domain\username
                
                # File paths (Windows and Unix)
                {"label": "PATH", "pattern": [{"TEXT": {"REGEX": r"\b[C-Z]:\\[\\A-Za-z0-9\s\.\-_\(\)]+\b"}}]},  # Windows paths
                {"label": "PATH", "pattern": [{"TEXT": {"REGEX": r"\b/[/A-Za-z0-9\s\.\-_\(\)]+\b"}}]},  # Unix paths
                
                # Process names
                {"label": "PROCESS", "pattern": [{"TEXT": {"REGEX": r"\b[A-Za-z0-9\-_]+\.(exe|dll|bat|cmd|ps1|sh)\b"}}]},
                
                # Hash values (MD5, SHA1, SHA256)
                {"label": "HASH", "pattern": [{"TEXT": {"REGEX": r"\b[a-fA-F0-9]{32}\b"}}]},  # MD5
                {"label": "HASH", "pattern": [{"TEXT": {"REGEX": r"\b[a-fA-F0-9]{40}\b"}}]},  # SHA1
                {"label": "HASH", "pattern": [{"TEXT": {"REGEX": r"\b[a-fA-F0-9]{64}\b"}}]},  # SHA256
                
                # Port numbers
                {"label": "PORT", "pattern": [{"TEXT": {"REGEX": r"\b([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])\b"}}]},
            ]
            
            ruler.add_patterns(patterns)
            logging.info(f"Added {len(patterns)} custom entity patterns to spaCy pipeline")
        
        logging.info("spaCy NER initialization complete")
        
    except OSError as e:
        logging.error(f"Failed to load spaCy model 'en_core_web_sm': {e}")
        logging.error("Please install the model with: python -m spacy download en_core_web_sm")
        logging.warning("Falling back to regex-only entity extraction")
        nlp = "regex_only"
    except Exception as e:
        logging.error(f"Failed to initialize NER: {e}")
        logging.warning("Falling back to regex-only entity extraction")
        nlp = "regex_only"


def extract_entities_regex(text: str) -> List[str]:
    """
    Fallback regex-based entity extraction when spaCy is not available.
    
    Args:
        text: Input text to analyze
        
    Returns:
        List of unique entity strings found in the text
    """
    if not text or not text.strip():
        return []
    
    entities = []
    seen = set()
    
    # Define regex patterns for cybersecurity entities
    patterns = {
        'IP': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'HOST': r'\b[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,6}\b',
        'COMPUTER': r'\b[A-Za-z0-9\-]{2,15}-(PC|SERVER|WS|SRV|DC)\b',
        'WORKSTATION': r'\b(DESKTOP|LAPTOP|SERVER|DC|WORKSTATION)-[A-Za-z0-9\-]+\b',
        'USER': r'\b(user_|admin_|service_|svc_)[A-Za-z0-9\-_]+\b',
        'DOMAIN_USER': r'\b[A-Za-z0-9]{2,}\\\\[A-Za-z0-9\-_\.]+\b',
        'WINDOWS_PATH': r'\b[C-Z]:\\\\[\\\\A-Za-z0-9\s\.\-_\(\)]+\b',
        'UNIX_PATH': r'\b/[/A-Za-z0-9\s\.\-_\(\)]+\b',
        'PROCESS': r'\b[A-Za-z0-9\-_]+\.(exe|dll|bat|cmd|ps1|sh)\b',
        'MD5_HASH': r'\b[a-fA-F0-9]{32}\b',
        'SHA1_HASH': r'\b[a-fA-F0-9]{40}\b',
        'SHA256_HASH': r'\b[a-fA-F0-9]{64}\b',
    }
    
    # Extract entities using regex patterns
    for pattern_name, pattern in patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                # Handle tuple results from regex groups
                entity_text = match[0] if match[0] else str(match)
            else:
                entity_text = str(match)
            
            entity_text = entity_text.strip()
            if entity_text and entity_text not in seen:
                entities.append(entity_text)
                seen.add(entity_text)
    
    return entities


def extract_entities(text: str) -> List[str]:
    """
    Extract named entities from text using spaCy or regex fallback.
    
    Args:
        text: Input text to analyze
        
    Returns:
        List of unique entity strings found in the text
    """
    if not text or not text.strip():
        return []
        
    if nlp is None:
        initialize_ner()
    
    # Use regex fallback if spaCy is not available
    if nlp == "regex_only":
        return extract_entities_regex(text)
    
    try:
        # Process the text with spaCy
        doc = nlp(text)
        
        # Extract entities, focusing on cybersecurity-relevant types
        relevant_labels = {
            "PERSON",    # People names
            "ORG",       # Organizations
            "GPE",       # Geopolitical entities (countries, cities)
            "IP",        # IP addresses (custom)
            "HOST",      # Hostnames/computer names (custom)
            "USER",      # Usernames (custom)
            "PATH",      # File paths (custom)
            "PROCESS",   # Process names (custom)
            "HASH",      # Hash values (custom)
            "PORT",      # Port numbers (custom)
        }
        
        entities = []
        seen = set()
        
        for ent in doc.ents:
            if ent.label_ in relevant_labels:
                entity_text = ent.text.strip()
                if entity_text and entity_text not in seen:
                    entities.append(entity_text)
                    seen.add(entity_text)
        
        # Log extracted entities only at debug level to reduce verbosity
        if entities:
            logging.debug(f"Extracted entities: {entities}")
        
        return entities
        
    except Exception as e:
        logging.error(f"Error extracting entities from text: {e}")
        return []


def extract_entities_with_labels(text: str) -> List[tuple[str, str]]:
    """
    Extract named entities with their labels from text.
    
    Args:
        text: Input text to analyze
        
    Returns:
        List of (entity_text, label) tuples
    """
    if not text or not text.strip():
        return []
        
    if nlp is None:
        initialize_ner()
    
    # Use basic regex fallback if spaCy is not available (without labels)
    if nlp == "regex_only":
        entities = extract_entities_regex(text)
        return [(entity, "UNKNOWN") for entity in entities]
    
    try:
        doc = nlp(text)
        
        relevant_labels = {
            "PERSON", "ORG", "GPE", "IP", "HOST", "USER", 
            "PATH", "PROCESS", "HASH", "PORT"
        }
        
        entities = []
        seen = set()
        
        for ent in doc.ents:
            if ent.label_ in relevant_labels:
                entity_text = ent.text.strip()
                entity_key = (entity_text, ent.label_)
                if entity_text and entity_key not in seen:
                    entities.append((entity_text, ent.label_))
                    seen.add(entity_key)
        
        return entities
        
    except Exception as e:
        logging.error(f"Error extracting entities with labels: {e}")
        return []