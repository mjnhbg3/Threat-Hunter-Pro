"""
Vector database and metadata management for Threat Hunter.

This module encapsulates all interactions with the FAISS vector
database used to store and search log embeddings. It also manages
loading and saving the associated metadata and the sentence embedding
model. All stateful objects are stored on the global ``state``
object to ensure consistency across the application.
"""

from __future__ import annotations

import os
import json
import hashlib
import logging
import asyncio
import numpy as np
import faiss
from typing import List, Any, Dict

import state
from config import (
    DB_DIR,
    VECTOR_DB_FILE,
    METADATA_DB_FILE,
    EMBEDDING_MODEL_NAME,
    EMBEDDING_PROVIDER,
    EMBEDDING_DIMENSION,
    SENTENCE_TRANSFORMERS_MODEL,
)
from token_bucket import TokenBucket  # Imported to hint at rate limiting usage

from persistence import save_dashboard_data  # Needed for clear_database

# Import NER functionality for entity extraction and boosting
from ner_utils import extract_entities, initialize_ner

# Conditional imports based on embedding provider
if EMBEDDING_PROVIDER == "gemini":
    from gemini_embeddings import get_gemini_embedding_client, close_gemini_embedding_client, is_gemini_exhausted
    try:
        from sentence_transformers import SentenceTransformer
        SENTENCE_TRANSFORMERS_AVAILABLE = True
    except ImportError:
        logging.warning("SentenceTransformers not available - no fallback possible if Gemini API exhausted")
        SENTENCE_TRANSFORMERS_AVAILABLE = False
else:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True

# NEW: Import BM25 for hybrid search
try:
    import bm25s
    BM25_AVAILABLE = True
except ImportError:
    logging.warning("bm25s not available. Hybrid search disabled.")
    BM25_AVAILABLE = False
    bm25s = None


async def initialize_vector_db() -> None:
    """
    Ensure the vector database, metadata and embedding model are initialised.
    This function is idempotent and may be called multiple times. It
    creates the database directory if it does not exist, loads or
    creates the FAISS index and loads the metadata JSON file. It also
    instantiates the sentence embedding model on the first call.
    """
    logging.info(f"Creating database directory: {DB_DIR}")
    os.makedirs(DB_DIR, exist_ok=True)

    # Load the embedding model if not already loaded
    if state.embedding_model is None:
        logging.info(f"Loading embedding model using provider: {EMBEDDING_PROVIDER}...")
        try:
            if EMBEDDING_PROVIDER == "gemini":
                # For Gemini, we store the client and dimension info
                state.embedding_model = await get_gemini_embedding_client()
                state.embedding_provider = "gemini"
                embedding_dim = EMBEDDING_DIMENSION
                logging.info(f"Gemini embedding model loaded. Model: {EMBEDDING_MODEL_NAME}, Dimension: {embedding_dim}")
                
                # Pre-load SentenceTransformers as fallback if available
                if SENTENCE_TRANSFORMERS_AVAILABLE:
                    try:
                        state.fallback_embedding_model = SentenceTransformer(SENTENCE_TRANSFORMERS_MODEL)
                        logging.info(f"SentenceTransformers fallback model loaded: {SENTENCE_TRANSFORMERS_MODEL}")
                    except Exception as e:
                        logging.warning(f"Failed to load SentenceTransformers fallback: {e}")
                        state.fallback_embedding_model = None
                else:
                    state.fallback_embedding_model = None
            else:
                # For SentenceTransformers, load the model locally
                state.embedding_model = SentenceTransformer(SENTENCE_TRANSFORMERS_MODEL)
                state.embedding_provider = "sentence_transformers"
                state.fallback_embedding_model = None
                embedding_dim = state.embedding_model.get_sentence_embedding_dimension()
                logging.info(f"SentenceTransformers model loaded. Model: {SENTENCE_TRANSFORMERS_MODEL}, Dimension: {embedding_dim}")
        except Exception as e:
            logging.error(f"Failed to load embedding model: {e}")
            raise

    # Get embedding dimension based on current provider
    if hasattr(state, 'embedding_provider') and state.embedding_provider == "gemini":
        embedding_dim = EMBEDDING_DIMENSION
    else:
        embedding_dim = state.embedding_model.get_sentence_embedding_dimension()
    
    # NEW: Initialize NER for entity extraction
    try:
        initialize_ner()
        logging.info("NER initialization complete")
    except Exception as e:
        logging.warning(f"NER initialization failed: {e}. Continuing without NER.")
    
    # NEW: Initialize BM25 index for hybrid search
    if BM25_AVAILABLE:
        try:
            # Initialize empty BM25 index - will be populated when documents are added
            state.bm25_index = None  # Will be created when first documents are added
            state.bm25_corpus = []   # Store document texts for BM25
            logging.info("BM25 hybrid search initialized")
        except Exception as e:
            logging.warning(f"BM25 initialization failed: {e}. Hybrid search disabled.")
    
    # Load or create the FAISS index
    if os.path.exists(VECTOR_DB_FILE):
        logging.info("Loading existing vector database...")
        try:
            state.vector_db = faiss.read_index(VECTOR_DB_FILE)
            with open(METADATA_DB_FILE, 'r') as f:
                state.metadata_db = json.load(f)
            logging.info(f"Loaded {len(state.metadata_db)} metadata entries and {state.vector_db.ntotal} vectors")
        except Exception as e:
            logging.error(f"Failed to load vector database: {e}, creating new one")
            state.vector_db = faiss.IndexFlatL2(embedding_dim)
            state.vector_db = faiss.IndexIDMap(state.vector_db)
    else:
        logging.info("Creating new vector database.")
        state.vector_db = faiss.IndexFlatL2(embedding_dim)
        state.vector_db = faiss.IndexIDMap(state.vector_db)
        save_vector_db()
    logging.info("Vector database initialization complete.")


def save_vector_db() -> None:
    """Persist the FAISS index and metadata to disk."""
    if state.vector_db is not None:
        try:
            faiss.write_index(state.vector_db, VECTOR_DB_FILE)
            with open(METADATA_DB_FILE, 'w') as f:
                json.dump(state.metadata_db, f)
            logging.info("Vector database saved.")
        except Exception as e:
            logging.error(f"Failed to save vector database: {e}")


async def add_to_vector_db(log_entries: List[Dict[str, Any]]) -> None:
    """
    Deduplicate, embed and insert new logs into the vector database.

    This function is asynchronous as it offloads the embedding
    computation to a thread pool and uses locks to synchronise access
    to the shared FAISS index. It updates both the FAISS index and
    ``state.metadata_db``. No return value.
    """
    if not log_entries:
        return
    
    # Compute SHA256 hashes for deduplication
    unique_logs: Dict[str, Dict[str, Any]] = {}
    # Update status without awaiting since set_app_status is synchronous
    state.set_app_status("Checking for duplicates...")
    async with state.vector_lock:
        for log in log_entries:
            try:
                sha = hashlib.sha256(json.dumps(log, sort_keys=True).encode()).hexdigest()
            except Exception:
                continue
            if sha not in state.metadata_db:
                unique_logs[sha] = log
    
    if not unique_logs:
        logging.info("No new unique logs to add after deduplication")
        state.set_app_status("Ready")
        return
    
    # Prepare texts for embedding and random FAISS IDs
    texts_for_embedding: list[str] = []
    faiss_ids: list[np.int64] = []
    for sha, log in unique_logs.items():
        faiss_id = np.random.randint(0, 2**63 - 1, dtype=np.int64)
        faiss_ids.append(faiss_id)
        # Store metadata with SHA and FAISS ID
        log['sha256'] = sha
        log['faiss_id'] = int(faiss_id)
        # Create embedding text from log fields
        base_embedding_text = json.dumps({
            "timestamp": log.get("timestamp"),
            "rule": log.get("rule", {}),
            "agent": log.get("agent", {}),
            "location": log.get("location"),
            "data": log.get("data", {}),
            "full_log": log.get("full_log")
        })
        
        # NEW: Entity boosting - extract entities and repeat them for prominence
        try:
            entities = extract_entities(base_embedding_text)
            if entities:
                # Boost entities by repeating them 3 times
                entity_boost = ' '.join(entities * 3)
                boosted_text = entity_boost + ' ' + base_embedding_text
                texts_for_embedding.append(boosted_text)
                logging.debug(f"Boosted {len(entities)} entities for log {sha[:8]}")
            else:
                texts_for_embedding.append(base_embedding_text)
        except Exception as e:
            logging.warning(f"Entity extraction failed for log {sha[:8]}: {e}")
            texts_for_embedding.append(base_embedding_text)
    
    # Generate embeddings with intelligent fallback
    embeddings_list = []
    current_provider = getattr(state, 'embedding_provider', EMBEDDING_PROVIDER)
    
    if current_provider == "gemini":
        # Use Gemini embedding API with fallback
        chunk_size = 5  # Smaller chunks for strict rate limits
        gemini_exhausted = False
        
        for i in range(0, len(texts_for_embedding), chunk_size):
            chunk = texts_for_embedding[i:i+chunk_size]
            
            # Check if Gemini is exhausted and switch to fallback
            if is_gemini_exhausted() and not gemini_exhausted:
                logging.warning("Gemini API keys exhausted - switching to SentenceTransformers fallback")
                gemini_exhausted = True
                if state.fallback_embedding_model is not None:
                    state.embedding_provider = "sentence_transformers_fallback"
                    logging.info("Successfully switched to SentenceTransformers fallback")
                else:
                    logging.error("No fallback model available - continuing with zero embeddings")
            
            if not gemini_exhausted:
                # Try Gemini first
                state.set_app_status(f"Vectorizing chunk {i//chunk_size + 1}/{(len(texts_for_embedding)//chunk_size) + 1} via Gemini API")
                try:
                    chunk_embeddings = await state.embedding_model.embed_texts(chunk, batch_size=chunk_size)
                    if len(chunk_embeddings) > 0:
                        embeddings_list.append(chunk_embeddings)
                        continue
                except Exception as e:
                    logging.error(f"Failed to generate Gemini embeddings for chunk {i}: {e}")
                    # Fall through to fallback
            
            # Use fallback if Gemini failed or exhausted
            if state.fallback_embedding_model is not None:
                state.set_app_status(f"Vectorizing chunk {i//chunk_size + 1}/{(len(texts_for_embedding)//chunk_size) + 1} via fallback model")
                try:
                    chunk_embeddings = await asyncio.to_thread(
                        state.fallback_embedding_model.encode, chunk, convert_to_numpy=True, batch_size=16
                    )
                    embeddings_list.append(chunk_embeddings)
                except Exception as e:
                    logging.error(f"Failed to generate fallback embeddings for chunk {i}: {e}")
                    continue
            else:
                logging.warning(f"No embedding method available for chunk {i} - skipping")
                continue
    else:
        # Use SentenceTransformers (local model)
        chunk_size = 64
        for i in range(0, len(texts_for_embedding), chunk_size):
            chunk = texts_for_embedding[i:i+chunk_size]
            state.set_app_status(f"Vectorizing chunk {i//chunk_size + 1}/{(len(texts_for_embedding)//chunk_size) + 1} via local model")
            try:
                chunk_embeddings = await asyncio.to_thread(
                    state.embedding_model.encode, chunk, convert_to_numpy=True, batch_size=32
                )
                embeddings_list.append(chunk_embeddings)
            except Exception as e:
                logging.error(f"Failed to generate local embeddings for chunk {i}: {e}")
                continue
    
    if not embeddings_list:
        logging.error("Failed to generate any embeddings")
        state.set_app_status("Embedding generation failed")
        return
    
    embeddings = np.vstack(embeddings_list)
    
    state.set_app_status("Adding to vector database...")
    async with state.vector_lock:
        try:
            state.vector_db.add_with_ids(embeddings, np.array(faiss_ids))
            # Update metadata
            for sha, log in unique_logs.items():
                state.metadata_db[sha] = log
            
            # NEW: Update BM25 index for hybrid search
            if BM25_AVAILABLE and hasattr(state, 'bm25_corpus'):
                try:
                    # Add new document texts to BM25 corpus
                    state.bm25_corpus.extend(texts_for_embedding)
                    
                    # Rebuild BM25 index with full corpus (bm25s handles incremental updates efficiently)
                    if state.bm25_corpus:
                        # Tokenize corpus
                        corpus_tokens = []
                        for text in state.bm25_corpus:
                            # Simple tokenization - split on whitespace and punctuation
                            tokens = text.lower().replace(',', ' ').replace('.', ' ').replace(':', ' ').split()
                            corpus_tokens.append(tokens)
                        
                        # Create/update BM25 index
                        state.bm25_index = bm25s.BM25()
                        state.bm25_index.index(corpus_tokens)
                        
                        # Log available methods for debugging
                        available_methods = [method for method in dir(state.bm25_index) if not method.startswith('_')]
                        logging.debug(f"BM25 index created with {len(corpus_tokens)} documents. Available methods: {available_methods[:10]}")
                        logging.debug(f"Updated BM25 index with {len(corpus_tokens)} documents")
                except Exception as e:
                    logging.warning(f"Failed to update BM25 index: {e}")
                    
        except Exception as e:
            logging.error(f"Failed to add to FAISS: {e}")
            state.set_app_status("Vector DB update failed")
            return
    logging.info(f"Added {len(unique_logs)} new unique items to vector DB.")
    state.set_app_status("Ready")


async def search_vector_db(query_text: str, k: int = 10, keywords: List[str] = None) -> List[Dict[str, Any]]:
    """
    Perform a hybrid vector search against the FAISS index.
    
    Args:
        query_text: The search query text
        k: Number of results to return
        keywords: Optional list of keywords for hybrid search (BM25 + semantic)

    Returns:
        List of dictionaries containing the matching metadata and
        the corresponding distance/hybrid score. If the vector database is empty
        or the query is empty, an empty list is returned.
    """
    if not query_text or state.vector_db is None or state.vector_db.ntotal == 0:
        return []
    
    try:
        # NEW: Determine search strategy - hybrid vs semantic only  
        use_hybrid = (keywords and BM25_AVAILABLE and hasattr(state, 'bm25_index') and 
                     state.bm25_index is not None and hasattr(state, 'bm25_corpus') and 
                     len(state.bm25_corpus) > 0)
        
        # Step 1: Semantic search (fetch 2x candidates if using hybrid)
        search_k = k * 2 if use_hybrid else k
        
        # Generate query embedding using current provider with fallback
        current_provider = getattr(state, 'embedding_provider', EMBEDDING_PROVIDER)
        
        if current_provider == "gemini":
            # Check if Gemini is exhausted
            if is_gemini_exhausted():
                logging.warning("Gemini exhausted during search - using fallback model")
                if state.fallback_embedding_model is not None:
                    query_embedding = await asyncio.to_thread(
                        state.fallback_embedding_model.encode, [query_text], convert_to_numpy=True
                    )
                else:
                    logging.error("No fallback model available for search")
                    return []
            else:
                try:
                    query_embedding = await state.embedding_model.embed_texts([query_text])
                except Exception as e:
                    logging.error(f"Gemini embedding failed during search: {e}")
                    if state.fallback_embedding_model is not None:
                        logging.info("Falling back to SentenceTransformers for search")
                        query_embedding = await asyncio.to_thread(
                            state.fallback_embedding_model.encode, [query_text], convert_to_numpy=True
                        )
                    else:
                        return []
        else:
            query_embedding = await asyncio.to_thread(
                state.embedding_model.encode, [query_text], convert_to_numpy=True
            )
        async with state.vector_lock:
            distances, indices = state.vector_db.search(query_embedding, search_k)
        
        # Build initial results from semantic search
        semantic_results: list[Dict[str, Any]] = []
        async with state.vector_lock:
            for i, faiss_id in enumerate(indices[0]):
                if faiss_id != -1:
                    for sha, metadata in state.metadata_db.items():
                        if metadata.get('faiss_id') == faiss_id:
                            # Convert distance to similarity score (lower distance = higher similarity)
                            semantic_score = 1.0 / (1.0 + float(distances[0][i]))
                            semantic_results.append({
                                "id": sha,
                                "metadata": metadata,
                                "distance": float(distances[0][i]),
                                "semantic_score": semantic_score
                            })
                            break
        
        # Step 2: Hybrid reranking if keywords provided and BM25 available
        if use_hybrid and semantic_results:
            try:
                # Extract document texts for BM25 scoring
                doc_texts = []
                for result in semantic_results:
                    metadata = result["metadata"]
                    doc_text = json.dumps({
                        "timestamp": metadata.get("timestamp"),
                        "rule": metadata.get("rule", {}),
                        "agent": metadata.get("agent", {}),
                        "location": metadata.get("location"),
                        "data": metadata.get("data", {}),
                        "full_log": metadata.get("full_log")
                    })
                    doc_texts.append(doc_text)
                
                # Query BM25 with keywords - try different API methods
                query_tokens = ' '.join(keywords).lower().replace(',', ' ').replace('.', ' ').replace(':', ' ').split()
                bm25_scores = np.zeros(len(semantic_results))
                
                try:
                    # Try method 1: retrieve API
                    if hasattr(state.bm25_index, 'retrieve'):
                        bm25_results = await asyncio.to_thread(
                            state.bm25_index.retrieve, [query_tokens], k=len(semantic_results)
                        )
                        if bm25_results and len(bm25_results[0]) > 0:
                            bm25_doc_ids, scores = bm25_results[0]
                            for i, doc_id in enumerate(bm25_doc_ids):
                                if doc_id < len(bm25_scores):
                                    bm25_scores[doc_id] = scores[i]
                    
                    # Try method 2: get_scores API
                    elif hasattr(state.bm25_index, 'get_scores'):
                        scores = await asyncio.to_thread(state.bm25_index.get_scores, query_tokens)
                        if len(scores) == len(bm25_scores):
                            bm25_scores = scores
                    
                    # Try method 3: query API 
                    elif hasattr(state.bm25_index, 'query'):
                        query_str = ' '.join(query_tokens)
                        scores = await asyncio.to_thread(state.bm25_index.query, query_str)
                        if hasattr(scores, '__len__') and len(scores) == len(bm25_scores):
                            bm25_scores = np.array(scores)
                            
                except Exception as bm25_error:
                    logging.debug(f"BM25 query failed: {bm25_error}")
                    bm25_scores = np.zeros(len(semantic_results))
                
                # Normalize BM25 scores
                if bm25_scores.max() > 0:
                    bm25_norm = bm25_scores / bm25_scores.max()
                else:
                    bm25_norm = np.zeros_like(bm25_scores)
                
                # Compute hybrid scores (60% semantic, 40% BM25)
                for i, result in enumerate(semantic_results):
                    if i < len(bm25_norm):
                        hybrid_score = 0.6 * result["semantic_score"] + 0.4 * float(bm25_norm[i])
                        result["hybrid_score"] = hybrid_score
                        result["bm25_score"] = float(bm25_norm[i])
                    else:
                        result["hybrid_score"] = result["semantic_score"]
                        result["bm25_score"] = 0.0
                
                # Sort by hybrid score (descending) and take top k
                semantic_results.sort(key=lambda x: x["hybrid_score"], reverse=True)
                results = semantic_results[:k]
                
                logging.debug(f"Hybrid search completed: {len(results)} results with keywords {keywords}")
                
            except Exception as e:
                logging.warning(f"BM25 reranking failed: {e}. Using semantic results only.")
                results = semantic_results[:k]
        else:
            # Pure semantic search results
            results = semantic_results[:k]
            for result in results:
                result["hybrid_score"] = result["semantic_score"]
                result["bm25_score"] = 0.0
        
        return results
        
    except Exception as e:
        logging.error(f"Error in vector search: {e}")
        return []


async def clear_database() -> None:
    """Reset the FAISS index and metadata to an empty state."""
    async with state.vector_lock:
        embedding_dim = state.embedding_model.get_sentence_embedding_dimension()
        state.vector_db = faiss.IndexFlatL2(embedding_dim)
        state.vector_db = faiss.IndexIDMap(state.vector_db)
        state.metadata_db = {}
        
        # NEW: Clear BM25 index
        if BM25_AVAILABLE and hasattr(state, 'bm25_corpus'):
            state.bm25_index = None
            state.bm25_corpus = []
        
        state.dashboard_data["stats"]["total_logs"] = 0
        state.dashboard_data["issues"] = []
        state.dashboard_data["stats"]["anomalies"] = 0
        state.dashboard_data["log_trend"] = []
        state.dashboard_data["rule_distribution"] = {}
        save_vector_db()
        await save_dashboard_data()
        from .config import LOG_POSITION_FILE  # Avoid circular import at module top
        if os.path.exists(LOG_POSITION_FILE):
            os.remove(LOG_POSITION_FILE)
        logging.info("Database cleared.")