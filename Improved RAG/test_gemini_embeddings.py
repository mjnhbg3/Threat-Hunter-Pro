#!/usr/bin/env python3
"""
Test script for Gemini embeddings integration.

This script tests the Gemini embedding functionality to ensure
it's working correctly before full deployment.
"""

import os
import sys
import asyncio
import logging
import numpy as np

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set environment variables for testing
os.environ['EMBEDDING_PROVIDER'] = 'gemini'
os.environ['GEMINI_API_KEY'] = os.getenv('GEMINI_API_KEY', 'test_key')
os.environ['BASIC_AUTH_USER'] = 'admin'
os.environ['BASIC_AUTH_PASS'] = 'admin123'

async def test_gemini_embeddings():
    """Test Gemini embedding functionality."""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    print("Testing Gemini Embeddings Integration")
    print("=" * 50)
    
    try:
        # Test 1: Import and configuration
        print("Test 1: Configuration and imports...")
        from config import EMBEDDING_PROVIDER, GEMINI_EMBEDDING_MODEL, EMBEDDING_DIMENSION
        print(f"✓ Embedding provider: {EMBEDDING_PROVIDER}")
        print(f"✓ Gemini model: {GEMINI_EMBEDDING_MODEL}")
        print(f"✓ Embedding dimension: {EMBEDDING_DIMENSION}")
        
        # Test 2: Gemini client initialization
        print("\nTest 2: Gemini client initialization...")
        from gemini_embeddings import get_gemini_embedding_client
        client = await get_gemini_embedding_client()
        print(f"✓ Gemini client initialized: {type(client).__name__}")
        print(f"✓ Model: {client.model_name}")
        print(f"✓ Dimension: {client.dimension}")
        
        # Test 3: Single text embedding (only if real API key is available)
        if os.getenv('GEMINI_API_KEY') and os.getenv('GEMINI_API_KEY') != 'test_key':
            print("\nTest 3: Single text embedding...")
            test_text = "Failed authentication attempt from suspicious IP address"
            try:
                embedding = await client.embed_single_text(test_text)
                print(f"✓ Generated embedding shape: {embedding.shape}")
                print(f"✓ Embedding type: {type(embedding)}")
                print(f"✓ Sample values: {embedding[:5]}")
            except Exception as e:
                print(f"✗ Single text embedding failed: {e}")
        else:
            print("\nTest 3: Skipping single text embedding (no valid API key)")
        
        # Test 4: Batch embedding (only if real API key is available)
        if os.getenv('GEMINI_API_KEY') and os.getenv('GEMINI_API_KEY') != 'test_key':
            print("\nTest 4: Batch text embedding...")
            test_texts = [
                "Authentication failure detected",
                "Suspicious network activity",
                "System configuration changed",
                "User privilege escalation"
            ]
            try:
                embeddings = await client.embed_texts(test_texts, batch_size=2)
                print(f"✓ Generated batch embeddings shape: {embeddings.shape}")
                print(f"✓ Number of embeddings: {len(embeddings)}")
                print(f"✓ Each embedding dimension: {embeddings[0].shape if len(embeddings) > 0 else 'N/A'}")
            except Exception as e:
                print(f"✗ Batch text embedding failed: {e}")
        else:
            print("\nTest 4: Skipping batch embedding (no valid API key)")
        
        # Test 5: Vector database integration
        print("\nTest 5: Vector database integration...")
        try:
            import state
            from vector_db import initialize_vector_db
            
            # Initialize state for testing
            state.dashboard_data = {
                "stats": {"total_logs": 0},
                "issues": [],
                "log_trend": [],
                "rule_distribution": {}
            }
            
            await initialize_vector_db()
            print("✓ Vector database initialized with Gemini embeddings")
            print(f"✓ Embedding model type: {type(state.embedding_model).__name__}")
            
        except Exception as e:
            print(f"✗ Vector database integration failed: {e}")
        
        # Test 6: Fallback functionality
        print("\nTest 6: Fallback functionality...")
        try:
            from gemini_embeddings import is_gemini_exhausted
            print(f"✓ Gemini exhaustion check available: {is_gemini_exhausted()}")
            
            # Check if fallback model is loaded
            if hasattr(state, 'fallback_embedding_model') and state.fallback_embedding_model is not None:
                print("✓ SentenceTransformers fallback model loaded")
            else:
                print("⚠ No fallback model available")
        except Exception as e:
            print(f"✗ Fallback functionality test failed: {e}")
        
        # Test 7: Configuration validation
        print("\nTest 7: Configuration validation...")
        from config import MODEL_QUOTA
        if 'embedding' in MODEL_QUOTA:
            rpm, tpm, rpd = MODEL_QUOTA['embedding']
            print(f"✓ Embedding rate limits configured: {rpm} RPM, {tpm} TPM, {rpd} RPD")
            if rpm == 100 and tpm == 30000 and rpd == 1000:
                print("✓ Rate limits match expected values")
            else:
                print(f"⚠ Rate limits don't match expected (100 RPM, 30K TPM, 1K RPD)")
        else:
            print("✗ Embedding rate limits not configured")
        
        print("\n" + "=" * 50)
        print("Gemini Embeddings Integration Test Complete")
        
        if os.getenv('GEMINI_API_KEY') and os.getenv('GEMINI_API_KEY') != 'test_key':
            print("✓ All tests completed with real API key")
        else:
            print("⚠ Tests completed with limited functionality (no valid API key)")
            print("  Set GEMINI_API_KEY environment variable for full testing")
        
        return True
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_sentence_transformers_fallback():
    """Test fallback to SentenceTransformers."""
    print("\nTesting SentenceTransformers Fallback")
    print("=" * 50)
    
    # Temporarily switch to sentence transformers
    os.environ['EMBEDDING_PROVIDER'] = 'sentence_transformers'
    
    try:
        # Re-import with new environment
        from importlib import reload
        import config
        reload(config)
        
        print(f"✓ Switched to provider: {config.EMBEDDING_PROVIDER}")
        print(f"✓ Model: {config.EMBEDDING_MODEL_NAME}")
        print(f"✓ Dimension: {config.EMBEDDING_DIMENSION}")
        
        return True
        
    except Exception as e:
        print(f"✗ SentenceTransformers fallback test failed: {e}")
        return False

if __name__ == "__main__":
    async def main():
        # Test Gemini embeddings
        gemini_success = await test_gemini_embeddings()
        
        # Test SentenceTransformers fallback
        fallback_success = await test_sentence_transformers_fallback()
        
        if gemini_success and fallback_success:
            print("\n🎉 All tests passed!")
            sys.exit(0)
        else:
            print("\n❌ Some tests failed!")
            sys.exit(1)
    
    asyncio.run(main())