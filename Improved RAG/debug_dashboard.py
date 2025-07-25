#!/usr/bin/env python3
"""
Debug script to test dashboard API endpoint and diagnose loading issues.
"""

import sys
import os
import json
import asyncio
sys.path.append('.')

async def test_dashboard_data():
    """Test dashboard data generation and API endpoint."""
    print("=== DEBUGGING DASHBOARD DATA LOADING ===")
    print()
    
    try:
        # Import modules
        print("1. Testing imports...")
        from models import DashboardData
        from app import get_dashboard_data_api
        import state
        print("   ✓ Imports successful")
        
        # Check state initialization
        print("\n2. Checking state initialization...")
        print(f"   Dashboard data keys: {list(state.dashboard_data.keys())}")
        print(f"   Status: {state.dashboard_data.get('status', 'Unknown')}")
        print(f"   Summary: {state.dashboard_data.get('summary', 'None')}")
        print(f"   Total logs: {state.dashboard_data.get('stats', {}).get('total_logs', 0)}")
        print(f"   Issues count: {len(state.dashboard_data.get('issues', []))}")
        print(f"   Log trend length: {len(state.dashboard_data.get('log_trend', []))}")
        
        # Test model validation
        print("\n3. Testing model validation...")
        try:
            dashboard_model = DashboardData(**state.dashboard_data)
            print("   ✓ Model validation successful")
        except Exception as e:
            print(f"   ✗ Model validation failed: {e}")
            return
        
        # Test API endpoint
        print("\n4. Testing API endpoint...")
        try:
            from fastapi.security import HTTPBasicCredentials
            
            # Mock credentials for testing
            class MockCredentials:
                username = "test"
                password = "test"
            
            # Call the API function directly
            result = await get_dashboard_data_api("test_user")
            print("   ✓ API endpoint callable")
            print(f"   Response type: {type(result)}")
            
        except Exception as e:
            print(f"   ✗ API endpoint failed: {e}")
            import traceback
            traceback.print_exc()
        
        # Check vector database initialization
        print("\n5. Checking vector database...")
        try:
            from vector_db import initialize_vector_db
            print(f"   Vector DB state: {state.vector_db is not None}")
            print(f"   Metadata DB entries: {len(state.metadata_db) if state.metadata_db else 0}")
            print(f"   Embedding model loaded: {state.embedding_model is not None}")
        except Exception as e:
            print(f"   ✗ Vector DB check failed: {e}")
        
        # Check if background worker is needed
        print("\n6. Checking background processes...")
        try:
            from worker import background_worker
            print("   Background worker module loaded")
        except Exception as e:
            print(f"   Background worker issue: {e}")
        
        print("\n=== DEBUG COMPLETE ===")
        
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_dashboard_data())