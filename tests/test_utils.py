#!/usr/bin/env python3
"""
Test utilities for database operations
Provides compatibility between mock and real database collections in tests
"""

import asyncio
import sys
import os

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), '..', 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

def clear_collection(collection_func):
    """Clear a collection safely for both mock and real databases"""
    try:
        collection = collection_func()
        # For mock collections with data attribute
        if hasattr(collection, 'data'):
            collection.data.clear()
            return True
        # For collections with clear method
        elif hasattr(collection, 'clear'):
            if asyncio.iscoroutinefunction(collection.clear):
                # Async clear method
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(collection.clear())
                finally:
                    loop.close()
            else:
                # Sync clear method
                collection.clear()
            return True
        # For real Motor collections, we need to delete all documents
        elif hasattr(collection, 'delete_many'):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                # For mock collections, just clear the data directly
                if hasattr(collection, 'data'):
                    collection.data.clear()
                else:
                    # Try delete_many if available, otherwise use delete_one for each doc
                    if hasattr(collection, 'delete_many'):
                        loop.run_until_complete(collection.delete_many({}))
                    elif hasattr(collection, 'delete_one'):
                        # Get all documents and delete one by one
                        async def get_all_docs():
                            docs = []
                            if hasattr(collection, 'find'):
                                cursor = collection.find({})
                                if hasattr(cursor, 'to_list'):
                                    docs = await cursor.to_list(None)
                                else:
                                    for doc in collection.data.values():
                                        docs.append(doc)
                            return docs
                        
                        all_docs = loop.run_until_complete(get_all_docs())
                        for doc in all_docs:
                            if hasattr(collection, 'delete_one'):
                                loop.run_until_complete(collection.delete_one({'_id': doc['_id']}))
                    else:
                        print(f"[TEST_UTILS] Cannot clear collection - no delete method available")
                        return False
            finally:
                loop.close()
            return True
        else:
            print(f"[TEST_UTILS] Cannot clear collection - no supported method found")
            return False
    except Exception as e:
        print(f"[TEST_UTILS] Error clearing collection: {e}")
        return False

def setup_test_document(collection_func, document):
    """Setup a test document in a collection"""
    try:
        collection = collection_func()
        # For mock collections with data attribute
        if hasattr(collection, 'data'):
            doc_id = document.get('_id', str(len(collection.data) + 1))
            collection.data[doc_id] = document
            return doc_id
        # For real collections, use insert_one
        elif hasattr(collection, 'insert_one'):
            import inspect
            insert_method = collection.insert_one
            # Check if insert_one is async
            if inspect.iscoroutinefunction(insert_method):
                # Run async insert in event loop
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    result = loop.run_until_complete(insert_method(document))
                    return result.inserted_id if hasattr(result, 'inserted_id') else None
                finally:
                    loop.close()
            else:
                # Sync insert
                result = insert_method(document)
                return result.inserted_id if hasattr(result, 'inserted_id') else None
        else:
            print(f"[TEST_UTILS] Cannot setup document - collection type {type(collection)}")
            return None
    except Exception as e:
        print(f"[TEST_UTILS] Error setting up document: {e}")
        return None

def clear_all_test_collections():
    """Clear all commonly used test collections"""
    try:
        from backend.db_proxy import (
            users_collection, chats_collection, messages_collection,
            files_collection, uploads_collection, refresh_tokens_collection,
            reset_tokens_collection
        )
        
        collections_to_clear = [
            users_collection, chats_collection, messages_collection,
            files_collection, uploads_collection, refresh_tokens_collection,
            reset_tokens_collection
        ]
        
        failed_collections = []
        for collection_func in collections_to_clear:
            result = clear_collection(collection_func)
            if not result:
                failed_collections.append(collection_func.__name__ if hasattr(collection_func, '__name__') else 'unknown')
        
        if failed_collections:
            print(f"[TEST_UTILS] Warning: Failed to clear collections: {', '.join(failed_collections)}")
            return False
            
        print("[TEST_UTILS] Cleared all test collections")
        return True
    except ImportError as e:
        print(f"[TEST_UTILS] Import error: {e}")
        return False
    except Exception as e:
        print(f"[TEST_UTILS] Error clearing collections: {e}")
        return False