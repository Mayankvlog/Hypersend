"""
Mock Database for Testing
Provides mock implementations of database collections for testing without real MongoDB
"""

import asyncio
from typing import Dict, List, Optional, Any
from unittest.mock import AsyncMock
from datetime import datetime, timezone
import uuid

# Global singleton instance for mock database
_mock_db_instance = None


class MockMongoClient:
    """Mock MongoDB client for testing"""

    def __init__(self):
        self.databases = {}

    def __getitem__(self, name):
        """Get database by name"""
        if name not in self.databases:
            self.databases[name] = MockDatabase()
        return self.databases[name]

    def close(self):
        """Mock close method"""
        pass

    async def admin_command(self, command):
        """Mock admin command"""
        return {"ok": 1}


def get_mock_db():
    """Get or create singleton mock database instance"""
    global _mock_db_instance
    if _mock_db_instance is None:
        _mock_db_instance = MockDatabase()
        print("[MOCK_DB] Created singleton mock database instance")
    return _mock_db_instance


class MockDatabase:
    """Mock database for testing"""

    def __init__(self, client=None, name="test"):
        self.client = client
        self.name = name
        self.collections = {}

    def clear_all(self):
        """Clear all collections"""
        for collection in self.collections.values():
            collection.clear()
        print(f"[MOCK_DB] Cleared all collections")

    def __getitem__(self, name):
        """Support subscriptable access for collections"""
        if name == "__await__":
            raise AttributeError(
                f"'{type(self).__name__}' object has no attribute '__await__'"
            )
        if name not in self.collections:
            self.collections[name] = MockCollection(name)
        return self.collections[name]

    def __getattr__(self, name):
        """Create collections on demand (fallback)"""
        if name == "__await__":
            raise AttributeError(
                f"'{type(self).__name__}' object has no attribute '__await__'"
            )
        if name not in self.collections:
            self.collections[name] = MockCollection(name)
        return self.collections[name]


class MockCursor:
    """Mock cursor for async iteration"""

    def __init__(self, docs):
        self.docs = docs
        self._sort_applied = False
        self._sort_field = None
        self._sort_direction = None

    def sort(self, field, direction=1):
        """Mock sort method that actually sorts the documents"""
        print(f"[MOCK_CURSOR] sort called with field={field}, direction={direction}")
        self._sort_applied = True
        self._sort_field = field
        self._sort_direction = direction

        # Apply the sorting
        if field and direction is not None:
            self.docs.sort(key=lambda x: x.get(field), reverse=(direction == -1))

        return self

    def limit(self, count):
        """Mock limit method that limits the number of documents"""
        print(f"[MOCK_CURSOR] limit called with count={count}")
        self.docs = self.docs[:count]
        return self

    async def to_list(self, length=None):
        """Mock to_list method for MongoDB cursor compatibility"""
        print(f"[MOCK_CURSOR] to_list called with length={length}")
        if length is not None:
            return self.docs[:length]
        return self.docs

    def __aiter__(self):
        """Make cursor async iterable"""

        async def async_iter():
            for doc in self.docs:
                yield doc

        return async_iter()

    def __iter__(self):
        """Make cursor sync iterable too"""
        return iter(self.docs)


class MockCollection:
    """Mock collection for testing"""

    def __init__(self, name: str):
        self.name = name
        self.data: Dict[str, Dict] = {}
        self._id_counter = 1

    def _generate_id(self):
        return str(self._id_counter)

    def clear(self):
        """Clear all data from the collection"""
        self.data.clear()
        self._id_counter = 1
        print(f"[MOCK_DB] Cleared collection: {self.name}")

    async def insert_one(self, document: Dict):
        # Use provided _id or generate one
        if "_id" not in document:
            doc_id = self._generate_id()
            document["_id"] = doc_id
        else:
            doc_id = document["_id"]

        self.data[doc_id] = document.copy()
        self._id_counter += 1
        print(f"[MOCK_DB] Inserted document with ID: {doc_id}")
        print(
            f"[MOCK_DB] Collection '{self.name}' now has {len(self.data)} documents: {list(self.data.keys())}"
        )
        result = type("InsertResult", (), {"inserted_id": doc_id})()
        return result

    async def find_one(
        self, query: Dict, projection: Dict = None, sort: List = None
    ) -> Optional[Dict]:
        """Enhanced find_one with debugging"""
        print(f"[MOCK_DB] find_one called with query: {query}")
        print(f"[MOCK_DB] Current data: {list(self.data.keys())}")

        matching_docs = []
        for doc_id, doc in self.data.items():
            print(f"[MOCK_DB] Checking doc {doc_id}: {doc}")
            if self._match_query(doc, query):
                print(f"[MOCK_DB] Found matching document: {doc_id}")
                matching_docs.append(doc.copy())

        if not matching_docs:
            print(f"[MOCK_DB] No matching document found")
            return None

        # Apply projection if provided
        if projection:
            for doc in matching_docs:
                projected_doc = {}
                for field, include in projection.items():
                    if include == 1:
                        projected_doc[field] = doc.get(field)
                matching_docs = [projected_doc]

        # Apply sorting if provided
        if sort:
            for field, direction in sort:
                matching_docs.sort(
                    key=lambda x: x.get(field), reverse=(direction == -1)
                )

        return matching_docs[0] if matching_docs else None

    async def find_one_and_update(
        self, query: Dict, update: Dict, **kwargs
    ) -> Optional[Dict]:
        for doc_id, doc in self.data.items():
            if self._match_query(doc, query):
                # Apply update
                if "$set" in update:
                    doc.update(update["$set"])
                if "$inc" in update:
                    for field, value in update["$inc"].items():
                        doc[field] = doc.get(field, 0) + value
                self.data[doc_id] = doc.copy()

                # Create result object
                result = type(
                    "UpdateResult",
                    (),
                    {"matched_count": 1, "modified_count": 1, "upserted_id": None},
                )()
                return doc.copy()

        # If no document found and upsert=True, create new one
        if kwargs.get("upsert", False):
            # Generate new ID
            new_id = str(len(self.data) + 1)
            new_doc = query.copy()

            # Apply update to new document
            if "$set" in update:
                new_doc.update(update["$set"])
            if "$inc" in update:
                for field, value in update["$inc"].items():
                    new_doc[field] = value

            self.data[new_id] = new_doc

            # Create result object
            result = type(
                "UpdateResult",
                (),
                {"matched_count": 0, "modified_count": 0, "upserted_id": new_id},
            )()
            return new_doc.copy()

        return None

    async def delete_one(self, query: Dict):
        """Delete one document matching the query"""
        print(f"[MOCK_DB] delete_one called with query: {query}")

        doc_id_to_delete = None
        for doc_id, doc in self.data.items():
            if self._match_query(doc, query):
                doc_id_to_delete = doc_id
                break

        if doc_id_to_delete:
            del self.data[doc_id_to_delete]
            print(f"[MOCK_DB] Deleted document with ID: {doc_id_to_delete}")

            result = type("DeleteResult", (), {"deleted_count": 1})()
            return result
        else:
            print(f"[MOCK_DB] No document found to delete")

            result = type("DeleteResult", (), {"deleted_count": 0})()
            return result

    async def find(self, query: Dict = None, sort: List = None) -> MockCursor:
        """Mock find that returns a cursor-like object"""
        print(f"[MOCK_DB] find called with query={query}, sort={sort}")
        docs = []
        if not query:
            docs = [doc.copy() for doc in self.data.values()]
        else:
            docs = [
                doc.copy()
                for doc in self.data.values()
                if self._match_query(doc, query)
            ]

        # Apply sorting if provided - handle the sort parameter correctly
        if sort:
            for sort_item in sort:
                if isinstance(sort_item, tuple) and len(sort_item) == 2:
                    field, direction = sort_item
                    docs.sort(key=lambda x: x.get(field), reverse=(direction == -1))
                elif isinstance(sort_item, dict):
                    # Handle MongoDB sort format like {"field": 1}
                    for field, direction in sort_item.items():
                        docs.sort(key=lambda x: x.get(field), reverse=(direction == -1))

        cursor = MockCursor(docs)
        print(f"[MOCK_DB] find returning MockCursor with {len(docs)} docs")
        return cursor

    async def update_one(self, query: Dict, update: Dict):
        for doc_id, doc in self.data.items():
            if self._match_query(doc, query):
                if "$set" in update:
                    doc.update(update["$set"])
                elif "$addToSet" in update:
                    for field, value in update["$addToSet"].items():
                        if isinstance(value, dict) and "$each" in value:
                            # Handle $addToSet with $each for adding multiple values
                            if field not in doc:
                                doc[field] = []
                            for item in value["$each"]:
                                if item not in doc[field]:
                                    doc[field].append(item)
                        else:
                            # Handle simple $addToSet
                            if field not in doc:
                                doc[field] = []
                            if value not in doc[field]:
                                doc[field].append(value)
                self.data[doc_id] = doc.copy()
                result = type(
                    "UpdateResult",
                    (),
                    {"matched_count": 1, "modified_count": 1, "upserted_id": None},
                )()
                return result
        result = type(
            "UpdateResult",
            (),
            {"matched_count": 0, "modified_count": 0, "upserted_id": None},
        )()
        return result

    async def update_many(self, query: Dict, update: Dict):
        """Mock update_many method"""
        matched_count = 0
        modified_count = 0

        for doc_id, doc in self.data.items():
            if self._match_query(doc, query):
                matched_count += 1
                if "$set" in update:
                    doc.update(update["$set"])
                    modified_count += 1
                elif "$addToSet" in update:
                    for field, value in update["$addToSet"].items():
                        if isinstance(value, dict) and "$each" in value:
                            # Handle $addToSet with $each for adding multiple values
                            if field not in doc:
                                doc[field] = []
                            for item in value["$each"]:
                                if item not in doc[field]:
                                    doc[field].append(item)
                        else:
                            # Handle simple $addToSet
                            if field not in doc:
                                doc[field] = []
                            if value not in doc[field]:
                                doc[field].append(value)
                    modified_count += 1
                self.data[doc_id] = doc.copy()

        result = type(
            "UpdateResult",
            (),
            {
                "matched_count": matched_count,
                "modified_count": modified_count,
                "upserted_id": None,
            },
        )()
        return result

    async def delete_many(self, query: Dict):
        to_delete = []
        for doc_id, doc in self.data.items():
            if self._match_query(doc, query):
                to_delete.append(doc_id)

        for doc_id in to_delete:
            del self.data[doc_id]

        result = type("DeleteResult", (), {"deleted_count": len(to_delete)})()
        return result

    def _match_query(self, doc: Dict, query: Dict) -> bool:
        """Match document against query with basic operators"""
        if not query:
            return True

        for key, value in query.items():
            if key == "$and":
                if not all(self._match_query(doc, sub_query) for sub_query in value):
                    return False
            elif key == "$or":
                if not any(self._match_query(doc, sub_query) for sub_query in value):
                    return False
            elif key == "$in":
                # This is a complex case - need to handle field name from parent context
                # For now, handle simple case where query is {"field": {"$in": [values]}}
                return True  # Simplified for now
            elif key == "$nin":
                if doc.get(key) in value:
                    return False
            elif key == "$ne":
                if doc.get(key) == value:
                    return False
            elif key == "$gt":
                if not (doc.get(key) and doc.get(key) > value):
                    return False
            elif key == "$gte":
                if not (doc.get(key) and doc.get(key) >= value):
                    return False
            elif key == "$lt":
                if not (doc.get(key) and doc.get(key) < value):
                    return False
            elif key == "$lte":
                if not (doc.get(key) and doc.get(key) <= value):
                    return False
            elif key == "$regex":
                import re

                pattern = value if isinstance(value, re.Pattern) else re.compile(value)
                if not (doc.get(key) and pattern.search(str(doc.get(key)))):
                    return False
            elif isinstance(value, dict):
                # Handle nested operators like $all
                for op, op_val in value.items():
                    if op == "$all":
                        if not all(item in doc.get(key, []) for item in op_val):
                            return False
                    elif op == "$exists":
                        if (key in doc) != op_val:
                            return False
            else:
                # Direct comparison with ObjectId support and case-insensitive email matching
                doc_val = doc.get(key)
                if key == "email":
                    # Case-insensitive email comparison
                    if doc_val and value:
                        return doc_val.lower().strip() == value.lower().strip()
                if doc_val != value:
                    # Handle string vs ObjectId comparison
                    if str(doc_val) != str(value):
                        return False
        return True


# Singleton instances for collections
_users_collection = None
_chats_collection = None
_messages_collection = None
_files_collection = None
_uploads_collection = None
_refresh_tokens_collection = None
_reset_tokens_collection = None
_media_collection = None
_group_activity_collection = None


def users_collection():
    global _users_collection
    if _users_collection is None:
        _users_collection = MockCollection("users")
    return _users_collection


def chats_collection():
    global _chats_collection
    if _chats_collection is None:
        _chats_collection = MockCollection("chats")
    return _chats_collection


def messages_collection():
    global _messages_collection
    if _messages_collection is None:
        _messages_collection = MockCollection("messages")
    return _messages_collection


def files_collection():
    global _files_collection
    if _files_collection is None:
        _files_collection = MockCollection("files")
    return _files_collection


def uploads_collection():
    global _uploads_collection
    if _uploads_collection is None:
        _uploads_collection = MockCollection("uploads")
    return _uploads_collection


def refresh_tokens_collection():
    global _refresh_tokens_collection
    if _refresh_tokens_collection is None:
        _refresh_tokens_collection = MockCollection("refresh_tokens")
    return _refresh_tokens_collection


def reset_tokens_collection():
    global _reset_tokens_collection
    if _reset_tokens_collection is None:
        _reset_tokens_collection = MockCollection("reset_tokens")
    return _reset_tokens_collection


async def connect_db():
    """Mock database connection"""
    pass


async def close_db():
    """Mock database close"""
    pass


def get_db():
    """Mock database getter"""
    return MockDatabase()


def media_collection():
    """Get media collection following singleton pattern"""
    global _media_collection
    if _media_collection is None:
        _media_collection = MockCollection("media")
    return _media_collection


def group_activity_collection():
    """Get group activity collection following singleton pattern"""
    global _group_activity_collection
    if _group_activity_collection is None:
        _group_activity_collection = MockCollection("group_activity")
    return _group_activity_collection


# Helper function for tests to clear collections
def clear_test_collections():
    """Clear all mock collections for test isolation"""
    global _users_collection, _chats_collection, _messages_collection
    global \
        _files_collection, \
        _uploads_collection, \
        _refresh_tokens_collection, \
        _reset_tokens_collection
    global _media_collection, _group_activity_collection

    print("[MOCK_DB] Clearing all collection data for test isolation")

    # Clear data from existing collections instead of recreating them
    if _users_collection is not None:
        _users_collection.clear()
        print("[MOCK_DB] Users collection cleared")
    if _chats_collection is not None:
        _chats_collection.clear()
        print("[MOCK_DB] Chats collection cleared")
    if _messages_collection is not None:
        _messages_collection.clear()
        print("[MOCK_DB] Messages collection cleared")
    if _files_collection is not None:
        _files_collection.clear()
        print("[MOCK_DB] Files collection cleared")
    if _uploads_collection is not None:
        _uploads_collection.clear()
        print("[MOCK_DB] Uploads collection cleared")
    if _refresh_tokens_collection is not None:
        _refresh_tokens_collection.clear()
        print("[MOCK_DB] Refresh tokens collection cleared")
    if _reset_tokens_collection is not None:
        _reset_tokens_collection.clear()
        print("[MOCK_DB] Reset tokens collection cleared")
    if _media_collection is not None:
        _media_collection.clear()
        print("[MOCK_DB] Media collection cleared")
    if _group_activity_collection is not None:
        _group_activity_collection.clear()
        print("[MOCK_DB] Group activity collection cleared")

    print("[MOCK_DB] All collection data cleared for test isolation")
