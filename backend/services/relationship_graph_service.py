import json
import logging
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timezone, timedelta
from bson import ObjectId
import asyncio

try:
    from ..db_proxy import users_collection, chats_collection, messages_collection
    from ..redis_cache import cache
    from ..models import RelationshipGraph, UserRelationship
    from ..database import get_db
except ImportError:
    from db_proxy import users_collection, chats_collection, messages_collection
    from redis_cache import cache
    from models import RelationshipGraph, UserRelationship
    from database import get_db

logger = logging.getLogger(__name__)


class RelationshipGraphService:
    """WhatsApp-style relationship graph tracking service"""
    
    def __init__(self):
        self.cache = cache
        self.graph_ttl = 180 * 24 * 60 * 60  # 6 months retention
        self.interaction_window = 90 * 24 * 60 * 60  # 90 days for interaction counting
        
    async def update_user_interaction(self, user_a_id: str, user_b_id: str, 
                                   interaction_type: str = "message", 
                                   weight: float = 1.0) -> Dict[str, Any]:
        """
        Update interaction between two users
        interaction_type: message, file_share, reaction, etc.
        weight: importance weight for this interaction
        """
        try:
            # Ensure consistent ordering (lower user_id first)
            user_pair = tuple(sorted([user_a_id, user_b_id]))
            relationship_key = f"relationship:{user_pair[0]}:{user_pair[1]}"
            
            # Get current relationship data
            current_data = await self.cache.hgetall(relationship_key) or {}
            
            # Update interaction metrics
            current_data.update({
                "user_a": user_pair[0],
                "user_b": user_pair[1],
                "interaction_count": current_data.get("interaction_count", 0) + 1,
                "last_interaction": datetime.now(timezone.utc).isoformat(),
                "interaction_type": interaction_type,
                "total_weight": current_data.get("total_weight", 0) + weight
            })
            
            # Calculate relationship strength based on interactions and weight
            interaction_count = current_data["interaction_count"]
            total_weight = current_data["total_weight"]
            
            # Relationship strength: 0.0 to 1.0 based on interaction frequency and weight
            base_strength = min(interaction_count / 50.0, 1.0)  # Cap at 1.0 for 50+ interactions
            weight_modifier = min(total_weight / 100.0, 1.0)  # Weight modifier for heavy interactions
            current_data["relationship_strength"] = max(base_strength, weight_modifier)
            
            # Determine relationship type
            if interaction_count >= 100:
                current_data["relationship_type"] = "frequent"
            elif interaction_count >= 25:
                current_data["relationship_type"] = "regular"
            elif interaction_count >= 5:
                current_data["relationship_type"] = "contact"
            else:
                current_data["relationship_type"] = "new"
            
            # Store in cache with expiration
            await self.cache.hset(relationship_key, current_data)
            await self.cache.expire(relationship_key, self.graph_ttl)
            
            # Store reverse relationship (same data)
            reverse_key = f"relationship:{user_pair[1]}:{user_pair[0]}"
            await self.cache.hset(reverse_key, current_data)
            await self.cache.expire(reverse_key, self.graph_ttl)
            
            # Update interaction frequency cache
            await self._update_interaction_frequency(user_a_id, user_b_id)
            
            logger.info(f"Updated relationship: {user_a_id} <-> {user_b_id}, strength: {current_data['relationship_strength']:.3f}")
            
            return current_data
            
        except Exception as e:
            logger.error(f"Failed to update user interaction: {e}")
            return {}
    
    async def get_user_relationships(self, user_id: str, limit: int = 50, 
                                   min_strength: float = 0.1) -> List[Dict[str, Any]]:
        """
        Get all relationships for a user, sorted by relationship strength
        """
        try:
            # Get all relationship keys for this user
            pattern1 = f"relationship:{user_id}:*"
            pattern2 = f"relationship:*:{user_id}"
            
            try:
                keys1 = await self.cache.keys(pattern1)
                keys2 = await self.cache.keys(pattern2)
            except AttributeError:
                # Fallback for mock cache that doesn't support keys()
                keys1 = []
                keys2 = []
                # For mock cache, we'll return empty relationships
                return []
            
            all_keys = list(set(keys1 + keys2))
            
            relationships = []
            for key in all_keys[:limit * 2]:  # Get more to filter and sort
                try:
                    relationship_data = await self.cache.hgetall(key)
                    if not relationship_data:
                        continue
                        
                    # Check if this relationship involves the user
                    if (relationship_data.get("user_a") == user_id or 
                        relationship_data.get("user_b") == user_id):
                        
                        # Filter by minimum strength
                        strength = float(relationship_data.get("relationship_strength", 0))
                        if strength >= min_strength:
                            relationships.append(relationship_data)
                            
                except Exception as e:
                    logger.warning(f"Error processing relationship key {key}: {e}")
                    continue
            
            # Sort by relationship strength (descending)
            relationships.sort(key=lambda x: float(x.get("relationship_strength", 0)), reverse=True)
            
            # Remove duplicates and limit
            seen_pairs = set()
            unique_relationships = []
            for rel in relationships:
                pair = tuple(sorted([rel["user_a"], rel["user_b"]]))
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    unique_relationships.append(rel)
                    if len(unique_relationships) >= limit:
                        break
            
            return unique_relationships[:limit]
            
        except Exception as e:
            logger.error(f"Failed to get user relationships: {e}")
            return []
    
    async def get_contact_suggestions(self, user_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get contact suggestions based on relationship graph
        Uses: mutual friends, frequent contacts of contacts, group co-memberships
        """
        try:
            suggestions = {}
            
            # Get user's current relationships
            user_relationships = await self.get_user_relationships(user_id, limit=100)
            
            # 1. Mutual friends (2nd degree connections)
            mutual_suggestions = await self._get_mutual_friend_suggestions(user_id, user_relationships)
            for suggestion in mutual_suggestions:
                suggestions[suggestion["user_id"]] = suggestion
            
            # 2. Frequent contacts of frequent contacts
            frequent_suggestions = await self._get_frequent_contact_suggestions(user_id, user_relationships)
            for suggestion in frequent_suggestions:
                if suggestion["user_id"] not in suggestions:
                    suggestions[suggestion["user_id"]] = suggestion
            
            # 3. Group co-memberships
            group_suggestions = await self._get_group_co_member_suggestions(user_id)
            for suggestion in group_suggestions:
                if suggestion["user_id"] not in suggestions:
                    suggestions[suggestion["user_id"]] = suggestion
            
            # Sort all suggestions by combined score
            all_suggestions = list(suggestions.values())
            all_suggestions.sort(key=lambda x: x.get("suggestion_score", 0), reverse=True)
            
            return all_suggestions[:limit]
            
        except Exception as e:
            logger.error(f"Failed to get contact suggestions: {e}")
            return []
    
    async def calculate_interaction_frequency(self, user_a: str, user_b: str, days: int = 30) -> float:
        """
        Calculate interaction frequency between two users (messages per day)
        """
        try:
            # Get interaction counter from cache
            interaction_key = f"interaction_counter:{user_a}:{user_b}"
            count = await self.cache.get(interaction_key) or 0
            
            return float(count) / max(days, 1)
            
        except Exception as e:
            logger.error(f"Failed to calculate interaction frequency: {e}")
            return 0.0
    
    async def get_relationship_strength(self, user_a: str, user_b: str) -> float:
        """
        Get relationship strength between two users (0.0 to 1.0)
        """
        try:
            user_pair = tuple(sorted([user_a, user_b]))
            relationship_key = f"relationship:{user_pair[0]}:{user_pair[1]}"
            
            relationship_data = await self.cache.hgetall(relationship_key)
            if relationship_data:
                return float(relationship_data.get("relationship_strength", 0))
            
            return 0.0
            
        except Exception as e:
            logger.error(f"Failed to get relationship strength: {e}")
            return 0.0
    
    async def update_group_memberships(self, user_id: str, group_ids: List[str]):
        """
        Update group membership information for relationship graph
        """
        try:
            for group_id in group_ids:
                # Get group members
                group = await chats_collection().find_one({"_id": group_id})
                if not group:
                    continue
                
                members = group.get("members", group.get("participants", []))
                
                # Update group co-membership tracking
                for member_id in members:
                    if member_id != user_id:
                        co_member_key = f"group_co_members:{user_id}:{member_id}"
                        group_list = await self.cache.get(co_member_key) or []
                        if group_id not in group_list:
                            group_list.append(group_id)
                            await self.cache.set(co_member_key, group_list, expire_seconds=self.graph_ttl)
            
            logger.info(f"Updated group memberships for user {user_id}")
            
        except Exception as e:
            logger.error(f"Failed to update group memberships: {e}")
    
    async def get_user_graph_summary(self, user_id: str) -> Dict[str, Any]:
        """
        Get comprehensive relationship graph summary for a user
        """
        try:
            # Get all relationships
            relationships = await self.get_user_relationships(user_id, limit=200)
            
            # Calculate statistics
            total_contacts = len(relationships)
            frequent_contacts = len([r for r in relationships if r.get("relationship_type") == "frequent"])
            regular_contacts = len([r for r in relationships if r.get("relationship_type") == "regular"])
            
            # Calculate average relationship strength
            if relationships:
                avg_strength = sum(float(r.get("relationship_strength", 0)) for r in relationships) / len(relationships)
            else:
                avg_strength = 0.0
            
            # Get interaction statistics
            interaction_stats = await self._get_user_interaction_stats(user_id)
            
            return {
                "user_id": user_id,
                "total_contacts": total_contacts,
                "frequent_contacts": frequent_contacts,
                "regular_contacts": regular_contacts,
                "average_relationship_strength": round(avg_strength, 3),
                "interaction_stats": interaction_stats,
                "generated_at": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get user graph summary: {e}")
            return {}
    
    # Private helper methods
    async def _update_interaction_frequency(self, user_a: str, user_b: str):
        """Update interaction frequency counters"""
        interaction_key = f"interaction_counter:{user_a}:{user_b}"
        reverse_key = f"interaction_counter:{user_b}:{user_a}"
        
        await self.cache.incr(interaction_key)
        await self.cache.expire(interaction_key, self.interaction_window)
        
        await self.cache.incr(reverse_key)
        await self.cache.expire(reverse_key, self.interaction_window)
    
    async def _get_mutual_friend_suggestions(self, user_id: str, user_relationships: List[Dict]) -> List[Dict]:
        """Get suggestions through mutual friends"""
        suggestions = []
        
        # Get friends of user's friends
        for rel in user_relationships[:20]:  # Limit to top 20 friends
            friend_id = rel.get("user_b") if rel.get("user_a") == user_id else rel.get("user_a")
            if not friend_id or friend_id == user_id:
                continue
                
            # Get friends of this friend
            friend_relationships = await self.get_user_relationships(friend_id, limit=20)
            
            for friend_rel in friend_relationships:
                suggested_user = (friend_rel.get("user_b") if friend_rel.get("user_a") == friend_id else friend_rel.get("user_a"))
                
                if (suggested_user and suggested_user != user_id and 
                    suggested_user not in [s.get("user_id") for s in suggestions]):
                    
                    # Calculate suggestion strength
                    user_strength = float(rel.get("relationship_strength", 0))
                    friend_strength = float(friend_rel.get("relationship_strength", 0))
                    suggestion_score = user_strength * friend_strength
                    
                    suggestions.append({
                        "user_id": suggested_user,
                        "suggestion_score": suggestion_score,
                        "mutual_friends": 1,
                        "suggestion_reason": "mutual_friend"
                    })
        
        return suggestions
    
    async def _get_frequent_contact_suggestions(self, user_id: str, user_relationships: List[Dict]) -> List[Dict]:
        """Get suggestions based on frequent contacts of user's contacts"""
        suggestions = []
        
        # Find frequent contacts
        frequent_contacts = [r for r in user_relationships if r.get("relationship_type") == "frequent"]
        
        for contact in frequent_contacts[:10]:  # Limit to top 10 frequent contacts
            contact_id = contact.get("user_b") if contact.get("user_a") == user_id else contact.get("user_a")
            if not contact_id or contact_id == user_id:
                continue
            
            # Get contacts of this frequent contact
            contact_relationships = await self.get_user_relationships(contact_id, limit=15)
            
            for contact_rel in contact_relationships:
                suggested_user = (contact_rel.get("user_b") if contact_rel.get("user_a") == contact_id else contact_rel.get("user_a"))
                
                if (suggested_user and suggested_user != user_id and 
                    suggested_user not in [s.get("user_id") for s in suggestions]):
                    
                    # Calculate suggestion strength (lower than mutual friends)
                    user_strength = float(contact.get("relationship_strength", 0))
                    contact_strength = float(contact_rel.get("relationship_strength", 0))
                    suggestion_score = user_strength * contact_strength * 0.7  # Lower weight
                    
                    suggestions.append({
                        "user_id": suggested_user,
                        "suggestion_score": suggestion_score,
                        "mutual_friends": 0,
                        "suggestion_reason": "frequent_contact_network"
                    })
        
        return suggestions
    
    async def _get_group_co_member_suggestions(self, user_id: str) -> List[Dict]:
        """Get suggestions based on group co-memberships"""
        suggestions = []
        
        # Get all group co-memberships for user
        pattern = f"group_co_members:{user_id}:*"
        keys = await self.cache.keys(pattern)
        
        co_member_counts = {}
        for key in keys:
            try:
                member_id = key.split(":")[-1]
                group_list = await self.cache.get(key) or []
                for group_id in group_list:
                    if member_id not in co_member_counts:
                        co_member_counts[member_id] = 0
                    co_member_counts[member_id] += 1
            except Exception:
                continue
        
        # Sort by co-membership count and create suggestions
        sorted_co_members = sorted(co_member_counts.items(), key=lambda x: x[1], reverse=True)
        
        for member_id, count in sorted_co_members[:20]:
            if member_id != user_id:
                suggestion_score = min(count / 5.0, 1.0)  # Normalize to 0-1 range
                
                suggestions.append({
                    "user_id": member_id,
                    "suggestion_score": suggestion_score,
                    "mutual_friends": 0,
                    "suggestion_reason": "group_co_membership"
                })
        
        return suggestions
    
    async def _get_user_interaction_stats(self, user_id: str) -> Dict[str, Any]:
        """Get interaction statistics for a user"""
        try:
            # Get all interaction counters for user
            pattern1 = f"interaction_counter:{user_id}:*"
            pattern2 = f"interaction_counter:*:{user_id}"
            
            try:
                keys1 = await self.cache.keys(pattern1)
                keys2 = await self.cache.keys(pattern2)
            except AttributeError:
                # Fallback for mock cache that doesn't support keys()
                keys1 = []
                keys2 = []
            
            all_keys = list(set(keys1 + keys2))
            
            total_interactions = 0
            unique_contacts = set()
            
            for key in all_keys:
                try:
                    count = await self.cache.get(key) or 0
                    total_interactions += count
                    
                    # Extract other user ID from key
                    parts = key.split(":")
                    if len(parts) >= 3:
                        other_user = parts[2] if parts[1] == user_id else parts[1]
                        if other_user != user_id:
                            unique_contacts.add(other_user)
                except Exception:
                    continue
            
            return {
                "total_interactions": total_interactions,
                "unique_contacts": len(unique_contacts),
                "average_interactions_per_contact": total_interactions / max(len(unique_contacts), 1),
                "interaction_frequency": "high" if total_interactions > 100 else "medium" if total_interactions > 30 else "low"
            }
            
        except Exception as e:
            logger.error(f"Failed to get user interaction stats: {e}")
            return {}

    # ==================== PERSISTENT STORAGE INTEGRATION ====================
    
    async def update_relationship_from_message(self, 
                                             sender_id: str, 
                                             receiver_id: str,
                                             message_type: str = "text",
                                             timestamp: Optional[datetime] = None) -> str:
        """Update relationship metrics from a new message (persistent storage)"""
        try:
            if timestamp is None:
                timestamp = datetime.utcnow()
            
            # Ensure consistent ordering (user_a_id < user_b_id)
            user_a_id, user_b_id = sorted([sender_id, receiver_id])
            
            # Get database connection
            db = get_db()
            collection = db['user_relationships'] if db else None
            
            if collection:
                # Update in persistent storage
                relationship = await collection.find_one({
                    "user_a_id": user_a_id,
                    "user_b_id": user_b_id
                })
                
                if not relationship:
                    # Create new relationship
                    relationship = UserRelationship(
                        user_a_id=user_a_id,
                        user_b_id=user_b_id,
                        total_messages=1,
                        messages_last_7_days=1,
                        messages_last_30_days=1,
                        first_interaction=timestamp,
                        last_interaction=timestamp,
                        relationship_strength=0.1
                    )
                    
                    result = await collection.insert_one(relationship.model_dump(by_alias=True))
                    relationship_id = str(result.inserted_id)
                else:
                    # Update existing relationship
                    now = datetime.utcnow()
                    updates = {
                        "$inc": {
                            "total_messages": 1
                        },
                        "$set": {
                            "last_interaction": timestamp,
                            "updated_at": now
                        }
                    }
                    
                    # Update time-based counts
                    if timestamp >= now - timedelta(days=7):
                        updates["$inc"]["messages_last_7_days"] = 1
                    if timestamp >= now - timedelta(days=30):
                        updates["$inc"]["messages_last_30_days"] = 1
                    
                    # Update relationship strength
                    current_total = relationship.get("total_messages", 0) + 1
                    strength = min(1.0, current_total / 100.0)
                    updates["$set"]["relationship_strength"] = strength
                    
                    result = await collection.update_one(
                        {"user_a_id": user_a_id, "user_b_id": user_b_id},
                        updates
                    )
                    relationship_id = str(relationship.upserted_id) if result.upserted_id else str(relationship["_id"])
            
            # Also update in Redis cache for real-time access
            await self.update_user_interaction(sender_id, receiver_id, "message", 1.0)
            
            return relationship_id or "cache_updated"
            
        except Exception as e:
            logger.error(f"Failed to update relationship from message: {e}")
            # Fallback to cache-only update
            await self.update_user_interaction(sender_id, receiver_id, "message", 1.0)
            return "cache_fallback"
    
    async def get_persistent_relationships(self, 
                                          user_id: str, 
                                          limit: int = 50) -> List[Dict[str, Any]]:
        """Get user's relationships from persistent storage"""
        try:
            db = get_db()
            if not db:
                # Fallback to cache
                return await self.get_user_relationships(user_id, limit)
            
            collection = db['user_relationships']
            cursor = collection.find({
                "$or": [
                    {"user_a_id": user_id},
                    {"user_b_id": user_id}
                ],
                "is_blocked": False
            }).sort("relationship_strength", -1).limit(limit)
            
            relationships = await cursor.to_list(length=limit)
            
            # Transform to user-centric format
            user_relationships = []
            for rel in relationships:
                # Determine the other user in the relationship
                other_user_id = rel["user_b_id"] if rel["user_a_id"] == user_id else rel["user_a_id"]
                
                user_relationships.append({
                    "user_id": other_user_id,
                    "relationship_type": rel.get("relationship_type", "contact"),
                    "relationship_strength": rel.get("relationship_strength", 0.0),
                    "trust_score": rel.get("trust_score", 0.0),
                    "total_messages": rel.get("total_messages", 0),
                    "messages_last_7_days": rel.get("messages_last_7_days", 0),
                    "messages_last_30_days": rel.get("messages_last_30_days", 0),
                    "first_interaction": rel.get("first_interaction"),
                    "last_interaction": rel.get("last_interaction"),
                    "is_blocked": rel.get("is_blocked", False),
                    "is_muted": rel.get("is_muted", False)
                })
            
            return user_relationships
            
        except Exception as e:
            logger.error(f"Failed to get persistent relationships: {e}")
            # Fallback to cache
            return await self.get_user_relationships(user_id, limit)


# Global instance for easy access
relationship_graph_service = RelationshipGraphService()
