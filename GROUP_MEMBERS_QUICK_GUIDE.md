# 🚀 Group Members Add करना - Quick Reference Guide

## त्वरित शुरुआत (5 मिनट में!)

### Step 1: Login करें
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "your-email@example.com",
    "password": "your-password"
  }'

# Response से TOKEN copy करें (access_token का value)
```

### Step 2: Group ID खोजें
```bash
# अपने सभी groups देखें
curl -X GET http://localhost:8000/api/v1/groups \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"

# Response से अपने group की _id copy करें
```

### Step 3: Members Add करें
```bash
curl -X POST http://localhost:8000/api/v1/groups/YOUR_GROUP_ID/members \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "user_ids": ["user_id_1", "user_id_2", "user_id_3"]
  }'

# ✅ Response: {"added": 3, "member_count": 6, ...}
```

---

## Requirements (जरूरी चीजें)

```
✅ Admin होना चाहिए
✅ Valid Access Token
✅ Correct Group ID
✅ Valid User IDs
```

---

## API Endpoints

### Endpoint Details
| Action | Method | URL | Auth |
|--------|--------|-----|------|
| Login | POST | /api/v1/auth/login | No |
| List Groups | GET | /api/v1/groups | Yes |
| Get Group Info | GET | /api/v1/groups/{group_id} | Yes |
| **Add Members** | **POST** | **/api/v1/groups/{group_id}/members** | **Yes** |
| Search Members | GET | /api/v1/groups/{group_id}/members/suggestions | Yes |

---

## Request/Response

### ✅ Successful Request
```json
Request:
POST /api/v1/groups/group_123/members
Authorization: Bearer eyJ0eXA...

{
  "user_ids": ["user_4", "user_5"]
}

Response (200):
{
  "added": 2,
  "member_count": 5,
  "members": ["user_1", "user_2", "user_3", "user_4", "user_5"]
}
```

### ❌ Error Cases
```json
401 - Not Authenticated
{ "detail": "Not authenticated" }

403 - Not Admin
{ "detail": "Only admins can add members" }

404 - Group Not Found
{ "detail": "Group not found" }

400 - Invalid Request
{ "detail": "Invalid input" }
```

---

## Frontend Code (Copy-Paste Ready)

### JavaScript/Fetch
```javascript
async function addMembersToGroup(groupId, userIds, token) {
  const response = await fetch(
    `http://localhost:8000/api/v1/groups/${groupId}/members`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ user_ids: userIds })
    }
  );

  if (response.ok) {
    const data = await response.json();
    console.log(`✅ Added ${data.added} members`);
    return data;
  } else {
    const error = await response.json();
    console.error(`❌ Error: ${error.detail}`);
    throw error;
  }
}

// Usage:
addMembersToGroup('group_123', ['user_4', 'user_5'], 'your_token');
```

### React Hook
```javascript
import { useState } from 'react';

function useAddGroupMembers(groupId, token) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const addMembers = async (userIds) => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch(
        `http://localhost:8000/api/v1/groups/${groupId}/members`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ user_ids: userIds })
        }
      );

      if (!response.ok) {
        throw new Error(await response.json());
      }

      const data = await response.json();
      return data;
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  return { addMembers, loading, error };
}

// Usage in Component:
const { addMembers, loading, error } = useAddGroupMembers(groupId, token);
```

---

## Common Issues & Fix

### Problem 1: "Only admins can add members"
```
समस्या: आप admin नहीं हैं

Fix:
1. अपना group check करें
2. Group के admin से बात करें
3. या नया group बनाएं (आप automatically admin होंगे)
```

### Problem 2: "Group not found"
```
समस्या: Group ID गलत है या आप member नहीं हैं

Fix:
1. सभी groups list करें: GET /api/v1/groups
2. Correct group ID use करें
3. Check करें कि आप group में हैं
```

### Problem 3: "Not authenticated"
```
समस्या: Token invalid या expired है

Fix:
1. Re-login करें
2. नया token generate करें
3. Authorization header में Bearer {token} लगाएं
```

### Problem 4: Members नहीं add हुए
```
समस्या: सभी users पहले से group में हैं

Fix:
1. नए users की IDs भेजें
2. पहले group info check करें: GET /api/v1/groups/{id}
3. Current members से different users भेजें
```

---

## Testing

### Test with cURL
```bash
# 1. Login
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"pass"}' | jq -r '.access_token')

# 2. List Groups
curl -X GET http://localhost:8000/api/v1/groups \
  -H "Authorization: Bearer $TOKEN" | jq

# 3. Add Members
curl -X POST http://localhost:8000/api/v1/groups/GROUP_ID/members \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_ids":["user_1","user_2"]}'
```

### Test with Postman
```
1. Create new POST request
2. URL: http://localhost:8000/api/v1/groups/{group_id}/members
3. Headers:
   - Authorization: Bearer {your_token}
   - Content-Type: application/json
4. Body (raw JSON):
   {
     "user_ids": ["user_id_1", "user_id_2"]
   }
5. Send and check response
```

---

## Important Notes

```
📌 Only Admin can add members to group
📌 Users must exist in system
📌 Token must be valid (not expired)
📌 Group ID must be correct
📌 User IDs must be valid (non-empty strings)
📌 Same user can't be added twice
📌 Current user is automatically in group
📌 Activity is logged for audit trail
```

---

## Quick Checklist

```
Before Sending Request:
□ क्या मैं admin हूँ?
□ क्या token valid है?
□ क्या group ID correct है?
□ क्या user IDs valid हैं?
□ क्या duplicate users नहीं हैं?
□ क्या empty strings नहीं हैं?

After Response:
□ क्या status 200 है?
□ क्या "added" count > 0 है?
□ क्या "member_count" बढ़ी है?
□ क्या नए members list में हैं?
```

---

## Useful Commands

```bash
# Get all groups
curl -H "Authorization: Bearer TOKEN" \
  http://localhost:8000/api/v1/groups | jq

# Get specific group details
curl -H "Authorization: Bearer TOKEN" \
  http://localhost:8000/api/v1/groups/GROUP_ID | jq

# Add single member
curl -X POST -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_ids":["user_123"]}' \
  http://localhost:8000/api/v1/groups/GROUP_ID/members

# Add multiple members
curl -X POST -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_ids":["user_1","user_2","user_3"]}' \
  http://localhost:8000/api/v1/groups/GROUP_ID/members

# Search for contacts to add
curl -H "Authorization: Bearer TOKEN" \
  'http://localhost:8000/api/v1/groups/GROUP_ID/members/suggestions?q=john'
```

---

## API Response Codes

```
200 - ✅ Success (Members added)
400 - ❌ Bad Request (Invalid input)
401 - ❌ Unauthorized (Invalid token)
403 - ❌ Forbidden (Not admin)
404 - ❌ Not Found (Group doesn't exist)
500 - ❌ Server Error
```

---

## Video Tutorial Steps

```
1. Backend server start करें
   python backend/main.py

2. Frontend खोलें
   http://localhost:3000

3. Login करें
   Email: user@example.com
   Password: password123

4. Group खोलें

5. "Add Members" button click करें

6. User IDs enter करें
   (comma से separate करें)

7. "Add" button click करें

8. ✅ Members successfully added!
```

---

## Support

### अगर कोई समस्या हो तो:
1. GROUP_MEMBERS.md की detailed guide पढ़ें
2. Error message को ध्यान से पढ़ें
3. Checklist follow करें
4. Logs check करें (backend console)
5. Backend को restart करें अगर जरूरत हो

---

**Happy Grouping! 🎉👥**

---

For detailed documentation, see: [GROUP_MEMBERS.md](GROUP_MEMBERS.md)
