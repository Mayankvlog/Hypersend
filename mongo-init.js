// MongoDB Initialization Script
// This script runs when MongoDB starts for the first time

print('[mongo-init.js] Starting MongoDB initialization...');

// Get environment variables with defaults
var mongoUser = 'hypersend';
var mongoPassword = 'hypersend_secure_password';
var mongoDatabase = 'hypersend';

print('[mongo-init.js] MongoDB User: ' + mongoUser);
print('[mongo-init.js] MongoDB Database: ' + mongoDatabase);

// Switch to admin database
db = db.getSiblingDB('admin');

// Check if user exists
var userExists = false;
try {
  var users = db.getUsers();
  for (var i = 0; i < users.users.length; i++) {
    if (users.users[i].user === mongoUser) {
      userExists = true;
      break;
    }
  }
} catch (e) {
  print('[mongo-init.js] Could not check existing users: ' + e);
}

if (userExists) {
  print('[mongo-init.js] User "' + mongoUser + '" already exists');
} else {
  // Create the application user
  db.createUser({
    user: mongoUser,
    pwd: mongoPassword,
    roles: [
      { role: 'readWrite', db: mongoDatabase },
      { role: 'dbOwner', db: mongoDatabase }
    ]
  });
  print('[mongo-init.js] Created user "' + mongoUser + '" with access to "' + mongoDatabase + '"');
}

// Switch to application database
db = db.getSiblingDB(mongoDatabase);

// Create collections
var collections = ['users', 'chats', 'messages', 'files', 'uploads', 'refresh_tokens', 'reset_tokens', 'group_activity', 'channels'];

for (var i = 0; i < collections.length; i++) {
  var collName = collections[i];
  var existingColls = db.getCollectionNames();
  var exists = false;
  for (var j = 0; j < existingColls.length; j++) {
    if (existingColls[j] === collName) {
      exists = true;
      break;
    }
  }

  if (!exists) {
    db.createCollection(collName);
    print('[mongo-init.js] Created collection: ' + collName);
  }
}

// Create indexes
db.users.createIndex({ email: 1 }, { unique: true });
db.chats.createIndex({ members: 1 });
db.chats.createIndex({ type: 1, created_at: -1 });
db.messages.createIndex({ chat_id: 1, created_at: -1 });
db.messages.createIndex({ chat_id: 1, is_pinned: 1, pinned_at: -1 });
db.messages.createIndex({ chat_id: 1, is_deleted: 1 });
db.files.createIndex({ chat_id: 1, owner_id: 1 });
db.refresh_tokens.createIndex({ expires_at: 1 }, { expireAfterSeconds: 0 });
db.reset_tokens.createIndex({ expires_at: 1 }, { expireAfterSeconds: 0 });
db.group_activity.createIndex({ group_id: 1, created_at: -1 });
db.channels.createIndex({ name: 1 });

print('[mongo-init.js] Created indexes');
print('[mongo-init.js] MongoDB initialization complete!');
