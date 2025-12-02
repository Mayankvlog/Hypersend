// Initialize MongoDB with authentication
// This script runs when MongoDB container starts (via docker-entrypoint-initdb.d)

// Switch to admin database
db = db.getSiblingDB('admin');

// Get environment variables (passed via docker-compose)
const rootUser = process.env.MONGO_INITDB_ROOT_USERNAME || 'admin';
const rootPassword = process.env.MONGO_INITDB_ROOT_PASSWORD || 'changeme';
const appUser = 'hypersend';
const appPassword = 'Mayank@#03';

try {
    // Create root admin user if not exists
    db.createUser({
        user: rootUser,
        pwd: rootPassword,
        roles: ['root']
    });
    print(`[OK] Created root admin user: ${rootUser}`);
} catch (e) {
    if (e.code === 51003) {
        print(`[OK] Root admin user already exists: ${rootUser}`);
    } else {
        print(`[ERROR] Failed to create root user: ${e.message}`);
    }
}

try {
    // Create application user for 'hypersend' database
    db.createUser({
        user: appUser,
        pwd: appPassword,
        roles: [
            {role: 'readWrite', db: 'hypersend'},
            {role: 'dbOwner', db: 'hypersend'}
        ]
    });
    print(`[OK] Created application user: ${appUser}`);
} catch (e) {
    if (e.code === 51003) {
        print(`[OK] Application user already exists: ${appUser}`);
    } else {
        print(`[ERROR] Failed to create application user: ${e.message}`);
    }
}

// Create hypersend database and collections
db = db.getSiblingDB('hypersend');

try {
    // Create collections with indexes
    const collections = ['users', 'chats', 'messages', 'files', 'uploads', 'refresh_tokens', 'reset_tokens'];
    
    collections.forEach(collName => {
        try {
            db.createCollection(collName);
            print(`[OK] Created collection: ${collName}`);
        } catch (e) {
            if (e.code === 48) {
                print(`[OK] Collection already exists: ${collName}`);
            } else {
                print(`[WARN] ${collName}: ${e.message}`);
            }
        }
    });
    
    // Create indexes for better query performance
    db.users.createIndex({email: 1}, {unique: true});
    print('[OK] Created index: users.email');
    
    db.chats.createIndex({members: 1});
    print('[OK] Created index: chats.members');
    
    db.messages.createIndex({chat_id: 1, created_at: -1});
    print('[OK] Created index: messages.chat_id, created_at');
    
    db.files.createIndex({chat_id: 1, owner_id: 1});
    print('[OK] Created index: files.chat_id, owner_id');
    
    db.refresh_tokens.createIndex({expires_at: 1}, {expireAfterSeconds: 0});
    print('[OK] Created index: refresh_tokens.expires_at (TTL)');
    
    db.reset_tokens.createIndex({expires_at: 1}, {expireAfterSeconds: 0});
    print('[OK] Created index: reset_tokens.expires_at (TTL)');
    
    print('[OK] MongoDB initialization complete');
} catch (e) {
    print(`[ERROR] Failed to initialize collections: ${e.message}`);
}
