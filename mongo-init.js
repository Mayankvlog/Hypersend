db = db.getSiblingDB('admin');

// Check if user already exists
var userExists = db.getUser('hypersend');

if (!userExists) {
    print('Creating hypersend user...');
    db.createUser({
        user: 'hypersend',
        pwd: process.env.MONGO_PASSWORD || 'CHANGE_THIS_PASSWORD',
        roles: [
            { role: 'readWrite', db: 'hypersend' },
            { role: 'dbAdmin', db: 'hypersend' }
        ]
    });
    print('User hypersend created successfully');
} else {
    print('User hypersend already exists');
}

// Switch to hypersend database and create collections
db = db.getSiblingDB('hypersend');

print('MongoDB initialization complete');
