# Zaply - Modern File Sharing & Communication Platform

## 🚀 Project Overview

Zaply is a comprehensive file sharing and communication platform built with Flutter frontend and Python FastAPI backend. It enables users to securely share files, create groups, send messages, and manage their digital communications with modern security features.

### ✨ Key Features

- **📁 Secure File Sharing** - Upload and share files of any size with chunked uploads
- **💬 Real-time Messaging** - Instant messaging with file attachments
- **👥 Group Management** - Create and manage groups with multiple members
- **👤 Profile Management** - Customizable profiles with avatar support
- **📱 Cross-Platform** - Works on Web, Mobile, and Desktop
- **🔒 End-to-End Security** - JWT authentication and secure data handling
- **📊 Usage Analytics** - Track storage usage and activity statistics

---

## 🏗️ Architecture

### Frontend (Flutter)
```
frontend/
├── lib/
│   ├── core/                  # Core utilities and themes
│   │   ├── theme/
│   │   └── constants/
│   ├── data/                  # Data layer
│   │   ├── models/           # Data models
│   │   ├── services/         # API services
│   │   └── repositories/     # Repository pattern
│   ├── presentation/          # UI layer
│   │   ├── screens/          # Main screens
│   │   ├── widgets/          # Reusable widgets
│   │   └── providers/        # State management
│   └── infrastructure/        # External dependencies
└── assets/                  # Static assets
```

### Backend (Python FastAPI)
```
backend/
├── routes/                   # API endpoints
│   ├── auth.py              # Authentication endpoints
│   ├── users.py             # User management
│   ├── groups.py            # Group management
│   ├── files.py             # File handling
│   └── messages.py         # Message handling
├── models/                   # Pydantic models
├── auth/                     # Authentication logic
├── db_proxy/               # Database abstraction
├── middleware/              # Custom middleware
└── config/                  # Configuration management
```

---

## 🛠️ Technology Stack

### Frontend
- **Framework**: Flutter 3.x
- **State Management**: BLoC pattern
- **Navigation**: GoRouter
- **HTTP Client**: Dio
- **Local Storage**: Secure storage for credentials
- **File Handling**: File picker and chunked uploads

### Backend
- **Framework**: FastAPI
- **Database**: MongoDB with PyMongo
- **Authentication**: JWT with refresh tokens
- **File Storage**: Local file system with UUID naming
- **Validation**: Pydantic models with comprehensive validation
- **Async Support**: Full async/await implementation

---

## 🚀 Getting Started

### Prerequisites
- Flutter SDK 3.0+
- Python 3.8+
- MongoDB 5.0+

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/your-org/zaply.git
cd zaply
```

2. **Backend Setup**
```bash
cd backend
pip install -r requirements.txt
```

3. **Environment Configuration**
```bash
# Create .env file in backend/
cp .env.example .env
# Configure MongoDB connection and JWT secrets
```

4. **Database Setup**
```bash
# Ensure MongoDB is running
mongod --dbpath /path/to/your/db
```

5. **Frontend Setup**
```bash
cd frontend
flutter pub get
flutter run
```

6. **Backend Server**
```bash
cd backend
uvicorn main:app --reload --port=8000
```

---

## 📚 API Documentation

### Authentication Endpoints

#### Register User
```http
POST /api/v1/auth/register
Content-Type: application/json

{
    "name": "John Doe",
    "email": "john@example.com", 
    "password": "SecurePass123"
}
```

#### Login
```http
POST /api/v1/auth/login
Content-Type: application/json

{
    "email": "john@example.com",
    "password": "SecurePass123"
}
```

### User Management

#### Get Current User
```http
GET /api/v1/users/me
Authorization: Bearer <token>
```

#### Update Profile
```http
PUT /api/v1/users/profile
Authorization: Bearer <token>
Content-Type: application/json

{
    "name": "John Updated",
    "bio": "Updated bio"
}
```

#### Upload Avatar
```http
POST /api/v1/users/avatar
Authorization: Bearer <token>
Content-Type: multipart/form-data

file: <image_file>
```

### Group Management

#### Create Group
```http
POST /api/v1/users/create-group
Authorization: Bearer <token>
Content-Type: application/json

{
    "name": "My Group",
    "description": "Group description",
    "member_ids": ["user_id_1", "user_id_2"]
}
```

#### Get User Contacts
```http
GET /api/v1/users/contacts?limit=50
Authorization: Bearer <token>
```

### File Management

#### Initialize File Upload
```http
POST /api/v1/files/init
Authorization: Bearer <token>
Content-Type: application/json

{
    "filename": "document.pdf",
    "size": 1048576,
    "mime_type": "application/pdf",
    "chat_id": "chat_id_123"
}
```

#### Upload Chunk
```http
POST /api/v1/files/chunk/{upload_id}/{chunk_index}
Authorization: Bearer <token>
Content-Type: application/octet-stream

<chunk_data>
```

#### Complete Upload
```http
POST /api/v1/files/complete/{upload_id}
Authorization: Bearer <token>
Content-Type: application/json

{
    "checksum": "file_checksum_hash"
}
```

---

## 🔧 Development Guide

### Code Organization Principles

1. **Separation of Concerns**: Clear separation between UI, business logic, and data layers
2. **Repository Pattern**: Abstract database operations for testability
3. **Dependency Injection**: Use service providers for loose coupling
4. **Error Handling**: Comprehensive error handling with user-friendly messages
5. **Security First**: All operations validate authentication and authorization

### Adding New Features

1. **Backend Changes**
   - Add Pydantic models in `models/`
   - Create endpoints in appropriate `routes/` file
   - Add validation and error handling
   - Write unit tests in `tests/`

2. **Frontend Changes**
   - Create data models in `lib/data/models/`
   - Add API service methods in `lib/data/services/`
   - Build UI components in `lib/presentation/`
   - Add navigation routes

3. **Testing**
   - Backend: Use pytest with mock database
   - Frontend: Use widget tests and integration tests
   - Run comprehensive test suite before deployment

### Development Commands

```bash
# Backend Development
cd backend
python -m pytest tests/ -v  # Run tests
uvicorn main:app --reload   # Development server

# Frontend Development  
cd frontend
flutter analyze             # Code analysis
flutter test                # Run tests
flutter run                 # Development server
```

---

## 🧪 Testing

### Backend Tests
```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test files
python -m pytest tests/test_auth_fixes_comprehensive.py -v

# Run with coverage
python -m pytest --cov=. tests/
```

### Frontend Tests
```bash
# Widget tests
flutter test test/widget/

# Integration tests
flutter test integration_test/

# Code analysis
flutter analyze
```

### Test Categories

1. **Authentication Tests** - Login, registration, token refresh
2. **File Upload Tests** - Chunked uploads, validation, completion
3. **Group Management Tests** - Creation, member management
4. **User Management Tests** - Profile updates, avatar uploads
5. **Security Tests** - Authorization, input validation, error handling
6. **Integration Tests** - End-to-end workflows

---

## 🔒 Security Features

### Authentication & Authorization
- **JWT Tokens**: Access and refresh token pattern
- **Password Security**: Salted hashing with bcrypt
- **Session Management**: Secure token storage and rotation
- **Rate Limiting**: Prevent brute force attacks

### Data Protection
- **Input Validation**: Comprehensive Pydantic validation
- **SQL Injection Prevention**: Parameterized queries
- **XSS Protection**: Input sanitization and output encoding
- **File Security**: Type validation and size limits

### API Security
- **CORS Configuration**: Secure cross-origin requests
- **HTTPS Enforcement**: Secure communication only
- **Error Handling**: Non-revealing error messages
- **Logging**: Security event tracking

---

## 📊 Monitoring & Analytics

### Application Metrics
- **User Activity**: Login patterns, feature usage
- **File Statistics**: Upload counts, storage usage
- **Performance Metrics**: Response times, error rates
- **System Health**: Database connections, memory usage

### Logging Strategy
```python
# Structured logging example
logger.info(
    "User action completed",
    extra={
        "user_id": current_user,
        "action": "file_upload",
        "file_size": file_size,
        "timestamp": datetime.utcnow()
    }
)
```

---

## 🚀 Deployment

### Production Setup

1. **Environment Configuration**
```bash
# Production environment variables
export NODE_ENV=production
export MONGODB_URI=mongodb://prod-server:27017/zaply
export JWT_SECRET_KEY=your-secure-secret-key
export DATA_ROOT=/var/lib/zaply
```

2. **Database Setup**
```bash
# Production MongoDB with replica set
mongod --replSet zaplyRS --dbpath /data/db
```

3. **Application Server**
```bash
# Production server with Gunicorn
pip install gunicorn
gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app
```

4. **Frontend Build**
```bash
# Production Flutter build
cd frontend
flutter build web --release
# or for mobile
flutter build apk --release
```

### Docker Deployment

```dockerfile
# Backend Dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0"]
```

```dockerfile
# Frontend Dockerfile  
FROM stedolan/docker:alpine
WORKDIR /app
COPY . .
RUN flutter build web
FROM nginx:alpine
COPY --from=0 /app/build/web /usr/share/nginx/html
```

---

## 🤝 Contributing Guidelines

### Code Style
- **Python**: Follow PEP 8, use black formatting
- **Dart**: Follow Flutter style guide, use dartfmt
- **Comments**: Document complex logic and public APIs
- **Testing**: Maintain >80% test coverage

### Pull Request Process
1. **Fork** the repository
2. **Create** feature branch from main
3. **Implement** changes with tests
4. **Run** full test suite locally
5. **Submit** pull request with description
6. **Code Review**: Address all feedback
7. **Merge**: After approval

### Issue Reporting
- **Bug Reports**: Include steps to reproduce and environment details
- **Feature Requests**: Describe use case and expected behavior
- **Security Issues**: Report privately to maintainers

---

## 📝 Changelog

### v1.0.0 (Latest)
- ✅ Group creation member selection fix
- ✅ Profile photo rendering glitch fix  
- ✅ Enhanced file upload validation
- ✅ Improved error handling and logging
- ✅ Security enhancements and input validation

### Key Recent Fixes

#### Group Creation Bug Fix
- **Issue**: Members not appearing in "Add Members" list
- **Root Cause**: `searchUsers('')` returned empty list due to 2-character minimum
- **Solution**: Modified search endpoint to handle empty queries for group creation
- **Result**: Users can now see and select contacts for group creation

#### Profile Photo Rendering Fix  
- **Issue**: Filenames like "YenSurferUserSetup" displayed as overlay text
- **Root Cause**: Poor filename pattern detection in avatar loading logic
- **Solution**: Enhanced validation to detect and block filename patterns
- **Result**: Proper fallback to initials instead of filename overlays

---

## 🔧 Configuration Options

### Backend Configuration (`config/settings.py`)
```python
class Settings:
    # Database
    MONGODB_URI: str = "mongodb://localhost:27017/zaply"
    
    # Authentication
    JWT_SECRET_KEY: str = "your-secret-key"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # File Storage
    DATA_ROOT: str = "./data"
    MAX_FILE_SIZE: int = 42949672960  # 40GB
    CHUNK_SIZE: int = 1048576  # 1MB
    
    # Security
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]
    DEBUG: bool = False
```

### Frontend Configuration (`lib/core/constants/api_constants.dart`)
```dart
class ApiConstants {
  static const String baseUrl = 'http://localhost:8000';
  static const String serverBaseUrl = 'http://localhost:8000';
  static const String authEndpoint = '/api/v1/auth';
  static const String usersEndpoint = '/api/v1/users';
  static const String filesEndpoint = '/api/v1/files';
  static const String messagesEndpoint = '/api/v1/messages';
  
  // Timeouts
  static const Duration connectTimeout = Duration(minutes: 10);
  static const Duration receiveTimeout = Duration(hours: 4);
  static const Duration sendTimeout = Duration(minutes: 10);
}
```

---

## 📞 Support & Community

### Getting Help
- **Documentation**: Check this README and code comments
- **Issues**: Search existing GitHub issues first
- **Discussions**: Use GitHub Discussions for questions
- **Email**: support@zaply.com for critical issues

### Community Resources
- **Wiki**: Advanced guides and tutorials
- **Examples**: Sample integrations and use cases
- **Contributors**: Recognition for valuable contributions
- **Roadmap**: Planned features and releases

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### License Summary
- ✅ Commercial use allowed
- ✅ Modification allowed  
- ✅ Distribution allowed
- ✅ Private use allowed
- ❗ Liability and warranty disclaimed

---

## 🙏 Acknowledgments

### Key Contributors
- **Development Team**: Core platform development and maintenance
- **Security Team**: Security audits and vulnerability fixes
- **Community**: Bug reports, feature suggestions, and contributions

### Technologies & Libraries
- **Flutter**: Cross-platform UI framework
- **FastAPI**: Modern Python web framework  
- **MongoDB**: NoSQL database
- **JWT**: Authentication standard
- **Pydantic**: Data validation
- **Dio**: HTTP client for Flutter

---

## 🚀 Future Roadmap

### Upcoming Features
- **📹 Video Calling**: Real-time video communication
- **🔐 End-to-End Encryption**: Message and file encryption
- **🌍 Multi-language Support**: Internationalization
- **📱 Mobile Apps**: Native iOS and Android apps
- **☁️ Cloud Storage**: AWS S3, Google Cloud integration
- **🤖 AI Features**: Smart file organization and search

### Platform Improvements
- **Performance**: Enhanced caching and optimization
- **Scalability**: Horizontal scaling support
- **Monitoring**: Advanced metrics and alerting
- **Security**: Enhanced authentication methods (2FA, SSO)

---

## 🔧 Project Structure Details

### Key Components

#### Authentication System
- **JWT-based authentication** with access and refresh tokens
- **Password hashing** using bcrypt with salt
- **Session management** with automatic token refresh
- **Multi-device support** with device tracking

#### File Management
- **Chunked uploads** for large file handling
- **Progress tracking** with real-time updates
- **Resume capability** for interrupted uploads
- **File validation** with type and size checks

#### Communication System
- **Real-time messaging** with WebSocket support
- **Group conversations** with member management
- **File sharing** within conversations
- **Message status** tracking (sent, delivered, read)

#### Security Architecture
- **Input validation** at all API endpoints
- **Rate limiting** to prevent abuse
- **CORS configuration** for secure cross-origin requests
- **Error handling** that doesn't leak sensitive information

---

## 🛠️ Advanced Features

### Smart File Handling
- **Automatic deduplication** using file hashes
- **Thumbnail generation** for image previews
- **Virus scanning** integration capabilities
- **Metadata extraction** for searchability

### User Experience
- **Offline mode** with local caching
- **Push notifications** for new messages
- **Dark/Light theme** support
- **Responsive design** for all screen sizes

### Developer Tools
- **Comprehensive API** documentation
- **SDK/libraries** for easy integration
- **Webhook support** for real-time events
- **Analytics dashboard** for usage insights

---

---

*Built with ❤️ by the Zaply Team*

---

**Quick Links**
- 🌐 [Local Demo](http://localhost:8000)
- 📚 [Documentation](http://localhost:8000/docs)  
- 🐛 [Report Issues](https://github.com/zaply/zaply/issues)
- 💬 [Discussions](https://github.com/zaply/zaply/discussions)
- 📧 [Contact](mailto:support@zaply.in.net)