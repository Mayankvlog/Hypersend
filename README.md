# Hypersend

A full-stack application with a Python backend and Flutter frontend, featuring user authentication, MongoDB integration, Redis caching, and Nginx reverse proxy support.

## Project Structure

```
hypersend/
├── backend/              # Python Flask backend
│   ├── auth/            # Authentication routes and logic
│   ├── routes/          # API routes
│   ├── utils/           # Utility functions
│   ├── data/            # Data processing
│   ├── main.py          # Application entry point
│   ├── config.py        # Configuration settings
│   ├── database.py      # Database initialization
│   ├── models.py        # Database models
│   ├── security.py      # Security utilities
│   └── requirements.txt  # Python dependencies
├── frontend/            # Flutter frontend application
│   ├── lib/            # Flutter source code
│   ├── android/        # Android platform-specific code
│   ├── ios/            # iOS platform-specific code
│   ├── web/            # Web platform code
│   └── pubspec.yaml    # Flutter dependencies
├── tests/              # Comprehensive test suite
├── scripts/            # Utility scripts
├── data/               # Data storage
│   ├── db/            # Database files
│   ├── uploads/       # User uploads
│   └── tmp/           # Temporary files
├── docker-compose.yml  # Docker orchestration
├── nginx.conf          # Nginx configuration
└── pyproject.toml      # Python project configuration
```

## Technology Stack

### Backend
- **Framework**: Python Flask
- **Database**: MongoDB
- **Cache**: Redis
- **Authentication**: JWT-based
- **Containerization**: Docker

### Frontend
- **Framework**: Flutter
- **Supported Platforms**: Android, iOS, Web, Windows, Linux, macOS

### Infrastructure
- **Reverse Proxy**: Nginx
- **Orchestration**: Docker Compose

## Prerequisites

- Docker & Docker Compose (recommended for easy setup)
- Python 3.8+ (for local backend development)
- Flutter SDK (for frontend development)
- MongoDB (included in Docker Compose)
- Redis (included in Docker Compose)

## Installation

### Using Docker Compose (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd hypersend

# Start all services
docker-compose up -d

# Initialize the database
docker-compose exec backend python scripts/seed_mongodb.py
```

The application will be available at `http://localhost` (via Nginx reverse proxy).

### Local Development

#### Backend Setup

```bash
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
# Create a .env file with necessary configuration

# Run the backend
python main.py
```

#### Frontend Setup

```bash
# Navigate to frontend directory
cd frontend

# Get Flutter dependencies
flutter pub get

# Run the application
flutter run
```

## Configuration

### Backend Configuration
- Edit `backend/config.py` for application settings
- Configure database connection in environment variables
- Set up Redis cache settings

### Frontend Configuration
- Update `frontend/pubspec.yaml` for dependencies
- Configure API endpoints in the frontend code

## Running Tests

```bash
# Run all tests
cd tests
pytest

# Run specific test file
pytest test_auth_endpoints.py

# Run with coverage
pytest --cov=backend
```

## API Endpoints

The backend exposes various REST API endpoints for:
- User authentication and registration
- Profile management
- Data operations
- File uploads

Refer to the backend routes documentation for detailed endpoint information.

## Security Features

- JWT token-based authentication
- Password hashing with industry-standard algorithms
- Rate limiting
- CORS configuration
- Input validation
- Security error handling

## Development Workflow

1. Create a feature branch
2. Make your changes
3. Run tests to ensure everything works
4. Submit a pull request

## Troubleshooting

### Database Connection Issues
- Ensure MongoDB is running
- Check connection string in configuration
- Verify network connectivity

### Redis Cache Issues
- Ensure Redis service is running
- Check Redis connection configuration
- Verify port availability

### Backend Startup Issues
- Install all required dependencies: `pip install -r requirements.txt`
- Check Python version compatibility
- Review configuration file settings

## Contributing

Contributions are welcome! Please ensure:
- All tests pass
- Code follows project conventions
- Documentation is updated
- Commits have clear messages

## License

[Add license information here]

## Support

For issues and questions, please open an issue in the repository.
