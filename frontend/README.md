# Zaply - Flutter Chat Application

A modern, dark-themed messaging application built with Flutter.

## Features

- 🎨 Beautiful dark theme with cyan accents
- 💬 Real-time messaging interface
- 🔐 Permissions management
- ⚙️ Chat settings and customization
- 📱 Material Design 3
- 🌐 API integration ready

## Tech Stack

- **Framework**: Flutter 3.x
- **State Management**: flutter_bloc
- **Routing**: go_router
- **API Client**: dio
- **Utilities**: intl, equatable

## API Configuration

The app is configured to connect to the backend server at:

```dart
Base URL: http://139.59.82.105
```

This is configured in `lib/core/constants/api_constants.dart`.

## Project Structure

```
lib/
├── core/
│   ├── constants/      # App constants and API config
│   ├── router/         # Navigation configuration
│   ├── theme/          # App theme and colors
│   └── utils/          # Utility functions
├── data/
│   ├── models/         # Data models
│   └── mock/           # Mock data for development
└── presentation/
    ├── screens/        # App screens
    └── widgets/        # Reusable widgets
```

## Screens

1. **Splash Screen** - Loading screen with app logo
2. **Permissions Screen** - Request app permissions
3. **Chat List Screen** - List of conversations
4. **Chat Detail Screen** - Individual chat view
5. **Chat Settings Screen** - User and chat settings

## Getting Started

### Prerequisites

- Flutter SDK (3.9.2 or higher)
- Dart SDK (3.9.2 or higher)

### Installation

1. Install dependencies:
```bash
flutter pub get
```

2. Run the app:
```bash
flutter run
```

### Development

Run analysis:
```bash
flutter analyze
```

Run tests:
```bash
flutter test
```

## Color Palette

- **Primary Cyan**: #4FC3F7
- **Background Dark**: #1A2332
- **Card Dark**: #2C3E50
- **Text Primary**: #FFFFFF
- **Text Secondary**: #8B9DAF

## API Endpoints

The app expects the following endpoints from the backend:

- `/api/auth` - Authentication
- `/api/chats` - Chat operations
- `/api/messages` - Message operations
- `/api/users` - User operations
- `/api/files` - File operations

## License

This project is part of the Hypersend application.