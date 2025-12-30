// Clean error handling section for profile_photo_screen.dart
} else if (errorString.contains('avatar too long') || errorString.contains('avatar must be 10 characters or less')) {
  errorMessage = 'Avatar initials are too long. Please use 1-10 characters only.';
} else if (errorString.contains('name cannot be empty') || errorString.contains('name must be at least 2 characters')) {
  // This shouldn't happen on photo-only screen - log for debugging
  debugPrint('[PHOTO_SCREEN] Unexpected name validation error on photo upload: $errorString');
  errorMessage = 'Photo upload failed. This appears to be a server issue. Please try again.';
} else if (errorString.contains('validation failed') && errorString.contains('avatar')) {
  errorMessage = 'Photo validation failed. Please try a different image or check the format.';
} else if (errorString.contains('validation failed') || errorString.contains('validation error')) {
  // For photo screen, be more specific about validation failures
  if (errorString.contains('file') || errorString.contains('upload') || errorString.contains('image')) {
    errorMessage = 'Photo upload failed. Please check image format (JPG, PNG) and file size.';
  } else {
    errorMessage = 'Photo upload failed due to server validation. Please try again.';
  }
} else if (errorString.contains('invalid data provided')) {
  // Catch specific backend validation error
  errorMessage = 'Photo upload failed. Please check image format and try again.';
} else if (errorString.contains('validation') && !errorString.contains('avatar')) {
  // For photo screen, hide validation errors that don't make sense
  errorMessage = 'Photo upload failed. Please try a different image or check your connection.';
} else if (errorString.contains('invalid') && !errorString.contains('avatar')) {
  errorMessage = 'Photo upload failed. Please check image and try again.';
} else if (errorString.isNotEmpty) {
  errorMessage = e.toString();
}