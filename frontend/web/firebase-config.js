// Firebase web configuration
// This file contains the Firebase configuration for web deployment
// Replace with your actual Firebase project configuration

const firebaseConfig = {
  apiKey: "AIzaSyDummyApiKeyForTesting",
  authDomain: "hypersend.firebaseapp.com",
  projectId: "hypersend",
  storageBucket: "hypersend.appspot.com",
  messagingSenderId: "123456789",
  appId: "1:123456789:web:abcdef123456"
};

// Initialize Firebase with comprehensive error handling
window.firebaseInitialized = false;
window.firebaseError = null;
window.firebaseApp = null;

// Wait for Firebase SDK to load before initializing
function initializeFirebase() {
  try {
    if (typeof firebase === 'undefined') {
      console.debug('Firebase SDK not loaded yet - will retry');
      window.firebaseError = 'Firebase SDK not available';
      return false;
    }

    // Check if Firebase app is already initialized
    if (firebase.apps && firebase.apps.length > 0) {
      window.firebaseApp = firebase.apps[0];
      window.firebaseInitialized = true;
      console.log('Firebase already initialized');
      // Resolve the promise immediately
      if (window.firebaseResolve) {
        window.firebaseResolve(true);
      }
      return true;
    }

    // Initialize Firebase
    window.firebaseApp = firebase.initializeApp(firebaseConfig);
    window.firebaseInitialized = true;
    console.log('Firebase initialized successfully');
    
    // Resolve the promise now that Firebase is ready
    if (window.firebaseResolve) {
      window.firebaseResolve(true);
    }
    return true;
  } catch (error) {
    console.debug('Firebase initialization error (non-critical):', error.message);
    window.firebaseError = error.message;
    window.firebaseInitialized = false;
    // Continue without Firebase - app will work without analytics
    return false;
  }
}

// Try to initialize immediately
initializeFirebase();

// Also try on DOMContentLoaded if not initialized yet
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', function() {
    if (!window.firebaseInitialized) {
      // Wait for Firebase SDK to load
      setTimeout(function() {
        initializeFirebase();
      }, 500);
    }
  });
} else {
  // If DOM is already loaded, try again after a small delay
  setTimeout(function() {
    if (!window.firebaseInitialized) {
      initializeFirebase();
    }
  }, 500);
}

// Set a timeout to resolve the promise even if Firebase fails to load
// This ensures Flutter app loads even if Firebase is unavailable
setTimeout(function() {
  if (window.firebaseResolve && !window.firebaseInitialized) {
    console.debug('Firebase initialization timeout - proceeding without Firebase');
    window.firebaseResolve(false);
  }
}, 3000);

// Provide a fallback for Firebase analytics
window.logEvent = function(eventName, eventData) {
  if (window.firebaseInitialized && window.firebaseApp) {
    try {
      // Use the initialized app instance
      if (window.firebaseApp.analytics) {
        window.firebaseApp.analytics().logEvent(eventName, eventData);
      }
    } catch (e) {
      console.debug('Analytics event not logged:', eventName, e.message);
    }
  } else {
    console.debug('Firebase not available, skipping analytics:', eventName);
  }
};

// Provide a safe way for Dart to check Firebase status
window.getFirebaseStatus = function() {
  return {
    initialized: window.firebaseInitialized,
    error: window.firebaseError,
    hasApp: window.firebaseApp !== null
  };
};
