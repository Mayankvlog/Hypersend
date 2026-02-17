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
      console.warn('Firebase SDK not loaded yet - will retry');
      window.firebaseError = 'Firebase SDK not available';
      return false;
    }

    // Check if Firebase app is already initialized
    if (firebase.apps && firebase.apps.length > 0) {
      window.firebaseApp = firebase.apps[0];
      window.firebaseInitialized = true;
      console.log('Firebase already initialized');
      return true;
    }

    // Initialize Firebase
    window.firebaseApp = firebase.initializeApp(firebaseConfig);
    window.firebaseInitialized = true;
    console.log('Firebase initialized successfully');
    return true;
  } catch (error) {
    console.warn('Firebase initialization error (non-critical):', error.message);
    window.firebaseError = error.message;
    window.firebaseInitialized = false;
    // Continue without Firebase - app will work without analytics
    return false;
  }
}

// Try to initialize immediately
initializeFirebase();

// Retry initialization if Firebase SDK wasn't ready
if (!window.firebaseInitialized && typeof firebase === 'undefined') {
  // Wait for Firebase SDK to load
  setTimeout(function() {
    if (!window.firebaseInitialized) {
      console.log('Retrying Firebase initialization...');
      initializeFirebase();
    }
  }, 1000);
}

// Provide a fallback for Firebase analytics
window.logEvent = function(eventName, eventData) {
  if (window.firebaseInitialized && window.firebaseApp) {
    try {
      // Use the initialized app instance
      window.firebaseApp.analytics().logEvent(eventName, eventData);
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
