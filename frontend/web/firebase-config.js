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

// Initialize Firebase with error handling
window.firebaseInitialized = false;
window.firebaseError = null;

try {
  if (typeof firebase !== 'undefined') {
    // Check if Firebase app is already initialized
    if (!firebase.apps || firebase.apps.length === 0) {
      firebase.initializeApp(firebaseConfig);
      window.firebaseInitialized = true;
      console.log('Firebase initialized successfully');
    } else {
      window.firebaseInitialized = true;
      console.log('Firebase already initialized');
    }
  } else {
    console.warn('Firebase SDK not loaded - analytics disabled');
    window.firebaseError = 'Firebase SDK not available';
  }
} catch (error) {
  console.warn('Firebase initialization error (non-critical):', error.message);
  window.firebaseError = error.message;
  // Continue without Firebase - app will work without analytics
}

// Provide a fallback for Firebase analytics
window.logEvent = function(eventName, eventData) {
  if (window.firebaseInitialized && typeof firebase !== 'undefined') {
    try {
      firebase.analytics().logEvent(eventName, eventData);
    } catch (e) {
      console.debug('Analytics event not logged:', eventName);
    }
  } else {
    console.debug('Firebase not available, skipping analytics:', eventName);
  }
};
