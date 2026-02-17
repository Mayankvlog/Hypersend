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

// Initialize Firebase
if (typeof firebase !== 'undefined') {
  firebase.initializeApp(firebaseConfig);
  console.log('Firebase initialized successfully');
} else {
  console.warn('Firebase SDK not loaded');
}
