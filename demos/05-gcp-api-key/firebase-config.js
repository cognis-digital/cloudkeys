// Frontend bundle that shipped a GCP/Firebase web config with an UNRESTRICTED
// API key. Web API keys are meant to be public-ish, BUT an unrestricted key
// can call billable Google APIs and is a real, frequently-abused leak.
// NOTE: every value below is FAKE, shaped like the real format. Not live.

const firebaseConfig = {
  apiKey: "AIzaSyEXAMPLEexampleNotARealGcpKey00000",
  authDomain: "demo-analytics-472310.firebaseapp.com",
  projectId: "demo-analytics-472310",
  storageBucket: "demo-analytics-472310.appspot.com",
  messagingSenderId: "109876543210",
  appId: "1:109876543210:web:abc123def456abc123def4",
};

export default firebaseConfig;
