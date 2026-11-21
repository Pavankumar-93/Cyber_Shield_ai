import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
  apiKey: "AIzaSyDpES9q8yVdsJksYLQgD4mwS1xGrAm71xI",
  authDomain: "cybershield-ai-4428c.firebaseapp.com",
  projectId: "cybershield-ai-4428c",
  storageBucket: "cybershield-ai-4428c.firebasestorage.app",
  messagingSenderId: "190812474085",
  appId: "1:190812474085:web:9ab195817606c0c627a20c",
  measurementId: "G-989W1D9XNK"
};

const app = initializeApp(firebaseConfig);

export const auth = getAuth(app);
export const db = getFirestore(app);

export default app;