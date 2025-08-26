const admin = require('firebase-admin');
const serviceAccount = require('./firebase-service-account.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

async function testFirebase() {
  try {
    // Test écriture
    await db.collection('test').doc('test').set({
      message: 'Hello Firestore!',
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    // Test lecture
    const doc = await db.collection('test').doc('test').get();
    console.log('✅ Firebase fonctionne !');
    console.log('Data:', doc.data());

    // Nettoyer
    await db.collection('test').doc('test').delete();
  } catch (error) {
    console.log('❌ Erreur Firebase:', error.message);
  }
}

testFirebase();
