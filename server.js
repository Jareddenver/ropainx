
// Initialisation de l'application Express
const axiosRetry = require('axios-retry');
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const { TwitterApi } = require('twitter-api-v2');
const fs = require('fs').promises;
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const admin = require('firebase-admin');

const serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT
  ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)
  : require('./firebase-service-account.json'); // Fallback pour local
try {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: `https://${serviceAccount.project_id}.firebaseio.com`
  });
  console.log('✅ Firebase Admin initialisé');
} catch (error) {
  console.error('❌ Erreur initialisation Firebase Admin:', error.message, error.stack);
  process.exit(1);
}


require('dotenv').config();
const db = admin.firestore(); // Define db after initialization



//Admin add1


// Ajouts pour intégration admin (Twitter hardcodé + données Firebase admin)
const ADMIN_SECRET = process.env.ADMIN_SECRET; // Ajoute dans .env: ADMIN_SECRET=ton_secret_super_securise
if (!ADMIN_SECRET) {
  console.error('❌ ADMIN_SECRET manquant dans .env');
  process.exit(1);
}

// Env vars pour Twitter admin hardcodé (ajoute dans .env: ADMIN_TWITTER_APP_KEY=xxx, etc.)
if (!process.env.ADMIN_TWITTER_APP_KEY || !process.env.ADMIN_TWITTER_APP_SECRET || !process.env.ADMIN_TWITTER_ACCESS_TOKEN || !process.env.ADMIN_TWITTER_ACCESS_SECRET) {
  console.error('❌ Variables d\'environnement Twitter Admin manquantes. Vérifiez votre fichier .env.');
  process.exit(1);
}

// Client Twitter admin hardcodé
const adminTwitterClient = new TwitterApi({
  appKey: process.env.ADMIN_TWITTER_APP_KEY,
  appSecret: process.env.ADMIN_TWITTER_APP_SECRET,
  accessToken: process.env.ADMIN_TWITTER_ACCESS_TOKEN,
  accessSecret: process.env.ADMIN_TWITTER_ACCESS_SECRET,
});

// Test connexion admin au startup (ajoute dans startServer plus bas)

async function testAdminTwitterConnection() {
  try {
    const me = await adminTwitterClient.v2.me();
    console.log('✅ Connexion Twitter Admin réussie:', me.data.username);
    return me.data.id;
  } catch (error) {
    console.error('❌ Échec de la connexion Twitter Admin:', error.message);
    process.exit(1);
  }
}

// Données admin globales (similaire à userData, mais pour admin unique)
let adminData = {
  userStyle: {
    writings: [],
    patterns: [],
    vocabulary: new Set(),
    tone: 'neutral',
    styleProgress: 0,
    lastModified: new Date().toISOString()
  },
  generatedTweetsHistory: [],
  scheduledTweets: [],
  dataLock: false,
  tweetIdCounter: 1,
  twitterUserId: null
};

// Ref Firebase pour admin (collection 'admin', doc 'data')
const adminRef = db.collection('admin').doc('data');

// Fonctions load/save admin (similaire à initializeUserData/saveUserData, mais pour admin)
async function loadAdminData() {
  try {
    const doc = await adminRef.get();
    if (doc.exists) {
      const data = doc.data();
      // Load userStyle
      adminData.userStyle = {
        ...adminData.userStyle,
        ...data.userStyle,
        vocabulary: new Set(data.userStyle?.vocabulary || []),
        lastModified: data.userStyle?.lastModified?.toDate()?.toISOString() || new Date().toISOString(),
      };
      // Load history
      adminData.generatedTweetsHistory = (data.generatedTweetsHistory || []).map(tweet => ({
        ...tweet,
        timestamp: new Date(tweet.timestamp),
        lastModified: new Date(tweet.lastModified),
      }));
      // Load scheduled
      adminData.scheduledTweets = (data.scheduledTweets || []).map(tweet => ({
        ...tweet,
        datetime: new Date(tweet.datetime),
        createdAt: new Date(tweet.createdAt),
        lastModified: new Date(tweet.lastModified),
        publishedAt: tweet.publishedAt ? new Date(tweet.publishedAt) : null,
      }));
      const maxId = Math.max(...adminData.scheduledTweets.map(t => t.id || 0), 1);
      adminData.tweetIdCounter = maxId + 1;
      console.log('✅ Données admin chargées depuis Firestore');
    } else {
      await saveAdminData();
      console.log('✅ Données admin créées dans Firestore');
    }
  } catch (error) {
    console.error('❌ Erreur load admin data:', error.message);
    throw error;
  }
}

async function saveAdminData() {
  if (adminData.dataLock) {
    console.log('🔒 Sauvegarde admin ignorée (verrou)');
    return;
  }
  adminData.dataLock = true;
  try {
    await adminRef.set({
      userStyle: {
        ...adminData.userStyle,
        vocabulary: Array.from(adminData.userStyle.vocabulary),
        lastModified: admin.firestore.Timestamp.fromDate(new Date(adminData.userStyle.lastModified)),
      },
      generatedTweetsHistory: adminData.generatedTweetsHistory.map(tweet => ({
        ...tweet,
        timestamp: admin.firestore.Timestamp.fromDate(new Date(tweet.timestamp)),
        lastModified: admin.firestore.Timestamp.fromDate(new Date(tweet.lastModified)),
      })),
      scheduledTweets: adminData.scheduledTweets.map(tweet => ({
        ...tweet,
        datetime: admin.firestore.Timestamp.fromDate(tweet.datetime),
        createdAt: admin.firestore.Timestamp.fromDate(tweet.createdAt),
        lastModified: admin.firestore.Timestamp.fromDate(tweet.lastModified),
        publishedAt: tweet.publishedAt ? admin.firestore.Timestamp.fromDate(tweet.publishedAt) : null,
      })),
    }, { merge: true });
    console.log('✅ Données admin sauvegardées dans Firestore');
  } catch (error) {
    console.error('❌ Erreur save admin data:', error.message);
  } finally {
    adminData.dataLock = false;
  }
}

// Fonction publish pour admin (similaire à publishTweetToTwitter, mais avec adminClient)
async function publishAdminTweetToTwitter(tweet, content) {
  try {
    console.log('🚀 Publication admin tweet:', tweet.id);
    let mediaIds = [];
    if (tweet.media && tweet.media.length > 0) {
      for (const media of tweet.media) {
        const filePath = path.join(__dirname, 'Uploads', 'admin', media.filename); // Dossier 'admin' pour uploads
        if (await fs.access(filePath).then(() => true).catch(() => false)) {
          const mediaId = await adminTwitterClient.v1.uploadMedia(filePath, { mimeType: media.mimetype });
          mediaIds.push(mediaId);
        }
      }
    }
    const options = { text: content };
    if (mediaIds.length > 0) options.media = { media_ids: mediaIds };
    const result = await adminTwitterClient.v2.tweet(options);
    // Cleanup media
    if (tweet.media && tweet.media.length > 0) {
      for (const media of tweet.media) {
        const filePath = path.join(__dirname, 'Uploads', 'admin', media.filename);
        await fs.unlink(filePath).catch(console.error);
      }
    }
    return result;
  } catch (error) {
    console.error('❌ Erreur publication admin Twitter:', error.message);
    throw error;
  }
}

// Scheduler checker pour admin (similaire à startScheduleChecker, mais pour admin)
function startAdminScheduleChecker() {
  console.log('⏰ Démarrage vérificateur admin tweets...');
  setInterval(async () => {
    const now = new Date();
    const tweetsToPublish = adminData.scheduledTweets.filter(t => t.status === 'scheduled' && t.datetime <= now);
    if (tweetsToPublish.length === 0) return;
    for (const tweet of tweetsToPublish) {
      try {
        await publishAdminTweetToTwitter(tweet, tweet.content);
        tweet.status = 'published';
        tweet.publishedAt = new Date();
        tweet.twitterId = 'admin-' + Date.now(); // Pas de real ID, mais OK
        tweet.lastModified = new Date();
        console.log(`✅ Admin tweet publié: ${tweet.id}`);
      } catch (error) {
        tweet.status = 'failed';
        tweet.error = error.message;
        tweet.lastModified = new Date();
      }
    }
    await saveAdminData();
  }, 30000); // 30s
}

// Middleware protection admin (simple header secret)
const adminAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        const adminKey = req.headers['x-admin-key'];
        if (!authHeader || !authHeader.startsWith('Bearer ') || adminKey !== process.env.ADMIN_SECRET) {
            console.log('❌ [DEBUG] Invalid admin key or token:', { authHeader: !!authHeader, adminKey });
            return res.status(401).json({ error: 'Unauthorized' });
        }
        const idToken = authHeader.split('Bearer ')[1];
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        console.log('✅ [DEBUG] Token verified:', { uid: decodedToken.uid });
        if (decodedToken.uid !== '5DOofrwItGflRGtUtbebf21sR2D3') {
            console.log('❌ [DEBUG] UID mismatch:', decodedToken.uid);
            return res.status(401).json({ error: 'Unauthorized: Not admin' });
        }
        req.user = decodedToken;
        next();
    } catch (error) {
        console.error('❌ [DEBUG] Token verification error:', error.message);
        return res.status(401).json({ error: 'Unauthorized' });
    }
};

//admin add1 end


const BASE_URL = process.env.NODE_ENV === 'production'
  ? 'https://ropainx.onrender.com'
  : 'http://localhost:3000';
// Templates de tweets structurels
const tweetTemplates = {
  'basic': {
    structure: "[hook] [statement]",
    example: "sorry not sorry but coding with ai makes it so fun to build products"
  },
  'repetition': {
    structure: "[phrase]\n[phrase]\n[phrase]\n[phrase]",
    example: "be better\nbe better\nbe better\nbe better"
  },
  'equation': {
    structure: "[concept] = [element1] + [element2]",
    example: "Discipline = Don't be a flake + See things through"
  },
  'oneliner': {
    structure: "[impactful statement]",
    example: "The best developer is the one who knows when not to code"
  },
  'bullet_points': {
    structure: "[title]:\n• [point1]\n• [point2]\n• [point3]\n[conclusion]",
    example: "Productivity Hack 101:\n• Unsure? Start.\n• Stressed? Move.\n• Afraid? Push through.\nEvery step builds strength."
  }
};

// Mapping intelligent template-mode
const templateModeMapping = {
  'tweet-viral': ['basic', 'oneliner', 'repetition'],
  'critique-constructive': ['equation', 'oneliner'],
  'thread-twitter': ['basic', 'basic'],
  'reformulation-simple': ['basic', 'oneliner'],
  'angle-contrarian': ['equation', 'oneliner'],
  'storytelling': ['basic', 'oneliner'],
  'rage-bait': ['oneliner', 'basic'],
  'metaphore-creative': ['equation', 'basic'],
  'style-personnel': ['basic', 'oneliner', 'bullet_points']
};


const metrics = {
  totalTweetGenerations: 0,
  generationsByMode: {},  // ex: { 'tweet-viral': 5, 'angle-contrarian': 3 }
  averageGenerationTimeMs: 0,
  totalErrors: 0,
  quickCommentsGenerated: 0,
  quickCommentsByType: {},  // ex: { 'joke': 2, 'contrarian': 1, 'agree': 4 }
  lastUpdate: new Date()
};
// Initialisation de l'application Express
const app = express();
const PORT = process.env.PORT || 3000;
// Fonction pour sélectionner un template
function selectTemplate(mode) {
  const availableTemplates = templateModeMapping[mode] || Object.keys(tweetTemplates);
  const randomIndex = Math.floor(Math.random() * availableTemplates.length);
  return availableTemplates[randomIndex];
}
// Configuration des middlewares
app.use(cors({
  origin: /*'http://localhost:3000', 'http://127.0.0.1:3000', 'http://127.0.0.1:8080', 'https://x.com','https://ropainx.onrender.com',*/"*",
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'If-None-Match', 'Authorization', 'X-User-ID', 'Accept', 'Origin', 'X-Requested-With'],
  credentials: true,
}));
app.use(express.json());

// Servir les fichiers statiques
app.use('/Uploads', express.static(path.join(__dirname, 'Uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// Serve static files from 'welcome' directory for assets

// Add cookie-parser requirement at the top, after other requires
const cookieParser = require('cookie-parser');

// Add cookie-parser middleware after app.use(express.json());
app.use(cookieParser());

// Modify the root route handler to use cookie for authentication
app.get('/', async (req, res) => {
  let uid = 'anonymous';

  // Check if user is authenticated via cookie
  if (req.cookies.idToken) {
    try {
      const decodedToken = await admin.auth().verifyIdToken(req.cookies.idToken, true);
      uid = decodedToken.uid;
      await initializeUserData(uid);

      // Serve dashboard (index.html at root) for authenticated users
      const html = await fs.readFile(path.join(__dirname, 'index.html'), 'utf8');
      const modifiedHtml = html.replace('<!-- UID_PLACEHOLDER -->', `<script>window.__USER_UID__ = "${uid}";</script>`);
      return res.send(modifiedHtml);
    } catch (error) {
      console.error('❌ Erreur vérification token cookie pour /:', error.message, error.stack);
      // Clear invalid cookie
      res.clearCookie('idToken');
      // Fall through to serve welcome page
    }
  }

  // Serve welcome/index.html for unauthenticated users
  const html = await fs.readFile(path.join(__dirname, 'welcome', 'index.html'), 'utf8');
  res.send(html);
});

// In /api/login route, add cookie setting after successful login
app.post('/api/login',verifyToken, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const idToken = authHeader.split('Bearer ')[1]; // Extract token to set in cookie
    const uid = req.user.uid;
    console.log(`🔍 Connexion pour UID: ${uid} - Début initialisation données`);
    await initializeUserData(uid);
    console.log(`✅ Initialisation données réussie pour ${uid}`);

    // Set cookie with idToken
    res.cookie('idToken', idToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000 // 1 hour
    });

    res.json({ success: true, message: 'Connexion réussie', uid });
  } catch (error) {
    console.error(`❌ Erreur traitement connexion pour ${req.user?.uid || 'inconnu'}:`, error.message, error.stack);
    res.status(500).json({ success: false, error: 'Échec traitement connexion', details: error.message });
  }
});

// In /api/logout route, add cookie clearing
app.post('/api/logout', async (req, res) => {
  try {
    const uid = req.user.uid;
    console.log(`🔍 Déconnexion pour UID: ${uid}`);
    await admin.auth().revokeRefreshTokens(uid);
    userData.delete(uid);
    tweetIdCounters.delete(uid);

    // Clear cookie
    res.clearCookie('idToken');

    console.log(`✅ Déconnexion réussie pour UID: ${uid}`);
    res.json({ success: true, message: 'Déconnexion réussie' });
  } catch (error) {
    console.error(`❌ Erreur déconnexion pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({ success: false, error: 'Échec déconnexion', details: error.message });
  }
});

// Optional: Remove or keep the /welcome route as needed. If you don't want a separate /welcome URL, comment it out:
// // app.get('/welcome', async (req, res) => {
// //   const html = await fs.readFile(path.join(__dirname, 'welcome', 'index.html'), 'utf8');
// //   res.send(html);
// // });

// Also, if you have app.use(express.static(path.join(__dirname, 'public'))); and no 'public' folder exists, remove it to avoid unnecessary middleware:
// // app.use(express.static(path.join(__dirname, 'public'))); // Comment or remove if no public folder

// Clean URL for /welcome (serves welcome/index.html without .html)

app.get('/auth', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'auth.html'));
});

// Route personnalisée pour "/welcome" → public/welcome/index.html
app.get('/welcome', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'welcome', 'index.html'));
});
// Initialisation Firebase Admin


// Configuration axios-retry
if (axiosRetry) {
  axiosRetry(axios, {
    retries: 3,
    retryDelay: (retryCount) => retryCount * 1000,
    retryCondition: (error) => {
      return error.response?.status === 429 || error.code === 'ECONNABORTED' || error.code === 'ENOTFOUND';
    }
  });
} else {
  console.warn('axios-retry not available, skipping retry configuration');
}

// Clés API
const GROQ_API_KEY = process.env.GROQ_API_KEY;
console.log("🔑 [DEBUG] GROQ_API_KEY:", process.env.GROQ_API_KEY ? "Présent" : "Manquant");

// Instance Axios pour l'API Groq
const axiosInstance = axios.create({
  timeout: 15000,
  headers: {
    Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
    'Content-Type': 'application/json',
  },
});

// Configuration Twitter OAuth 2.0 avec PKCE
const twitterOAuthClient = new TwitterApi({
  clientId: process.env.TWITTER_CLIENT_ID,
  clientSecret: process.env.TWITTER_CLIENT_SECRET,
});

// Stockage des données utilisateur
const userData = new Map();
const tweetIdCounters = new Map();

// Chemins des fichiers pour la persistance des données utilisateur

// Modified initializeUserData
async function initializeUserData(uid) {
  if (!userData.has(uid)) {
    console.log(`🔄 Initialisation données pour UID: ${uid}`);
    const defaultUserStyle = {
      writings: [],
      patterns: [],
      vocabulary: new Set(),
      tone: 'neutral',
      styleProgress: 0,
      lastModified: new Date().toISOString(),
    };
    userData.set(uid, {
      userStyle: defaultUserStyle,
      generatedTweetsHistory: [],
      scheduledTweets: [],
      twitterClient: null,
      twitterTokens: null,
      twitterUser: null,
      dataLock: false,
      sessionStart: new Date(),
    });
    tweetIdCounters.set(uid, 1);

    const userRef = db.collection('users').doc(uid);
    try {
      const userDoc = await userRef.get();
      if (userDoc.exists) {
        const data = userDoc.data();

        // Load userStyle
        userData.get(uid).userStyle = {
          ...defaultUserStyle,
          ...data.userStyle,
          vocabulary: new Set(data.userStyle?.vocabulary || []),
          lastModified: data.userStyle?.lastModified?.toDate()?.toISOString() || new Date().toISOString(),
        };

        // Load generatedTweetsHistory
        userData.get(uid).generatedTweetsHistory = (data.generatedTweetsHistory || []).map(tweet => ({
          ...tweet,
          timestamp: new Date(tweet.timestamp),
          lastModified: new Date(tweet.lastModified),
        }));
        if (userData.get(uid).generatedTweetsHistory.length > 0) {
          const maxId = Math.max(...userData.get(uid).generatedTweetsHistory.map(t => parseInt(t.id) || 0));
          if (maxId >= tweetIdCounters.get(uid)) tweetIdCounters.set(uid, maxId + 1);
        }

        // Load scheduledTweets
        userData.get(uid).scheduledTweets = (data.scheduledTweets || []).map(tweet => ({
          ...tweet,
          datetime: new Date(tweet.datetime),
          createdAt: new Date(tweet.createdAt),
          lastModified: new Date(tweet.lastModified),
          publishedAt: tweet.publishedAt ? new Date(tweet.publishedAt) : null,
          failedAt: tweet.failedAt ? new Date(tweet.failedAt) : null,
        }));
        if (userData.get(uid).scheduledTweets.length > 0) {
          const maxId = Math.max(...userData.get(uid).scheduledTweets.map(t => t.id || 0));
          if (maxId >= tweetIdCounters.get(uid)) tweetIdCounters.set(uid, maxId + 1);
        }

        // Load twitterTokens and related
        if (data.twitterTokens) {
          userData.get(uid).twitterTokens = data.twitterTokens;
          userData.get(uid).twitterClient = new TwitterApi(data.twitterTokens.access_token);
          userData.get(uid).twitterUser = data.twitterUser;
        }

        console.log(`✅ Données chargées depuis Firestore pour ${uid}`);
      } else {
        // Create default doc if none exists
        await saveUserData(uid);
        console.log(`✅ Document utilisateur créé dans Firestore pour ${uid}`);
      }
    } catch (error) {
      console.error(`❌ Erreur chargement données Firestore pour ${uid}:`, error.message, error.stack);
      throw new Error(`Échec chargement données: ${error.message}`);
    }
  }
}

// Modified saveUserData

async function saveUserData(uid) {
  const user = userData.get(uid);
  if (!user || user.dataLock) {
    console.log(`🔒 Sauvegarde données ignorée pour ${uid} (verrou ou données absentes)`);
    return;
  }
  user.dataLock = true;
  const userRef = db.collection('users').doc(uid);

  // Fonction helper pour convertir en timestamp sûrement
  const safeTimestamp = (dateValue) => {
    if (!dateValue) return null;
    const date = dateValue instanceof Date ? dateValue : new Date(dateValue);
    return isNaN(date.getTime()) ? admin.firestore.Timestamp.now() : admin.firestore.Timestamp.fromDate(date);
  };

  try {
    await userRef.set({
      userStyle: {
        ...user.userStyle,
        vocabulary: Array.from(user.userStyle.vocabulary),
        lastModified: safeTimestamp(user.userStyle.lastModified),
      },
      generatedTweetsHistory: user.generatedTweetsHistory.map(tweet => ({
        ...tweet,
        timestamp: safeTimestamp(tweet.timestamp),
        lastModified: safeTimestamp(tweet.lastModified),
      })),
      scheduledTweets: user.scheduledTweets.map(tweet => ({
        ...tweet,
        datetime: safeTimestamp(tweet.datetime),
        createdAt: safeTimestamp(tweet.createdAt),
        lastModified: safeTimestamp(tweet.lastModified),
        publishedAt: tweet.publishedAt ? safeTimestamp(tweet.publishedAt) : null,
        failedAt: tweet.failedAt ? safeTimestamp(tweet.failedAt) : null,
      })),
      twitterTokens: user.twitterTokens,
      twitterUser: user.twitterUser,
    }, { merge: true });
    console.log(`✅ Données sauvegardées dans Firestore pour ${uid}`);
  } catch (error) {
    console.error(`❌ Erreur sauvegarde données Firestore pour ${uid}:`, error.message, error.stack);
    throw new Error(`Échec sauvegarde données: ${error.message}`);
  } finally {
    user.dataLock = false;
  }
}


// Générer un ETag pour le cache
function generateETag(data) {
  return crypto.createHash('md5').update(JSON.stringify(data)).digest('hex');
}

// Détection du ton du texte
function detectTone(text) {
  const positiveWords = ['great', 'awesome', 'fantastic', 'love', 'happy', 'good', 'excellent', 'amazing'];
  const negativeWords = ['bad', 'terrible', 'hate', 'sad', 'problem', 'fail', 'awful', 'horrible'];
  const words = text.toLowerCase().split(/\s+/);
  let positiveCount = 0;
  let negativeCount = 0;

  words.forEach(word => {
    if (positiveWords.includes(word)) positiveCount++;
    if (negativeWords.includes(word)) negativeCount++;
  });

  if (positiveCount > negativeCount) return 'positive';
  if (negativeCount > positiveCount) return 'negative';
  return 'neutral';
}

// Générer un code verifier et challenge pour PKCE
function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// Configuration de Multer pour l'upload de fichiers
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    let uploadPath;
    if (req.headers['x-admin-key'] === ADMIN_SECRET) {
      uploadPath = path.join(__dirname, 'Uploads', 'admin');
    } else {
      uploadPath = path.join(__dirname, 'Uploads', req.user ? req.user.uid : 'anonymous');
    }
    await fs.mkdir(uploadPath, { recursive: true });
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
    cb(null, `${uniqueSuffix}-${file.originalname}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'video/mp4'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Type de fichier non supporté. Utilisez JPEG, PNG ou MP4.'), false);
    }
  },
});

// Middleware pour vérifier le token Firebase
async function verifyToken(req, res, next) {
    console.log('DEBUG - All headers:', req.headers);
    console.log('DEBUG - Authorization header:', req.headers.authorization);

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.error('ERREUR - Header auth manquant ou invalide:', authHeader);
        return res.status(401).json({ success: false, error: 'Aucun ou mauvais en-tête Authorization' });
    }

    const idToken = authHeader.split('Bearer ')[1];
    try {
        console.log(`🔍 Vérification token pour ${req.path}: ${idToken.substring(0, 10)}...`);
        const decodedToken = await Promise.race([
            admin.auth().verifyIdToken(idToken, false),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Token verification timeout')), 5000)) // 5s timeout
        ]);
        req.user = { uid: decodedToken.uid };
        console.log('✅ Token vérifié, UID:', decodedToken.uid);
        next();
    } catch (error) {
        console.error('❌ Erreur vérification token:', error.message, { path: req.path, stack: error.stack });
        if (error.code === 'auth/id-token-expired') {
            return res.status(401).json({ success: false, error: 'Token expiré', details: 'Veuillez vous reconnecter' });
        } else if (error.code === 'auth/id-token-revoked') {
            return res.status(401).json({ success: false, error: 'Token révoqué', details: 'Veuillez vous reconnecter' });
        }
        return res.status(401).json({ success: false, error: 'Token invalide', details: error.message });
    }
}
// Public routes (before verifyToken middleware)

// Route pour l'interface de connexion via extension (public)
app.get('/api/extension-login', (req, res) => {
  const loginPage = `
    <!DOCTYPE html>
    <html lang="fr">
    <head>
      <meta charset="UTF-8">
      <title>TwitterFlow - Connexion Extension</title>
      <script src="https://www.gstatic.com/firebasejs/10.7.1/firebase-app-compat.js"></script>
      <script src="https://www.gstatic.com/firebasejs/10.7.1/firebase-auth-compat.js"></script>
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          display: flex;
          justify-content: center;
          align-items: center;
          height: 100vh;
          margin: 0;
          background: #1a1a1a;
          color: white;
        }
        .container {
          text-align: center;
          padding: 20px;
          border-radius: 10px;
          background: rgba(255, 255, 255, 0.05);
          box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
        }
        button {
          padding: 10px 20px;
          margin: 10px;
          border: none;
          border-radius: 5px;
          background: #007BFE;
          color: white;
          cursor: pointer;
          font-size: 16px;
        }
        button:hover { background: #005bb5; }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>Connexion à TwitterFlow</h2>
        <p>Connectez-vous pour utiliser l'extension.</p>
        <button onclick="signInWithGoogle()">Connexion avec Google</button>
        <button onclick="signInWithTwitter()">Connexion avec Twitter</button>
        <button onclick="signInWithEmail()">Connexion avec Email</button>
        <div id="error" style="color: #ff6b6b; margin-top: 10px;"></div>
      </div>
      <script>
        const firebaseConfig = {
          apiKey: "AIzaSyCh0EeCbrm-LzHYOJAYTuQlJJzTFBs-xjo",
          authDomain: "ropainx-b13da.firebaseapp.com",
          projectId: "ropainx-b13da",
          storageBucket: "ropainx-b13da.firebasestorage.app",
          messagingSenderId: "293729340264",
          appId: "1:293729340264:web:89bbcdc6197a05520b64dd",
          measurementId: "G-H3T6EF9E4H"
        };
        firebase.initializeApp(firebaseConfig);
        const auth = firebase.auth();

        function signInWithGoogle() {
          const provider = new firebase.auth.GoogleAuthProvider();
          auth.signInWithPopup(provider)
            .then(async (result) => {
              const token = await result.user.getIdToken(true);
              console.log('✅ Token généré:', token.substring(0, 10) + '...');
              window.opener.postMessage({ type: 'TF_LOGIN', token, uid: result.user.uid }, '*');
              window.close();
            })
            .catch(error => {
              console.error('❌ Erreur connexion Google:', error.message);
              document.getElementById('error').innerText = 'Erreur: ' + error.message;
            });
        }
        function signInWithTwitter() {
          const provider = new firebase.auth.TwitterAuthProvider();
          auth.signInWithPopup(provider)
            .then(async (result) => {
              const token = await result.user.getIdToken(true);
              console.log('✅ Token Twitter-Firebase généré:', token.substring(0, 10) + '...');
              window.opener.postMessage({ type: 'TF_LOGIN', token, uid: result.user.uid }, '*');
              window.close();
            })
            .catch(error => {
              console.error('❌ Erreur connexion Twitter:', error.message);
              document.getElementById('error').innerText = 'Erreur: ' + error.message;
            });
        }
        function signInWithEmail() {
          const email = prompt('Entrez votre email:');
          const password = prompt('Entrez votre mot de passe:');
          if (email && password) {
            auth.signInWithEmailAndPassword(email, password)
              .then(async (result) => {
                const token = await result.user.getIdToken(true);
                console.log('✅ Token généré:', token.substring(0, 10) + '...');
                window.opener.postMessage({ type: 'TF_LOGIN', token, uid: result.user.uid }, '*');
                window.close();
              })
              .catch(error => {
                console.error('❌ Erreur connexion Email:', error.message);
                document.getElementById('error').innerText = 'Erreur: ' + error.message;
              });
          }
        }
      </script>
    </body>
    </html>
  `;
  res.send(loginPage);
});

// Route pour rafraîchir le token Firebase (public)
app.post('/api/refresh-token', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('❌ Aucun token fourni pour /api/refresh-token');
    return res.status(401).json({ success: false, error: 'Aucun token fourni' });
  }

  const oldToken = authHeader.split('Bearer ')[1];
  try {
    console.log(`🔄 Tentative de rafraîchissement du token: ${oldToken.substring(0, 10)}...`);
    const decodedToken = await admin.auth().verifyIdToken(oldToken, true);
    const newToken = await admin.auth().createCustomToken(decodedToken.uid);
    console.log('✅ Nouveau token généré pour UID:', decodedToken.uid);
    res.json({ success: true, idToken: newToken });
  } catch (error) {
    console.error('❌ Erreur rafraîchissement token:', error.message, error.stack);
    res.status(401).json({ success: false, error: 'Échec rafraîchissement token', details: error.message });
  }
});

// Apply verifyToken to all /api/* routes except the public ones above
app.use('/api/*', verifyToken);

// Protected routes below

// Route pour gérer la connexion via Firebase
// app.post('/api/login', async (req, res) => {
//   try {
//     const uid = req.user.uid;
//     console.log(`🔍 Connexion pour UID: ${uid} - Début initialisation données`);
//     await initializeUserData(uid);
//     console.log(`✅ Initialisation données réussie pour ${uid}`);
//     res.json({ success: true, message: 'Connexion réussie', uid });
//   } catch (error) {
//     console.error(`❌ Erreur traitement connexion pour ${req.user?.uid || 'inconnu'}:`, error.message, error.stack);
//     res.status(500).json({ success: false, error: 'Échec traitement connexion', details: error.message });
//   }
// });
//
// // Route pour la déconnexion Firebase
// app.post('/api/logout', async (req, res) => {
//   try {
//     const uid = req.user.uid;
//     console.log(`🔍 Déconnexion pour UID: ${uid}`);
//     await admin.auth().revokeRefreshTokens(uid);
//     userData.delete(uid);
//     tweetIdCounters.delete(uid);
//     console.log(`✅ Déconnexion réussie pour UID: ${uid}`);
//     res.json({ success: true, message: 'Déconnexion réussie' });
//   } catch (error) {
//     console.error(`❌ Erreur déconnexion pour ${req.user.uid}:`, error.message, error.stack);
//     res.status(500).json({ success: false, error: 'Échec déconnexion', details: error.message });
//   }
// });

// Statut d'authentification Firebase
app.get('/api/auth-status', async (req, res) => {
  try {
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    const isTwitterAuth = !!user.twitterClient;

    res.json({
      authenticated: true,
      user: user.twitterUser || null,
      twitterAuthenticated: isTwitterAuth,
      uid: uid
    });
  } catch (error) {
    console.error('❌ Erreur récupération statut auth:', error.message, error.stack);
    res.json({
      authenticated: false,
      user: null,
      twitterAuthenticated: false,
      uid: null,
      error: error.message
    });
  }
});

// Route pour initier l'authentification Twitter/X OAuth 2.0
app.get('/api/twitter-auth', async (req, res) => {
  try {
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

   const authLink = await twitterOAuthClient.generateOAuth2AuthLink(`${BASE_URL}/api/twitter-callback`, {
      scope: ['tweet.read', 'tweet.write', 'users.read', 'offline.access'],
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    user.twitterAuthState = authLink.state;
    user.codeVerifier = codeVerifier;

    console.log(`✅ Auth Twitter initiée pour ${uid}, URL: ${authLink.url}`);
    res.json({ success: true, authUrl: authLink.url });
  } catch (error) {
    console.error(`❌ Erreur initiation auth Twitter:`, error.message, error.stack);
    res.status(500).json({ success: false, error: 'Échec initiation auth Twitter', details: error.message });
  }
});

// Route pour gérer le callback Twitter/X OAuth (this is public-ish, but requires auth header as per code)
app.get('/api/twitter-callback', async (req, res) => {
  try {
    const { code, state } = req.query;

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'Token Firebase requis pour le callback' });
    }

    const idToken = authHeader.split('Bearer ')[1];
    const decodedToken = await admin.auth().verifyIdToken(idToken, true);
    const uid = decodedToken.uid;

    await initializeUserData(uid);
    const user = userData.get(uid);

    if (!user.twitterAuthState || user.twitterAuthState !== state) {
      console.error(`❌ Paramètre state invalide pour ${uid}`, { expected: user.twitterAuthState, received: state });
      return res.status(400).json({ success: false, error: 'Paramètre state invalide' });
    }

    if (!user.codeVerifier) {
      console.error(`❌ Code verifier manquant pour ${uid}`);
      return res.status(400).json({ success: false, error: 'Code verifier manquant' });
    }

    const { client, accessToken, refreshToken, expiresIn } = await twitterOAuthClient.loginWithOAuth2({
      code,
      codeVerifier: user.codeVerifier,
   redirectUri: `${BASE_URL}/api/twitter-callback`,
    });

    user.twitterTokens = {
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: expiresIn,
      expires_at: new Date(Date.now() + expiresIn * 1000),
    };
    user.twitterClient = client;

    const userInfo = await client.v2.me({
      'user.fields': 'id,username,name,profile_image_url',
    });
    user.twitterUser = {
      username: userInfo.data.name,
      handle: `@${userInfo.data.username}`,
      profile_picture: userInfo.data.profile_image_url,
    };

    await saveUserData(uid);
    delete user.twitterAuthState;
    delete user.codeVerifier;
    console.log(`✅ Auth Twitter complétée pour ${uid}, utilisateur: ${user.twitterUser.handle}`);
    res.redirect(`${BASE_URL}/`);
  } catch (error) {
    console.error(`❌ Erreur callback Twitter:`, error.message, error.stack);
    res.status(500).json({ success: false, error: 'Échec authentification Twitter', details: error.message });
  }
});

// Route pour rafraîchir le token Twitter/X
app.post('/api/twitter-refresh', async (req, res) => {
  try {
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    if (!user.twitterTokens || !user.twitterTokens.refresh_token) {
      return res.status(400).json({ success: false, error: 'Aucun refresh token disponible' });
    }

    const { client, accessToken, refreshToken, expiresIn } = await twitterOAuthClient.refreshOAuth2Token(
      user.twitterTokens.refresh_token
    );

    user.twitterTokens = {
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: expiresIn,
      expires_at: new Date(Date.now() + expiresIn * 1000),
    };
    user.twitterClient = client;

    await saveUserData(uid);
    console.log(`✅ Token Twitter rafraîchi pour ${uid}`);
    res.json({ success: true, message: 'Token Twitter rafraîchi' });
  } catch (error) {
    console.error(`❌ Erreur rafraîchissement token Twitter pour ${uid}:`, error.message, error.stack);
    res.status(500).json({ success: false, error: 'Échec rafraîchissement token Twitter', details: error.message });
  }
});

// Route pour déconnexion Twitter/X
app.post('/api/twitter-logout', async (req, res) => {
  try {
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    user.twitterTokens = null;
    user.twitterClient = null;
    user.twitterUser = null;
    await saveUserData(uid);
    console.log(`✅ Déconnexion Twitter réussie pour ${uid}`);
    res.json({ success: true, message: 'Déconnexion Twitter réussie' });
  } catch (error) {
    console.error(`❌ Erreur déconnexion Twitter pour ${uid}:`, error.message, error.stack);
    res.status(500).json({ success: false, error: 'Échec déconnexion Twitter', details: error.message });
  }
});
// Add this route after the twitter-logout route
app.get('/api/twitter-status', async (req, res) => {
  try {
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    res.json({
      success: true,
      authenticated: !!user.twitterClient,
      user: user.twitterUser || null
    });
  } catch (error) {
    console.error(`Error checking Twitter status for ${req.user.uid}:`, error);
    res.status(500).json({ success: false, error: 'Error checking Twitter status' });
  }
});

// Route pour récupérer les données utilisateur Twitter/X
app.get('/api/user', async (req, res) => {
  try {
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    if (!user.twitterUser) {
      return res.json({
        success: true,
        data: null,
        message: 'Utilisateur Twitter non authentifié'
      });
    }

    res.json({
      success: true,
      data: {
        username: user.twitterUser.username,
        handle: user.twitterUser.handle,
        profile_picture: user.twitterUser.profile_picture,
      },
    });
  } catch (error) {
    console.error(`❌ Erreur récupération données utilisateur pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({ success: false, error: 'Erreur récupération données utilisateur', details: error.message });
  }
});

// Route pour récupérer les statistiques utilisateur
app.get('/api/user-stats', async (req, res) => {
  try {
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    const stats = {
      tweetsGenerated: user.generatedTweetsHistory.length,
      tweetsScheduled: user.scheduledTweets.length,
      tweetsPublished: user.scheduledTweets.filter(t => t.status === 'published').length,
      tweetsFailed: user.scheduledTweets.filter(t => t.status === 'failed').length,
      styleProgress: user.userStyle.styleProgress,
      twitterAuthenticated: !!user.twitterClient,
      sessionDuration: Math.floor((new Date() - user.sessionStart) / 1000 / 60), // En minutes
    };

    res.json({ success: true, data: stats });
  } catch (error) {
    console.error(`❌ Erreur récupération stats pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({ success: false, error: 'Erreur récupération stats', details: error.message });
  }
});

// Route pour apprendre le style de l'utilisateur
app.post('/api/learn-style', async (req, res) => {
  try {
    const { styleText } = req.body;
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    if (!styleText || styleText.trim() === '') {
      return res.status(400).json({ success: false, error: 'styleText requis' });
    }

    const trimmedText = styleText.trim();
    user.userStyle.writings.push({ text: trimmedText, timestamp: new Date() });
    const words = trimmedText.toLowerCase().match(/\b\w+\b/g) || [];
    words.forEach(word => user.userStyle.vocabulary.add(word));
    user.userStyle.tone = detectTone(trimmedText);
    user.userStyle.styleProgress = Math.min(user.userStyle.styleProgress + 100, 10000);
    user.userStyle.lastModified = new Date();

    if (user.userStyle.writings.length > 50) {
      user.userStyle.writings = user.userStyle.writings.slice(-50);
    }

    await saveUserData(uid);
    console.log(`✅ Style appris pour ${uid}: ${trimmedText.substring(0, 50)}...`);
    res.json({
      success: true,
      message: 'Style appris avec succès',
      data: {
        styleProgress: user.userStyle.styleProgress,
        lastModified: user.userStyle.lastModified,
      },
    });
  } catch (error) {
    console.error(`❌ Erreur apprentissage style pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({
      success: false,
      error: 'Erreur apprentissage style',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
    });
  }
});
//alleger start

// Route pour générer des tweets avec système de templates
app.post('/api/generate-tweets', async (req, res) => {
  const startTime = Date.now(); // ✅ AJOUT: Définir startTime au début

  try {
    const { userComment, originalTweet, context, modeFilter } = req.body;
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    if (!userComment || userComment.trim() === '') {
      return res.status(400).json({ success: false, error: 'userComment requis' });
    }

    console.log(`🔍 Génération tweets pour ${uid}: ${userComment.substring(0, 50)}...`);

    const styleContext = user.userStyle.writings.length > 0
      ? `\n\nUser style (tone: ${user.userStyle.tone}, words: ${Array.from(user.userStyle.vocabulary)
          .slice(-5)
          .join(', ')}):\n${user.userStyle.writings.slice(-3).map(w => `- "${w.text}"`).join('\n')}`
      : '';

    const modes = [
      'tweet-viral',
      'critique-constructive',
      'thread-twitter',
      'reformulation-simple',
      'angle-contrarian',
      'storytelling',
      'rage-bait',
      'metaphore-creative',
      'style-personnel',
    ];

    // ... (garde tous tes modePrompts comme ils sont) ...
    const modePrompts = {
      'tweet-viral': (template) => `Write a viral-style tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Inspiration: "${userComment}"
Context: "${originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Start with a bold, surprising or slightly provocative hook
- Sentences max 12 words
- Use simple language (no jargon, easy for everyone)
- Break into short paragraphs (1–2 sentences per line)
- If relevant, twist the angle (e.g. mango → avocado)
- Encourage engagement (implicit or explicit question if it fits)
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'critique-constructive': (template) => `Write a constructive critique tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Based on: "${userComment}"
Context: "${originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Be clear and simple, avoid harsh tone
- Show value: suggest an improvement, not just point a flaw
- Sentences max 12 words, short paragraphs
- If possible, end with a question to invite discussion
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'thread-twitter': (template) => `Write the FIRST tweet of a thread using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Based on: "${userComment}"
Context: "${originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Strong hook, curiosity gap, or contrarian statement
- Sentences max 12 words
- Short paragraphs (1–2 sentences, then line break)
- Must make people want to click "show this thread"
- Use more than 200 chars
- Avoid jargon, keep it clear
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'reformulation-simple': (template) => `Reformulate simply using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Based on: "${userComment}"
Context: "${originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Keep it clear, concise, easy to read
- Sentences max 12 words
- Stay close to the original idea but lighter
- Avoid complex words or metaphors
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'angle-contrarian': (template) => `Write a contrarian tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Based on: "${userComment}"
Context: "${originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Start with "Hot take" style or bold contrarian hook
- Sentences max 12 words
- Short paragraphs, easy to scan
- Twist the perspective, avoid obvious angle
- End with a question if possible to spark replies
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'storytelling': (template) => `Write a storytelling tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Inspiration: "${userComment}"
Context: "${originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Tell a relatable story in paragraphs and make it long (betweeen 190 and 280 chars)
- Sentences max 12 words
- Build curiosity at the start
- Deliver a small lesson at the end
- Language must be simple, no jargon
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'rage-bait': (template) => `Write a rage-bait tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Topic: "${userComment}"
Context: "${originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Make the question bold, clear, and thought-provoking
- Sentences max 12 words
- Short and direct, easy to read
- Push readers to reflect or react
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'metaphore-creative': (template) => `Write a creative metaphor tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Inspiration: "${userComment}"
Context: "${originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Use a metaphor that shifts the angle (e.g. mango → avocado)
- Sentences max 12 words
- Keep it playful but clear
- Avoid clichés or overused sayings
- Encourage engagement if possible
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'style-personnel': (template) => `Write a personal-style tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Inspiration: "${userComment}"
Context: "${originalTweet || ''}"
Style (tone: ${user.userStyle.tone}, words: ${Array.from(user.userStyle.vocabulary).slice(-5).join(', ')})
Example: "${tweetTemplates[template].example}"
Rules:
- Match the user's tone and vocabulary closely
- Sentences max 12 words, short paragraphs
- Keep it authentic, like a friend tweeting
- Can end with a soft engagement question if natural
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,
    };

    const filteredModes = modeFilter && modes.includes(modeFilter) ? [modeFilter] : modes;

    // Sélectionner les templates pour chaque mode
    const selectedTemplates = filteredModes.map(mode => selectTemplate(mode));

    // Générer les prompts avec les templates
    const prompts = filteredModes.map((mode, index) => {
      const selectedTemplate = selectedTemplates[index];
      return modePrompts[mode](selectedTemplate);
    });

    user.userStyle.writings.push({ text: userComment.trim(), timestamp: new Date() });
    user.userStyle.tone = detectTone(userComment.trim());
    user.userStyle.styleProgress = Math.min(user.userStyle.styleProgress + 100, 10000);
    user.userStyle.lastModified = new Date();

    if (user.userStyle.writings.length > 50) {
      user.userStyle.writings = user.userStyle.writings.slice(-50);
    }

    const promises = prompts.map(async (prompt, index) => {
      try {
        console.log(`[SERVER DEBUG] Génération mode ${filteredModes[index]}`);

        const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
          messages: [
            {
              role: 'system',
              content:
                'Tweet expert. Generate original tweets based on user comment using EXACT structure provided. Secondary context: original tweet. Max 280 chars, no hashtags/emojis. Respond only with the tweet without quotes',
            },
            { role: 'user', content: prompt },
          ],
         model: 'llama-3.1-8b-instant',
          temperature: 0.7,
          max_tokens: 100,
        });

        const tweet = response.data.choices[0].message.content.trim();
        if (tweet.length > 280) {
          console.warn(`⚠️ Tweet trop long pour mode ${filteredModes[index]}: ${tweet.length} chars`);
          return { success: false, tweet: tweet.substring(0, 280), mode: filteredModes[index], template: selectedTemplates[index], error: 'Tweet trop long' };
        }
        return { success: true, tweet, mode: filteredModes[index], template: selectedTemplates[index] };
      } catch (error) {
        console.error(`❌ Erreur mode ${filteredModes[index]}:`, error.message);
        return {
          success: false,
          tweet: `Erreur: Échec génération pour ${filteredModes[index]}`,
          mode: filteredModes[index],
          template: selectedTemplates[index],
          error: error.message,
        };
      }
    });

    const results = await Promise.all(promises);
    const generatedTweets = results.map(r => r.tweet);
    const usedModes = results.map(r => r.mode);
    const usedTemplates = results.map(r => r.template);

    // ✅ CORRECTION: Rétablir les métriques avec startTime défini
    const endTime = Date.now();
    const duration = endTime - startTime;

    metrics.totalTweetGenerations += filteredModes.length;
    filteredModes.forEach(mode => {
      metrics.generationsByMode[mode] = (metrics.generationsByMode[mode] || 0) + 1;
    });
    metrics.averageGenerationTimeMs = (metrics.averageGenerationTimeMs * (metrics.totalTweetGenerations - filteredModes.length) + duration) / metrics.totalTweetGenerations;
    metrics.lastUpdate = new Date();

    const tweetData = {
      id: uuidv4(),
      timestamp: new Date(),
      lastModified: new Date(),
      originalTweet: originalTweet || null,
      userComment: userComment.trim(),
      context: context || null,
      generatedTweets,
      modesUsed: usedModes,
      templatesUsed: usedTemplates,
      used: false,
    };

    user.generatedTweetsHistory.push(tweetData);
    if (user.generatedTweetsHistory.length > 100) {
      user.generatedTweetsHistory = user.generatedTweetsHistory.slice(-100);
    }

    await saveUserData(uid);
    console.log(`✅ Tweets générés pour ${uid}: ${generatedTweets.length} avec templates: ${usedTemplates.join(', ')}`);

    if (user.generatedTweetsHistory.length > 0) {
        user.lastETagUpdate = Date.now();
    }

    res.json({
      success: true,
      data: tweetData,
      lastModified: tweetData.lastModified,
    });
  } catch (error) {
    console.error(`❌ Erreur génération tweets pour ${req.user?.uid || 'unknown'}:`, error.message);
    res.status(500).json({
      success: false,
      error: 'Erreur génération tweets',
      details: error.message,
    });
  }
});
app.get('/api/metrics', (req, res) => {
  if (!req.user || req.user.uid !== 'ton_uid_admin') {  // Sécurise si besoin
    return res.status(403).json({ error: 'Accès interdit' });
  }
  res.json({ success: true, metrics });
});
app.post('/api/generate-quick-comment', async (req, res) => {
  try {
    console.log('[SERVER DEBUG] Quick comment request:', req.body);
    const { type, wordsToInclude, originalTweet, uid } = req.body;

    if (!type) {
      console.log('[SERVER DEBUG] Erreur: type manquant');
      return res.status(400).json({ success: false, error: 'type requis' });
    }

    // Utiliser l'UID authentifié
    const authenticatedUid = req.user ? req.user.uid : uid;
    await initializeUserData(authenticatedUid);
    const user = userData.get(authenticatedUid);

    // Formater le tweet original avec retours à la ligne
    const formatOriginalTweet = (tweet) => {
      if (!tweet || tweet.length < 50) return tweet;

      // Diviser en phrases et ajouter des retours à la ligne
      return tweet
        .replace(/([.!?])\s+/g, '$1\n') // Retour après ponctuation
        .replace(/(.{60,}?)\s+/g, '$1\n') // Retour tous les ~60 chars
        .trim();
    };

    const formattedTweet = formatOriginalTweet(originalTweet);

    // Style utilisateur mais contextuellement approprié
    const userStyleHint = user && user.userStyle ?
      `Write in a ${user.userStyle.tone} tone, but prioritize relevance to the tweet content.` :
      'Write naturally and contextually.';

    // Prompts en anglais pour de meilleurs résultats
    let basePrompt = '';
    switch(type.toLowerCase()) {
      case 'agree':
        basePrompt = `Generate a Twitter reply that agrees with this tweet:\n\n"${formattedTweet}"\n\nShow genuine agreement and add valuable perspective.`;
        break;

      case 'disagree':
        basePrompt = `Generate a respectful Twitter reply that politely disagrees with this tweet:\n\n"${formattedTweet}"\n\nPresent a different viewpoint constructively.`;
        break;

      case 'joke':
      case 'funny':
        basePrompt = `Generate a witty, humorous Twitter reply to this tweet:\n\n"${formattedTweet}"\n\nMake it clever and contextually funny.`;
        break;

      case 'suspicious':
        basePrompt = `Generate a skeptical Twitter reply questioning this tweet:\n\n"${formattedTweet}"\n\nExpress healthy doubt with curiosity.`;
        break;

      case 'question':
        basePrompt = `Generate a thoughtful question as a Twitter reply to this tweet:\n\n"${formattedTweet}"\n\nAsk something that encourages discussion.`;
        break;

      default:
        basePrompt = `Generate a Twitter reply with a "${type}" style responding to this tweet:\n\n"${formattedTweet}"\n\nStay contextually relevant.`;
    }

    // Ajouter les mots SEULEMENT s'ils sont pertinents au contexte
    const wordsConstraint = wordsToInclude && wordsToInclude.length > 0
      ? ` If naturally fitting, try to incorporate these words: "${wordsToInclude.join(', ')}". Only use them if they make sense in context.`
      : '';

    const fullPrompt = `${basePrompt}${wordsConstraint}

${userStyleHint}

RULES:
- Maximum 280 characters
- Reply ONLY with the comment text
- No quotes, no hashtags unless contextually essential
- Make it feel natural and human
- Prioritize relevance to the original tweet over everything else`;

    console.log('[SERVER DEBUG] Prompt généré:', fullPrompt);

    const groqPayload = {
      messages: [
        {
          role: 'system',
          content: 'You are a social media expert who generates contextually relevant, engaging Twitter replies. Focus on the tweet content above all else.'
        },
        { role: 'user', content: fullPrompt }
      ],
      model: 'llama-3.1-8b-instant',
      temperature: 0.8, // Un peu plus créatif
      max_tokens: 100
    };

    console.log('[SERVER DEBUG] Payload Groq:', JSON.stringify(groqPayload, null, 2));

    const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', groqPayload);
    let comment = response.data.choices[0].message.content.trim();

    // Nettoyer les guillemets et formatage parasites
    comment = comment.replace(/^["']|["']$/g, '').replace(/\n+/g, ' ').trim();

    if (comment.length > 280) {
      console.warn(`[SERVER DEBUG] Commentaire trop long: ${comment.length} chars, troncature`);
      comment = comment.substring(0, 277) + '...';
    }

    console.log('[SERVER DEBUG] Commentaire généré:', comment);

    // Tracker métriques
    metrics.quickCommentsGenerated += 1;
    metrics.quickCommentsByType[type] = (metrics.quickCommentsByType[type] || 0) + 1;
    metrics.lastUpdate = new Date();

    res.json({ success: true, comment });

  } catch (error) {
    metrics.totalErrors += 1;
    console.error(`[SERVER DEBUG] Erreur quick comment:`, error.message);

    if (error.response) {
      console.error('[SERVER DEBUG] Erreur Groq - Status:', error.response.status);
      console.error('[SERVER DEBUG] Erreur Groq - Data:', JSON.stringify(error.response.data, null, 2));
    }

    res.status(500).json({
      success: false,
      error: 'Erreur génération commentaire',
      details: error.response?.data?.error?.message || error.message
    });
  }
});
// Route pour ask-ai (général Q&A via Groq)
app.post('/api/ask-ai', async (req, res) => {
  try {
    const { question } = req.body;
    const uid = req.user.uid;
    await initializeUserData(uid);

    if (!question || question.trim() === '') {
      return res.status(400).json({ success: false, error: 'question required' });
    }

    const prompt = `Answer this question concisely and helpfully: "${question.trim()}"`;

    const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
      messages: [
        { role: 'system', content: 'You are a helpful AI assistant. Answer directly and briefly.' },
        { role: 'user', content: prompt }
      ],
      model: 'llama-3.1-8b-instant',
          temperature: 0.7,
          max_tokens: 100,
    });

    const answer = response.data.choices[0].message.content.trim();
    res.json({ success: true, answer });

  } catch (error) {
    console.error(`❌ Error ask-ai for ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({ success: false, error: 'Error processing question' });
  }
});
// Route pour régénérer un tweet avec système de templates
app.post('/api/regenerate-tweet', async (req, res) => {
  try {
    const { tweetId, tweetIndex, mode } = req.body;
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    if (!tweetId || tweetIndex === undefined || !mode) {
      return res.status(400).json({ success: false, error: 'tweetId, tweetIndex et mode requis' });
    }

    const tweetGroup = user.generatedTweetsHistory.find(t => t.id === tweetId);
    if (!tweetGroup) {
      return res.status(404).json({ success: false, error: 'Groupe tweets non trouvé' });
    }

    if (!Number.isInteger(parseInt(tweetIndex)) || tweetIndex < 0 || tweetIndex >= tweetGroup.generatedTweets.length) {
      return res.status(400).json({ success: false, error: 'Index tweet invalide' });
    }

    const styleContext = user.userStyle.writings.length > 0
      ? `\n\nUser style (tone: ${user.userStyle.tone}, words: ${Array.from(user.userStyle.vocabulary)
          .slice(-5)
          .join(', ')}):\n${user.userStyle.writings.slice(-3).map(w => `- "${w.text}"`).join('\n')}`
      : '';

    const modePrompts = {
      'tweet-viral': (template) => `Generate a viral-style tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Content based on: "${tweetGroup.userComment}"
Context: "${tweetGroup.originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Start with a bold, surprising, or provocative hook
- Sentences max 12 words
- Short paragraphs (1–2 sentences per line)
- Use simple language, no jargon
- Twist the angle if possible (mango → avocado)
- Encourage engagement implicitly or explicitly
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'critique-constructive': (template) => `Generate a constructive critique tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Content based on: "${tweetGroup.userComment}"
Context: "${tweetGroup.originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Clear and respectful tone, no harshness
- Suggest an improvement, not just criticism
- Sentences max 12 words, short paragraphs
- Can end with a soft question to invite replies
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'thread-twitter': (template) => `Generate the FIRST tweet of a thread using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Content based on: "${tweetGroup.userComment}"
Context: "${tweetGroup.originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Hook must create curiosity or be contrarian
- Sentences max 12 words
- Short paragraphs, easy to scan
- Use more than 200 chars
- Make readers want to click "Show this thread"
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'reformulation-simple': (template) => `Generate a simple reformulation using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Content based on: "${tweetGroup.userComment}"
Context: "${tweetGroup.originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Keep close to the idea but make it lighter
- Sentences max 12 words
- Use simple words, no metaphors
- Must feel clear and easy to read
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'angle-contrarian': (template) => `Generate a contrarian tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Content based on: "${tweetGroup.userComment}"
Context: "${tweetGroup.originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Start with "Hot take" or bold contrarian hook
- Sentences max 12 words
- Short paragraphs, direct and readable
- Twist perspective, avoid obvious angles
- End with a thought-provoking question if possible
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'storytelling': (template) => `Generate a storytelling tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Content based on: "${tweetGroup.userComment}"
Context: "${tweetGroup.originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Tell a relatable story in paragraphs and make it long (betweeen 190 and 280 chars)
- Sentences max 12 words
- Start with curiosity, finish with a lesson
- Must feel human and relatable
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'rage-bait': (template) => `Generate a rage-bait tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Content based on: "${tweetGroup.userComment}"
Context: "${tweetGroup.originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Question must be bold, clear, thought-provoking
- Sentences max 12 words
- Push readers to reflect or react
- Short, direct, easy to scan
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'metaphore-creative': (template) => `Generate a creative metaphor tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Content based on: "${tweetGroup.userComment}"
Context: "${tweetGroup.originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Use a metaphor with a fresh angle (mango → avocado)
- Sentences max 12 words
- Keep it playful, not cliché
- Encourage engagement if natural
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'style-personnel': (template) => `Generate a personal-style tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Content based on: "${tweetGroup.userComment}"
Style (tone: ${user.userStyle.tone}, words: ${Array.from(user.userStyle.vocabulary).slice(-5).join(', ')})
Context: "${tweetGroup.originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Match the user's tone and vocabulary
- Sentences max 12 words, short paragraphs
- Must feel authentic, like a friend tweeting
- End with a soft question if natural
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,
    };

    if (!modePrompts[mode]) {
      return res.status(400).json({ success: false, error: 'Mode invalide' });
    }

    const selectedTemplate = selectTemplate(mode);
    const prompt = modePrompts[mode](selectedTemplate);

    const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
      messages: [
        {
          role: 'system',
          content:
            'Tweet expert. Generate original tweets based on user comment using EXACT structure provided. Secondary context: original tweet. Max 280 chars, no hashtags/emojis. Respond only with the tweet',
        },
        { role: 'user', content: prompt },
      ],
      model: 'llama-3.1-8b-instant',
          temperature: 0.7,
          max_tokens: 100,
    });

    const newTweet = response.data.choices[0].message.content.trim();
    if (newTweet.length > 280) {
      console.warn(`⚠️ Tweet régénéré trop long: ${newTweet.length} chars`);
      return res.status(400).json({ success: false, error: 'Tweet régénéré dépasse 280 chars' });
    }

    tweetGroup.generatedTweets[tweetIndex] = newTweet;
    tweetGroup.modesUsed[tweetIndex] = mode;

    // Initialiser templatesUsed si pas présent (compatibilité avec anciens tweets)
    if (!tweetGroup.templatesUsed) {
      tweetGroup.templatesUsed = new Array(tweetGroup.generatedTweets.length).fill('basic');
    }
    tweetGroup.templatesUsed[tweetIndex] = selectedTemplate;
    tweetGroup.lastModified = new Date();

    const scheduledTweet = user.scheduledTweets.find(t => t.tweetId === tweetId && t.tweetIndex === parseInt(tweetIndex));
    if (scheduledTweet) {
      scheduledTweet.content = newTweet;
      scheduledTweet.lastModified = new Date();
    }

    await saveUserData(uid);
    console.log(`✅ Tweet régénéré pour ${uid}: ${newTweet.substring(0, 50)}... avec template: ${selectedTemplate}`);
    res.json({
      success: true,
      data: { tweet: newTweet, mode, template: selectedTemplate, lastModified: tweetGroup.lastModified },
    });
  } catch (error) {
    console.error(`❌ Erreur régénération tweet pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({
      success: false,
      error: 'Erreur régénération tweet',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
    });
  }
});

// Route pour apprendre sur le contenu ragebait ou viral
app.post('/api/learn-content', async (req, res) => {
  try {
    const { type } = req.body;

    if (!['ragebait', 'viral'].includes(type)) {
      return res.status(400).json({ success: false, error: 'Type contenu invalide' });
    }

    const prompt =
      type === 'ragebait'
        ? 'Explain ragebait, how it works on social media, 3 example ragebait tweets. In French, max 500 chars.'
        : 'Explain viral content on social media, 3 example viral tweets. In French, max 500 chars.';

    const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
      messages: [
        { role: 'system', content: 'Social media expert. Concise explanation, examples in French, respect char limit.' },
        { role: 'user', content: prompt },
      ],
       model: 'llama-3.1-8b-instant',
          temperature: 0.7,
          max_tokens: 100,
    });

    const content = response.data.choices[0].message.content.trim();
    console.log(`✅ Contenu appris pour ${req.user.uid}: ${type}`);
    res.json({ success: true, data: content });
  } catch (error) {
    console.error(`❌ Erreur info contenu pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({
      success: false,
      error: 'Erreur récupération info contenu',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
    });
  }
});

//alleger edn

// Route pour récupérer l'historique des tweets
app.get('/api/tweets-history', async (req, res) => {
  try {
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    const data = user.generatedTweetsHistory
      .slice(-30)
      .reverse()
      .map(group => ({
        ...group,
        generatedTweets: group.generatedTweets || [],
        modesUsed: group.modesUsed || [],
        templatesUsed: group.templatesUsed || [], // Inclure les templates utilisés
        timestamp: new Date(group.timestamp),
        lastModified: new Date(group.lastModified),
      }));
    const etag = generateETag(data);
    if (req.get('If-None-Match') === etag) {
      console.log(`ℹ️ Données inchangées pour ${uid}`);
      return res.status(304).send();
    }
    res.set('ETag', etag);
    console.log(`✅ Historique tweets envoyé pour ${uid}: ${data.length} groupes`);
    res.json({
      success: true,
      data,
      lastModified: data[0]?.lastModified || new Date(),
    });
  } catch (error) {
    console.error(`❌ Erreur historique tweets pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({
      success: false,
      error: 'Erreur récupération historique',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
    });
  }
});

// Route pour marquer un tweet comme utilisé
app.post('/api/tweet-used', async (req, res) => {
  try {
    const { tweetId } = req.body;
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    if (!tweetId) {
      return res.status(400).json({ success: false, error: 'tweetId requis' });
    }

    const tweetGroup = user.generatedTweetsHistory.find(t => t.id === tweetId);
    if (!tweetGroup) {
      return res.status(404).json({ success: false, error: 'Tweet non trouvé' });
    }

    tweetGroup.used = true;
    tweetGroup.used_at = new Date();
    tweetGroup.lastModified = new Date();
    await saveUserData(uid);
    console.log(`✅ Tweet marqué utilisé pour ${uid}: ${tweetId}`);
    res.json({
      success: true,
      message: 'Tweet marqué utilisé',
      data: { lastModified: tweetGroup.lastModified },
    });
  } catch (error) {
    console.error(`❌ Erreur mise à jour tweet pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({
      success: false,
      error: 'Erreur mise à jour tweet',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
    });
  }
});

// Route pour éditer un tweet
app.post('/api/edit-tweet', async (req, res) => {
  try {
    const { tweetId, tweetIndex, newText } = req.body;
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    if (!tweetId || tweetIndex === undefined || !newText) {
      return res.status(400).json({ success: false, error: 'tweetId, tweetIndex et newText requis' });
    }

    const trimmedText = newText.trim();
    if (trimmedText === '') {
      return res.status(400).json({ success: false, error: 'Texte vide non autorisé' });
    }

    if (trimmedText.length > 280) {
      return res.status(400).json({ success: false, error: 'Tweet dépasse 280 chars' });
    }

    const tweetGroup = user.generatedTweetsHistory.find(t => t.id === tweetId);
    if (!tweetGroup) {
      return res.status(404).json({ success: false, error: 'Groupe tweets non trouvé' });
    }

    if (!Number.isInteger(parseInt(tweetIndex)) || tweetIndex < 0 || tweetIndex >= tweetGroup.generatedTweets.length) {
      return res.status(400).json({ success: false, error: 'Index tweet invalide' });
    }

    console.log(
      `📝 Modification tweet ${tweetId}[${tweetIndex}] pour ${uid}: "${tweetGroup.generatedTweets[tweetIndex]}" → "${trimmedText}"`
    );

    user.userStyle.writings.push({ text: trimmedText, timestamp: new Date() });
    const words = trimmedText.toLowerCase().match(/\b\w+\b/g) || [];
    words.forEach(word => user.userStyle.vocabulary.add(word));
    user.userStyle.tone = detectTone(trimmedText);
    user.userStyle.styleProgress = Math.min(user.userStyle.styleProgress + 100, 10000);
    user.userStyle.lastModified = new Date();

    if (user.userStyle.writings.length > 50) {
      user.userStyle.writings = user.userStyle.writings.slice(-50);
    }

    tweetGroup.generatedTweets[tweetIndex] = trimmedText;
    tweetGroup.lastModified = new Date();

    const scheduledTweet = user.scheduledTweets.find(t => t.tweetId === tweetId && t.tweetIndex === parseInt(tweetIndex));
    if (scheduledTweet) {
      scheduledTweet.content = trimmedText;
      scheduledTweet.lastModified = new Date();
    }

    await saveUserData(uid);
    console.log(`✅ Tweet modifié pour ${uid}: ${tweetId}[${tweetIndex}]`);
    res.json({
      success: true,
      message: 'Tweet modifié',
      data: {
        tweet: trimmedText,
        index: parseInt(tweetIndex),
        lastModified: tweetGroup.lastModified,
        styleProgress: user.userStyle.styleProgress,
      },
    });
  } catch (error) {
    console.error(`❌ Erreur modification tweet pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({
      success: false,
      error: 'Erreur modification tweet',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
    });
  }
});

// Route pour programmer un tweet
app.post('/api/schedule-tweet', upload.array('media', 4), async (req, res) => {
  try {
    const { content, datetime, tweetId, tweetIndex } = req.body;
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    if (!user.twitterClient) {
      return res.status(403).json({ success: false, error: 'Compte Twitter non authentifié' });
    }

    if (!content || !datetime || !tweetId || tweetIndex === undefined) {
      return res.status(400).json({ success: false, error: 'content, datetime, tweetId et tweetIndex requis' });
    }

    const trimmedContent = content.trim();
    if (trimmedContent === '') {
      return res.status(400).json({ success: false, error: 'Contenu vide non autorisé' });
    }

    if (trimmedContent.length > 280) {
      return res.status(400).json({ success: false, error: 'Tweet dépasse 280 chars' });
    }

    const scheduleDate = new Date(datetime);
    if (isNaN(scheduleDate.getTime())) {
      return res.status(400).json({ success: false, error: 'Date/heure invalide' });
    }

    const now = new Date();
    if (scheduleDate <= now) {
      return res.status(400).json({ success: false, error: 'Date doit être future' });
    }

    const tweetGroup = user.generatedTweetsHistory.find(t => t.id === tweetId);
    if (!tweetGroup) {
      return res.status(404).json({ success: false, error: 'Groupe tweets non trouvé' });
    }

    if (!Number.isInteger(parseInt(tweetIndex)) || parseInt(tweetIndex) < 0 || parseInt(tweetIndex) >= tweetGroup.generatedTweets.length) {
      return res.status(400).json({ success: false, error: 'Index tweet invalide' });
    }

    const media = req.files
      ? req.files.map(file => ({
          id: uuidv4(),
          filename: file.filename,
          originalName: file.originalname,
          path: file.path,
          url: `http://localhost:${PORT}/Uploads/${uid}/${file.filename}`,
          mimetype: file.mimetype,
          type: file.mimetype.startsWith('image/') ? 'image' : 'video',
        }))
      : [];

    const tweet = {
      id: tweetIdCounters.get(uid)++,
      content: trimmedContent,
      datetime: scheduleDate,
      createdAt: new Date(),
      lastModified: new Date(),
      media,
      status: 'scheduled',
      tweetId,
      tweetIndex: parseInt(tweetIndex),
    };

    const existingIndex = user.scheduledTweets.findIndex(t => t.tweetId === tweetId && t.tweetIndex === parseInt(tweetIndex));
    if (existingIndex !== -1) {
      const oldTweet = user.scheduledTweets[existingIndex];
      user.scheduledTweets.splice(existingIndex, 1);
      if (oldTweet.media && oldTweet.media.length > 0) {
        for (const media of oldTweet.media) {
          try {
            const filePath = path.join(__dirname, 'Uploads', uid, media.filename);
            if (await fs.access(filePath).then(() => true).catch(() => false)) {
              await fs.unlink(filePath);
              console.log(`✅ Fichier média supprimé: ${media.filename}`);
            }
          } catch (err) {
            console.warn(`⚠️ Erreur suppression fichier ${media.filename}:`, err.message);
          }
        }
      }
    }

    user.scheduledTweets.push(tweet);
    await saveUserData(uid);
    console.log(`✅ Tweet programmé pour ${uid}: ${tweet.id}`);
    res.json({
      success: true,
      tweet: {
        ...tweet,
        media: media.map(m => ({
          id: m.id,
          filename: m.filename,
          originalName: m.originalName,
          url: m.url,
          mimetype: m.mimetype,
          type: m.type,
        })),
      },
    });
  } catch (error) {
    console.error(`❌ Erreur programmation tweet pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({
      success: false,
      error: 'Erreur programmation tweet',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
    });
  }
});

// Route pour récupérer tous les tweets programmés
app.get('/api/tweets', async (req, res) => {
  try {
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    const data = user.scheduledTweets.map(tweet => ({
      ...tweet,
      media: (tweet.media || []).map(media => ({
        id: media.id,
        filename: media.filename,
        originalName: media.originalName,
        url: media.url || `http://localhost:${PORT}/Uploads/${uid}/${media.filename}`,
        mimetype: media.mimetype || 'application/octet-stream',
        type: media.type || (media.mimetype && media.mimetype.startsWith('image/') ? 'image' : 'video'),
      })),
    }));
    const etag = generateETag(data);
    if (req.get('If-None-Match') === etag) {
      console.log(`ℹ️ Données inchangées pour ${uid}`);
      return res.status(304).send();
    }
    res.set('ETag', etag);
    console.log(`✅ Tweets programmés envoyés pour ${uid}: ${data.length}`);
    res.json(data);
  } catch (error) {
    console.error(`❌ Erreur récupération tweets programmés pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({
      success: false,
      error: 'Erreur récupération tweets programmés',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
    });
  }
});

// Route pour supprimer un tweet programmé
app.delete('/api/tweets/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    const tweetIndex = user.scheduledTweets.findIndex(t => t.id === parseInt(id));
    if (tweetIndex === -1) {
      return res.status(404).json({ success: false, error: 'Tweet programmé non trouvé' });
    }

    const tweet = user.scheduledTweets[tweetIndex];
    if (tweet.media && tweet.media.length > 0) {
      for (const media of tweet.media) {
        try {
          const filePath = path.join(__dirname, 'Uploads', uid, media.filename);
          if (await fs.access(filePath).then(() => true).catch(() => false)) {
            await fs.unlink(filePath);
            console.log(`✅ Fichier média supprimé: ${media.filename}`);
          }
        } catch (err) {
          console.warn(`⚠️ Erreur suppression fichier ${media.filename}:`, err.message);
        }
      }
    }

    user.scheduledTweets.splice(tweetIndex, 1);
    await saveUserData(uid);
    console.log(`✅ Tweet programmé supprimé pour ${uid}: ${id}`);
    res.json({
      success: true,
      message: 'Tweet programmé supprimé',
    });
  } catch (error) {
    console.error(`❌ Erreur suppression tweet programmé pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({
      success: false,
      error: 'Erreur suppression tweet programmé',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
    });
  }
});

// Route pour supprimer un tweet de l'historique
app.post('/api/delete-tweet', async (req, res) => {
  try {
    const { tweetId, tweetIndex } = req.body;
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    if (!tweetId || tweetIndex === undefined) {
      return res.status(400).json({ success: false, error: 'tweetId et tweetIndex requis' });
    }

    const tweetGroup = user.generatedTweetsHistory.find(t => t.id === tweetId);
    if (!tweetGroup) {
      return res.status(404).json({ success: false, error: 'Groupe tweets non trouvé' });
    }

    if (!Number.isInteger(parseInt(tweetIndex)) || tweetIndex < 0 || tweetIndex >= tweetGroup.generatedTweets.length) {
      return res.status(400).json({ success: false, error: 'Index tweet invalide' });
    }

    const scheduledTweetIndex = user.scheduledTweets.findIndex(t => t.tweetId === tweetId && t.tweetIndex === parseInt(tweetIndex));
    if (scheduledTweetIndex !== -1) {
      const tweet = user.scheduledTweets[scheduledTweetIndex];
      if (tweet.media && tweet.media.length > 0) {
        for (const media of tweet.media) {
          try {
            const filePath = path.join(__dirname, 'Uploads', uid, media.filename);
            if (await fs.access(filePath).then(() => true).catch(() => false)) {
              await fs.unlink(filePath);
              console.log(`✅ Fichier média supprimé: ${media.filename}`);
            }
          } catch (err) {
            console.warn(`⚠️ Erreur suppression fichier ${media.filename}:`, err.message);
          }
        }
      }
      user.scheduledTweets.splice(scheduledTweetIndex, 1);
    }

    tweetGroup.generatedTweets.splice(tweetIndex, 1);
    tweetGroup.modesUsed.splice(tweetIndex, 1);

    // Gérer templatesUsed si présent
    if (tweetGroup.templatesUsed) {
      tweetGroup.templatesUsed.splice(tweetIndex, 1);
    }

    tweetGroup.lastModified = new Date();

    if (tweetGroup.generatedTweets.length === 0) {
      user.generatedTweetsHistory = user.generatedTweetsHistory.filter(t => t.id !== tweetId);
    }

    await saveUserData(uid);
    console.log(`✅ Tweet supprimé pour ${uid}: ${tweetId}[${tweetIndex}]`);
    res.json({
      success: true,
      message: 'Tweet supprimé',
      data: {
        remaining: tweetGroup.generatedTweets.length,
        lastModified: tweetGroup.lastModified,
      },
    });
  } catch (error) {
    console.error(`❌ Erreur suppression tweet pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({
      success: false,
      error: 'Erreur suppression tweet',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
    });
  }
});

// Route pour publier un tweet programmé immédiatement
app.post('/api/tweets/:id/publish', async (req, res) => {
  try {
    const { id } = req.params;
    const { content } = req.body;
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    if (!user.twitterClient) {
      return res.status(403).json({ success: false, error: 'Compte Twitter non authentifié' });
    }

    const tweet = user.scheduledTweets.find(t => t.id === parseInt(id));
    if (!tweet) {
      return res.status(404).json({ success: false, error: 'Tweet programmé non trouvé' });
    }

    if (tweet.status !== 'scheduled') {
      return res.status(400).json({ success: false, error: 'Tweet non programmé' });
    }

    const result = await publishTweetToTwitter(tweet, content || tweet.content, uid);

    tweet.status = 'published';
    tweet.publishedAt = new Date();
    tweet.twitterId = result.data.id;
    tweet.lastModified = new Date();
    await saveUserData(uid);
    console.log(`✅ Tweet publié pour ${uid}: ${tweet.id}`);
    res.json({
      success: true,
      message: 'Tweet publié',
      result: result.data,
    });
  } catch (error) {
    console.error(`❌ Erreur publication tweet pour ${req.user.uid}:`, error.message, error.stack);
    const user = userData.get(req.user.uid);
    const tweet = user.scheduledTweets.find(t => t.id === parseInt(req.params.id));
    if (tweet) {
      tweet.status = 'failed';
      tweet.error = error.message;
      tweet.lastModified = new Date();
      tweet.failedAt = new Date();
      await saveUserData(req.user.uid);
    }

    res.status(error.code === 429 ? 429 : 500).json({
      success: false,
      error: 'Erreur publication tweet',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
    });
  }
});

// Fonction pour publier un tweet sur Twitter/X avec logique de retry
async function publishTweetToTwitter(tweet, content, uid) {
  const maxRetries = 3;
  let retryCount = 0;
  const user = userData.get(uid);
  const twitterClient = user.twitterClient;

  if (!twitterClient) {
    throw new Error("Aucun client Twitter disponible pour l'utilisateur");
  }

  // Vérifier si le token est expiré
  if (user.twitterTokens.expires_at < new Date()) {
    console.log(`🔄 Token Twitter expiré pour ${uid}, tentative de rafraîchissement`);
    const { client, accessToken, refreshToken, expiresIn } = await twitterOAuthClient.refreshOAuth2Token(
      user.twitterTokens.refresh_token
    );
    user.twitterTokens = {
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: expiresIn,
      expires_at: new Date(Date.now() + expiresIn * 1000),
    };
    user.twitterClient = client;
    await saveUserData(uid);
  }

  async function attemptPublish() {
    try {
      console.log(`🚀 Publication du tweet ${tweet.id} pour ${uid}`);

      let mediaIds = [];
      if (tweet.media && tweet.media.length > 0) {
        console.log('📎 Upload des médias...');
        for (const media of tweet.media) {
          const filePath = path.join(__dirname, 'Uploads', uid, media.filename);
          try {
            await fs.access(filePath);
            const mediaId = await twitterClient.v1.uploadMedia(filePath, {
              mimeType: media.mimetype,
            });
            mediaIds.push(mediaId);
            console.log(`✅ Média uploadé: ${media.filename}`);
          } catch (fileError) {
            console.warn(`⚠️ Fichier média introuvable, ignoré: ${media.filename}`);
          }
        }
      }

      const tweetOptions = { text: content };
      if (mediaIds.length > 0) {
        tweetOptions.media = { media_ids: mediaIds };
      }

      const result = await twitterClient.v2.tweet(tweetOptions);
      console.log(`✅ Tweet publié avec succès: ${result.data.id}`);

      if (tweet.media && tweet.media.length > 0) {
        for (const media of tweet.media) {
          try {
            const filePath = path.join(__dirname, 'Uploads', uid, media.filename);
            if (await fs.access(filePath).then(() => true).catch(() => false)) {
              await fs.unlink(filePath);
              console.log(`✅ Fichier média supprimé: ${media.filename}`);
            }
          } catch (err) {
            console.warn(`⚠️ Erreur suppression fichier ${media.filename}:`, err.message);
          }
        }
      }

      return result;
    } catch (error) {
      if (error.code === 429 && retryCount < maxRetries) {
        retryCount++;
        const waitTime = Math.pow(2, retryCount) * 1000;
        console.log(`⚠️ Limite de taux atteinte, nouvelle tentative dans ${waitTime / 1000}s (tentative ${retryCount}/${maxRetries})`);
        await new Promise(resolve => setTimeout(resolve, waitTime));
        return attemptPublish();
      }
      console.error(`❌ Erreur publication Twitter pour ${uid}:`, error.message, error.stack);
      throw error;
    }
  }

  return attemptPublish();
}

// Polar stuff
app.get('/api/subscription-status', async (req, res) => {
  try {
    const userId = req.user.uid;
    const subscriptionDoc = await db.collection('subscriptions').doc(userId).get();

    if (!subscriptionDoc.exists) {
      return res.json({ status: 'free' });
    }

    const subscriptionData = subscriptionDoc.data();
    if (subscriptionData.active && subscriptionData.type === 'premium') {
      return res.json({ status: 'premium' });
    }

    return res.json({ status: 'free' });
  } catch (error) {
    console.error('Error checking subscription:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint pour créer une session de checkout avec Polar
app.post('/api/create-checkout', async (req, res) => {
  try {
    const userId = req.user.uid;
    const user = await admin.auth().getUser(userId);
    const email = user.email;

    if (!email) {
      return res.status(400).json({ error: 'User email is required' });
    }

    const { success_url, cancel_url } = req.body;

    if (!success_url || !cancel_url) {
      return res.status(400).json({ error: 'success_url and cancel_url are required' });
    }

    // Appel à l'API Polar pour créer un checkout
    const polarResponse = await axios.post(
      `${process.env.POLAR_API_URL}/checkouts`,
      {
        product_id: process.env.POLAR_PRODUCT_ID,
        customer_email: email,
        success_url: success_url,
        cancel_url: cancel_url,
        // Ajoutez d'autres paramètres si nécessaires, comme quantity: 1, currency: 'EUR', etc.
        currency: process.env.PREMIUM_CURRENCY || 'EUR',
        amount: process.env.PREMIUM_PRICE_EUR * 100, // Si prix en cents, ajustez selon l'API Polar
      },
      {
        headers: {
          'Authorization': `Bearer ${process.env.POLAR_ACCESS_TOKEN}`,
          'Content-Type': 'application/json'
        }
      }
    );

    if (polarResponse.data && polarResponse.data.url) {
      return res.json({
        success: true,
        checkout_url: polarResponse.data.url
      });
    } else {
      throw new Error('No checkout URL returned from Polar');
    }
  } catch (error) {
    console.error('Error creating checkout:', error.response ? error.response.data : error.message);
    return res.status(500).json({ error: error.message || 'Failed to create checkout' });
  }
});

// Endpoint pour le webhook Polar
app.post('/webhook/polar', async (req, res) => {
  try {
    const signature = req.headers['polar-signature'];
    if (!signature) {
      return res.status(400).send('Missing signature');
    }

    // Vérifier la signature du webhook
    const hmac = crypto.createHmac('sha256', process.env.POLAR_WEBHOOK_SECRET);
    const digest = hmac.update(JSON.stringify(req.body)).digest('hex');
    if (signature !== digest) {
      return res.status(401).send('Invalid signature');
    }

    const event = req.body;

    // Gérer les événements Polar
    if (event.type === 'subscription.created' || event.type === 'subscription.updated') {
      const subscription = event.data.subscription;
      const userEmail = subscription.customer_email;
      const status = subscription.status; // 'active', 'canceled', etc.

      // Trouver l'utilisateur par email
      const user = await admin.auth().getUserByEmail(userEmail);
      if (!user) {
        console.warn('User not found for email:', userEmail);
        return res.status(200).send('OK');
      }

      const userId = user.uid;

      // Mettre à jour Firestore
      await db.collection('subscriptions').doc(userId).set({
        type: 'premium',
        active: status === 'active',
        polarSubscriptionId: subscription.id,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
    } else if (event.type === 'subscription.canceled') {
      const subscription = event.data.subscription;
      const userEmail = subscription.customer_email;

      const user = await admin.auth().getUserByEmail(userEmail);
      if (!user) {
        console.warn('User not found for email:', userEmail);
        return res.status(200).send('OK');
      }

      const userId = user.uid;

      await db.collection('subscriptions').doc(userId).update({
        active: false,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
    }

    // Ajoutez la gestion d'autres événements si nécessaire

    return res.status(200).send('OK');
  } catch (error) {
    console.error('Webhook error:', error);
    return res.status(500).send('Internal server error');
  }
});
// end polar stuff

// Vérificateur de tweets programmés
function startScheduleChecker() {
  console.log('⏰ Démarrage du vérificateur de tweets programmés...');

  const checkInterval = setInterval(async () => {
    try {
      const now = new Date();
      console.log(`🔍 Vérification des tweets programmés à ${now.toLocaleString()}`);

      for (const [uid, user] of userData) {
        if (!user.twitterClient) {
          continue;
        }

        const tweetsToPublish = user.scheduledTweets.filter(tweet => tweet.status === 'scheduled' && new Date(tweet.datetime) <= now);

        if (tweetsToPublish.length === 0) {
          continue;
        }

        console.log(`📝 ${tweetsToPublish.length} tweet(s) à publier pour ${uid}`);

        for (const tweet of tweetsToPublish) {
          try {
            console.log(`🚀 Tentative de publication du tweet ${tweet.id} pour ${uid}: "${tweet.content.substring(0, 50)}..."`);

            const result = await publishTweetToTwitter(tweet, tweet.content, uid);

            tweet.status = 'published';
            tweet.publishedAt = new Date();
            tweet.twitterId = result.data.id;
            tweet.lastModified = new Date();

            console.log(`✅ Tweet ${tweet.id} publié avec succès pour ${uid}: ${result.data.id}`);
          } catch (error) {
            console.error(`❌ Erreur publication tweet ${tweet.id} pour ${uid}:`, error.message, error.stack);
            tweet.status = 'failed';
            tweet.error = error.message;
            tweet.lastModified = new Date();
            tweet.failedAt = new Date();
          }
        }

        await saveUserData(uid);
      }
    } catch (error) {
      console.error('❌ Erreur dans le vérificateur de tweets:', error.message, error.stack);
    }
  }, 15000);

  process.scheduleChecker = checkInterval;
}

// // Route pour l'interface web
// app.get('/', async (req, res) => {
//   const authHeader = req.headers.authorization;
//   let uid = 'anonymous';
//   if (authHeader && authHeader.startsWith('Bearer ')) {
//     try {
//       const idToken = authHeader.split('Bearer ')[1];
//       const decodedToken = await admin.auth().verifyIdToken(idToken, true);
//       uid = decodedToken.uid;
//       await initializeUserData(uid);
//     } catch (error) {
//       console.error('❌ Erreur vérification token pour /:', error.message, error.stack);
//     }
//   }
//
//   const html = await fs.readFile(path.join(__dirname, 'public', 'index.html'), 'utf8');
//   const modifiedHtml = html.replace('<!-- UID_PLACEHOLDER -->', `<script>window.__USER_UID__ = "${uid}";</script>`);
//   res.send(modifiedHtml);
// });

// Route pour vérifier l'état du serveur
app.get('/health', async (req, res) => {
  try {
    const uid = req.user ? req.user.uid : 'anonymous';
    await initializeUserData(uid);
    const user = userData.get(uid) || {
      generatedTweetsHistory: [],
      scheduledTweets: [],
      userStyle: { writings: [], styleProgress: 0 },
    };

    res.json({
      status: 'OK',
      timestamp: new Date(),
      version: '2.4.0', // Mise à jour version avec templates
      tweetsCount: user.generatedTweetsHistory.length,
      scheduledTweetsCount: user.scheduledTweets.length,
      scheduledActiveCount: user.scheduledTweets.filter(t => t.status === 'scheduled').length,
      publishedCount: user.scheduledTweets.filter(t => t.status === 'published').length,
      failedCount: user.scheduledTweets.filter(t => t.status === 'failed').length,
      userStyleWritings: user.userStyle.writings.length,
      styleProgress: user.userStyle.styleProgress,
      userId: uid,
      twitterAuthenticated: !!user.twitterClient,
      templatesAvailable: Object.keys(tweetTemplates), // Nouveaux templates disponibles
    });
  } catch (error) {
    console.error('❌ Erreur health check:', error.message, error.stack);
    res.status(500).json({
      status: 'ERROR',
      error: error.message,
      timestamp: new Date(),
    });
  }
});

// Middleware de gestion des erreurs
app.use((error, req, res, next) => {
  console.error(`❌ Erreur globale pour ${req.user ? req.user.uid : 'anonymous'}:`, error.message, error.stack);
  res.status(error.message.includes('Type de fichier non supporté') ? 400 : 500).json({
    success: false,
    error: error.message.includes('Type de fichier non supporté') ? error.message : 'Erreur serveur interne',
    details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
  });
});


//admin route


// Dans server.js
const { getFirestore, collection, query, where, getDocs } = require('firebase/firestore');

app.get('/api/admin/tweets-history-by-uid', verifyToken, async (req, res) => {
    try {
        const uid = req.query.uid;
        if (!uid) {
            return res.status(400).json({ success: false, error: 'UID requis' });
        }
        if (req.user.uid !== uid) {
            return res.status(403).json({ success: false, error: 'Accès non autorisé' });
        }

        const db = getFirestore();
        const tweetsRef = collection(db, 'tweets');
        const q = query(tweetsRef, where('userId', '==', uid));
        const querySnapshot = await getDocs(q);
        const tweets = querySnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

        res.set('ETag', generateETag(tweets)); // Fonction pour générer ETag
        res.json({ success: true, data: tweets });
    } catch (error) {
        console.error('Erreur récupération tweets:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});
// Middleware admin sur ces routes
app.use('/api/admin/*', adminAuth);

// Route pour fetch communautés admin (placeholder comme avant)
app.get('/api/admin/user-communities', async (req, res) => {
  try {
    let communities = [];
    // Placeholder, comme dans le premier code
    res.json({ success: true, data: communities });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur communautés' });
  }
});

// Route update communauté admin
app.post('/api/admin/update-tweet-community', async (req, res) => {
  try {
    const { tweetId, tweetIndex, communityId } = req.body;
    const scheduledTweet = adminData.scheduledTweets.find(t => t.tweetId === tweetId && t.tweetIndex === parseInt(tweetIndex));
    if (!scheduledTweet) return res.status(404).json({ success: false, error: 'Tweet non trouvé' });
    scheduledTweet.communityId = communityId || null;
    scheduledTweet.lastModified = new Date().toISOString();
    await saveAdminData();
    res.json({ success: true, message: 'Communauté mise à jour' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur update communauté' });
  }
});

// Route learn-style admin
app.post('/api/admin/learn-style', async (req, res) => {
  try {
    const { styleText } = req.body;
    if (!styleText.trim()) return res.status(400).json({ success: false, error: 'styleText requis' });
    const trimmedText = styleText.trim();
    adminData.userStyle.writings.push({ text: trimmedText, timestamp: new Date() });
    const words = trimmedText.toLowerCase().match(/\b\w+\b/g) || [];
    words.forEach(word => adminData.userStyle.vocabulary.add(word));
    adminData.userStyle.tone = detectTone(trimmedText); // Réutilise fonction existante
    adminData.userStyle.styleProgress += 1;
    adminData.userStyle.lastModified = new Date().toISOString();
    if (adminData.userStyle.writings.length > 50) adminData.userStyle.writings = adminData.userStyle.writings.slice(-50);
    await saveAdminData();
    res.json({
      success: true,
      message: 'Style appris',
      data: { styleProgress: adminData.userStyle.styleProgress, lastModified: adminData.userStyle.lastModified }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur learn-style' });
  }
});

// Route generate-tweets admin (copie du premier, avec Groq, modes, intégrant style admin)
app.post('/api/admin/generate-tweets', async (req, res) => {
  try {
    const { userComment, originalTweet, context, modeFilter } = req.body;
    if (!userComment.trim()) return res.status(400).json({ success: false, error: 'userComment requis' });

    const styleContext = adminData.userStyle.writings.length > 0 ?
      `\n\nUser style (tone: ${adminData.userStyle.tone}, words: ${Array.from(adminData.userStyle.vocabulary).slice(-5).join(', ')}):\n${adminData.userStyle.writings.slice(-3).map(w => `- "${w.text}"`).join('\n')}` : '';

    const modes = ['tweet-viral', 'critique-constructive', 'thread-twitter', 'reformulation-simple', 'angle-contrarian', 'storytelling', 'rage-bait', 'metaphore-creative', 'style-personnel'];
    const filteredModes = modeFilter ? [modeFilter] : modes;

    // Prompts (copie du premier)
    const modePrompts = {
      'tweet-viral': `Generate a viral tweet based on: "${userComment}". Secondary context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'critique-constructive': `Generate a constructive critique tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'thread-twitter': `Generate the first tweet of a thread based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'reformulation-simple': `Generate a simple reformulation tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'angle-contrarian': `Generate a contrarian angle tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'storytelling': `Generate a storytelling tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'rage-bait': `Generate a rage-bait tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'metaphore-creative': `Generate a creative metaphor tweet for: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'style-personnel': `Generate a personal style tweet based on: "${userComment}". Style (tone: ${adminData.userStyle.tone}, words: ${Array.from(adminData.userStyle.vocabulary).slice(-5).join(', ')}). Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`
    };

    const prompts = filteredModes.map(mode => modePrompts[mode]);
    adminData.userStyle.writings.push({ text: userComment.trim(), timestamp: new Date() });
    adminData.userStyle.tone = detectTone(userComment.trim());
    adminData.userStyle.styleProgress += 1;
    adminData.userStyle.lastModified = new Date().toISOString();
    if (adminData.userStyle.writings.length > 50) adminData.userStyle.writings = adminData.userStyle.writings.slice(-50);

    const promises = prompts.map(async (prompt, index) => {
      try {
        const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
          messages: [{ role: 'system', content: 'Tweet expert. Generate original tweets... Respond only with the tweet.' }, { role: 'user', content: prompt }],
          model: 'llama3-8b-8192',
          temperature: 0.7,
          max_tokens: 100
        });
        return response.data.choices[0].message.content.trim();
      } catch (error) {
        return `Error: Generation failed for ${filteredModes[index]}`;
      }
    });

    const generatedTweets = await Promise.all(promises);
    const tweetData = {
      id: Date.now().toString(),
      timestamp: new Date().toISOString(),
      lastModified: new Date().toISOString(),
      originalTweet: originalTweet || null,
      userComment: userComment.trim(),
      context: context || null,
      generatedTweets,
      modesUsed: filteredModes,
      used: false
    };
    adminData.generatedTweetsHistory.push(tweetData);
    if (adminData.generatedTweetsHistory.length > 100) adminData.generatedTweetsHistory = adminData.generatedTweetsHistory.slice(-100);
    await saveAdminData();
    res.json({ success: true, data: tweetData, lastModified: tweetData.lastModified });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur génération' });
  }
});

// Route regenerate-tweet admin (similaire, copie/adaptée)
app.post('/api/admin/regenerate-tweet', async (req, res) => {
  try {
    const { tweetId, tweetIndex, mode } = req.body;
    if (!tweetId || tweetIndex === undefined || !mode) return res.status(400).json({ success: false, error: 'Params requis' });
    const tweetGroup = adminData.generatedTweetsHistory.find(t => t.id === tweetId);
    if (!tweetGroup || tweetIndex < 0 || tweetIndex >= tweetGroup.generatedTweets.length) return res.status(400).json({ success: false, error: 'Tweet invalide' });

   styleContext = user.userStyle.writings.length > 0
      ? `\n\nUser style (tone: ${user.userStyle.tone}, words: ${Array.from(user.userStyle.vocabulary)
          .slice(-5)
          .join(', ')}):\n${user.userStyle.writings.slice(-3).map(w => `- "${w.text}"`).join('\n')}`
      : '';

    const modePrompts = {
      'tweet-viral': (template) => `Generate a viral-style tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Content based on: "${tweetGroup.userComment}"
Context: "${tweetGroup.originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Start with a bold, surprising, or provocative hook
- Sentences max 12 words
- Short paragraphs (1–2 sentences per line)
- Use simple language, no jargon
- Twist the angle if possible (mango → avocado)
- Encourage engagement implicitly or explicitly
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'critique-constructive': (template) => `Generate a constructive critique tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Content based on: "${tweetGroup.userComment}"
Context: "${tweetGroup.originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Clear and respectful tone, no harshness
- Suggest an improvement, not just criticism
- Sentences max 12 words, short paragraphs
- Can end with a soft question to invite replies
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'thread-twitter': (template) => `Generate the FIRST tweet of a thread using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Content based on: "${tweetGroup.userComment}"
Context: "${tweetGroup.originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Hook must create curiosity or be contrarian
- Sentences max 12 words
- Short paragraphs, easy to scan
- Use more than 200 chars
- Make readers want to click "Show this thread"
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'reformulation-simple': (template) => `Generate a simple reformulation using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Content based on: "${tweetGroup.userComment}"
Context: "${tweetGroup.originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Keep close to the idea but make it lighter
- Sentences max 12 words
- Use simple words, no metaphors
- Must feel clear and easy to read
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'angle-contrarian': (template) => `Generate a contrarian tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Content based on: "${tweetGroup.userComment}"
Context: "${tweetGroup.originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Start with "Hot take" or bold contrarian hook
- Sentences max 12 words
- Short paragraphs, direct and readable
- Twist perspective, avoid obvious angles
- End with a thought-provoking question if possible
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'storytelling': (template) => `Generate a storytelling tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Content based on: "${tweetGroup.userComment}"
Context: "${tweetGroup.originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Tell a relatable story in paragraphs and make it long (betweeen 190 and 280 chars)
- Sentences max 12 words
- Start with curiosity, finish with a lesson
- Must feel human and relatable
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'rage-bait': (template) => `Generate a rage-bait tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Content based on: "${tweetGroup.userComment}"
Context: "${tweetGroup.originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Question must be bold, clear, thought-provoking
- Sentences max 12 words
- Push readers to reflect or react
- Short, direct, easy to scan
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'metaphore-creative': (template) => `Generate a creative metaphor tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Content based on: "${tweetGroup.userComment}"
Context: "${tweetGroup.originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Use a metaphor with a fresh angle (mango → avocado)
- Sentences max 12 words
- Keep it playful, not cliché
- Encourage engagement if natural
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,

      'style-personnel': (template) => `Generate a personal-style tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
Content based on: "${tweetGroup.userComment}"
Style (tone: ${user.userStyle.tone}, words: ${Array.from(user.userStyle.vocabulary).slice(-5).join(', ')})
Context: "${tweetGroup.originalTweet || ''}"
Example: "${tweetTemplates[template].example}"
Rules:
- Match the user's tone and vocabulary
- Sentences max 12 words, short paragraphs
- Must feel authentic, like a friend tweeting
- End with a soft question if natural
Max 280 chars, no hashtags, no emojis, NO QUOTES .${styleContext}`,
    };

    if (!modePrompts[mode]) {
      return res.status(400).json({ success: false, error: 'Mode invalide' });
    }

    const selectedTemplate = selectTemplate(mode);
    const prompt = modePrompts[mode](selectedTemplate);

    const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
      messages: [
        {
          role: 'system',
          content:
            'Tweet expert. Generate original tweets based on user comment using EXACT structure provided. Secondary context: original tweet. Max 280 chars, no hashtags/emojis. Respond only with the tweet',
        },
        { role: 'user', content: prompt },
      ],
      model: 'llama-3.1-8b-instant',
          temperature: 0.7,
          max_tokens: 100,
    });
    const newTweet = response.data.choices[0].message.content.trim();
    tweetGroup.generatedTweets[tweetIndex] = newTweet;
    tweetGroup.modesUsed[tweetIndex] = mode;
    tweetGroup.lastModified = new Date().toISOString();
    await saveAdminData();
    res.json({ success: true, data: { tweet: newTweet, mode, lastModified: tweetGroup.lastModified } });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur régénération' });
  }
});

// Route learn-content admin (ragebait/viral)
app.post('/api/admin/learn-content', async (req, res) => {
  try {
    const { type } = req.body;
    if (!['ragebait', 'viral'].includes(type)) return res.status(400).json({ success: false, error: 'Type invalide' });
    const prompt = type === 'ragebait' ? 'Explain ragebait... In French, max 500 chars.' : 'Explain viral... In French, max 500 chars.';
    const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
      messages: [{ role: 'system', content: 'Social media expert. Concise, in French.' }, { role: 'user', content: prompt }],
      model: 'llama3-8b-8192',
      temperature: 0.7,
      max_tokens: 200
    });
    const content = response.data.choices[0].message.content.trim();
    res.json({ success: true, data: content });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur learn-content' });
  }
});

// Route tweets-history admin
app.get('/api/admin/tweets-history', (req, res) => {
  try {
    const data = adminData.generatedTweetsHistory.slice(-30).reverse().map(group => ({ ...group, generatedTweets: group.generatedTweets || [], modesUsed: group.modesUsed || [] }));
    const etag = generateETag(data); // Réutilise fonction existante
    if (req.get('If-None-Match') === etag) return res.status(304).send();
    res.set('ETag', etag);
    res.json({ success: true, data, lastModified: data[0]?.lastModified || new Date().toISOString() });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur history' });
  }
});

// Route tweet-used admin
app.post('/api/admin/tweet-used', async (req, res) => {
  try {
    const { tweetId } = req.body;
    const tweetGroup = adminData.generatedTweetsHistory.find(t => t.id === tweetId);
    if (!tweetGroup) return res.status(404).json({ success: false, error: 'Tweet non trouvé' });
    tweetGroup.used = true;
    tweetGroup.used_at = new Date().toISOString();
    tweetGroup.lastModified = new Date().toISOString();
    await saveAdminData();
    res.json({ success: true, message: 'Marqué utilisé' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur used' });
  }
});

// Route delete-tweet admin
app.post('/api/admin/delete-tweet', async (req, res) => {
  try {
    const { tweetId, tweetIndex } = req.body;
    const tweetGroup = adminData.generatedTweetsHistory.find(t => t.id === tweetId);
    if (!tweetGroup || tweetIndex < 0 || tweetIndex >= tweetGroup.generatedTweets.length) return res.status(400).json({ success: false, error: 'Invalide' });
    // Cleanup scheduled si existe
    const scheduledIdx = adminData.scheduledTweets.findIndex(t => t.tweetId === tweetId && t.tweetIndex === tweetIndex);
    if (scheduledIdx !== -1) {
      const tweet = adminData.scheduledTweets[scheduledIdx];
      if (tweet.media) {
        for (const media of tweet.media) {
          const filePath = path.join(__dirname, 'Uploads', 'admin', media.filename);
          await fs.unlink(filePath).catch(() => {});
        }
      }
      adminData.scheduledTweets.splice(scheduledIdx, 1);
    }
    tweetGroup.generatedTweets.splice(tweetIndex, 1);
    tweetGroup.modesUsed.splice(tweetIndex, 1);
    tweetGroup.lastModified = new Date().toISOString();
    if (tweetGroup.generatedTweets.length === 0) adminData.generatedTweetsHistory = adminData.generatedTweetsHistory.filter(t => t.id !== tweetId);
    await saveAdminData();
    res.json({ success: true, message: 'Supprimé', data: { remainingCount: tweetGroup.generatedTweets.length } });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur delete' });
  }
});

// Route edit-tweet admin
app.post('/api/admin/edit-tweet', async (req, res) => {
  try {
    const { tweetId, tweetIndex, newText } = req.body;
    const trimmedText = newText.trim();
    if (!trimmedText || trimmedText.length > 280) return res.status(400).json({ success: false, error: 'Texte invalide' });
    const tweetGroup = adminData.generatedTweetsHistory.find(t => t.id === tweetId);
    if (!tweetGroup || tweetIndex < 0 || tweetIndex >= tweetGroup.generatedTweets.length) return res.status(400).json({ success: false, error: 'Invalide' });
    adminData.userStyle.writings.push({ text: trimmedText, timestamp: new Date() });
    const words = trimmedText.toLowerCase().match(/\b\w+\b/g) || [];
    words.forEach(word => adminData.userStyle.vocabulary.add(word));
    adminData.userStyle.tone = detectTone(trimmedText);
    adminData.userStyle.styleProgress += 1;
    adminData.userStyle.lastModified = new Date().toISOString();
    if (adminData.userStyle.writings.length > 50) adminData.userStyle.writings = adminData.userStyle.writings.slice(-50);
    tweetGroup.generatedTweets[tweetIndex] = trimmedText;
    tweetGroup.lastModified = new Date().toISOString();
    const scheduledTweet = adminData.scheduledTweets.find(t => t.tweetId === tweetId && t.tweetIndex === tweetIndex);
    if (scheduledTweet) {
      scheduledTweet.content = trimmedText;
      scheduledTweet.lastModified = new Date().toISOString();
    }
    await saveAdminData();
    res.json({ success: true, message: 'Modifié', data: { tweet: trimmedText, styleProgress: adminData.userStyle.styleProgress } });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur edit' });
  }
});

// Route schedule-tweet admin (avec upload)
app.post('/api/admin/schedule-tweet', upload.array('media', 4), async (req, res) => {
try {
    const { content, datetime, tweetId, tweetIndex, communityId } = req.body;

    // AJOUTEZ CES LOGS ICI :
    console.log('🔍 [SERVER DEBUG] Données reçues:', { content, datetime, tweetId, tweetIndex });
    console.log('🔍 [SERVER DEBUG] generatedTweetsHistory IDs:',
      adminData.generatedTweetsHistory.map(t => ({ id: t.id, tweetsLength: t.generatedTweets?.length }))
    );
    if (!content || !datetime || !tweetId || tweetIndex === undefined) return res.status(400).json({ success: false, error: 'Params requis' });
    const trimmedContent = content.trim();
    if (trimmedContent.length > 280) return res.status(400).json({ success: false, error: 'Trop long' });
    const scheduleDate = new Date(datetime);
    if (isNaN(scheduleDate.getTime()) || scheduleDate <= new Date()) return res.status(400).json({ success: false, error: 'Date invalide' });
   // const tweetGroup = adminData.generatedTweetsHistory.find(t => t.id === tweetId);
    //if (!tweetGroup || tweetIndex < 0 || tweetIndex >= tweetGroup.generatedTweets.length) return res.status(400).json({ success: false, error: 'Groupe invalide' });
    const media = req.files ? req.files.map(file => ({
      id: Date.now() + Math.random(),
      filename: file.filename,
      originalName: file.originalname,
      path: file.path,
      url: `http://localhost:${PORT}/Uploads/admin/${file.filename}`,
      mimetype: file.mimetype,
      type: file.mimetype.startsWith('image/') ? 'image' : 'video'
    })) : [];
    const tweet = {
      id: adminData.tweetIdCounter++,
      content: trimmedContent,
      datetime: scheduleDate.toISOString(),
      createdAt: new Date().toISOString(),
      lastModified: new Date().toISOString(),
      media,
      status: 'scheduled',
      tweetId,
      tweetIndex: parseInt(tweetIndex),
      communityId: communityId || null
    };
    // Remove old si existe
    const existingIdx = adminData.scheduledTweets.findIndex(t => t.tweetId === tweetId && t.tweetIndex === tweetIndex);
    if (existingIdx !== -1) {
      const oldTweet = adminData.scheduledTweets[existingIdx];
      adminData.scheduledTweets.splice(existingIdx, 1);
      if (oldTweet.media) {
        for (const m of oldTweet.media) {
          const fp = path.join(__dirname, 'Uploads', 'admin', m.filename);
          await fs.unlink(fp).catch(() => {});
        }
      }
    }
    adminData.scheduledTweets.push(tweet);
    await saveAdminData();
    res.json({ success: true, tweet: { ...tweet, media: media.map(m => ({ id: m.id, filename: m.filename, url: m.url, mimetype: m.mimetype, type: m.type })) } });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur schedule' });
  }
});
// Fonction pour publier un tweet avec médias
async function publishTweetToTwitter(tweet) {
  try {
    console.log(`📤 Publication du tweet: "${tweet.content.substring(0, 50)}..."`);

    let mediaIds = [];

    // Upload des médias s'il y en a
    if (tweet.media && tweet.media.length > 0) {
      console.log(`📎 Upload de ${tweet.media.length} médias...`);

      for (const media of tweet.media) {
        try {
          const mediaPath = path.join(__dirname, 'Uploads', 'admin', media.filename);
          const mediaData = await fs.readFile(mediaPath);

          console.log(`📸 Upload média: ${media.filename}`);
          const mediaUpload = await adminTwitterClient.v1.uploadMedia(mediaData, {
            mimeType: media.mimetype
          });

          mediaIds.push(mediaUpload);
          console.log(`✅ Média uploadé: ${mediaUpload}`);

        } catch (mediaError) {
          console.error(`❌ Erreur upload média ${media.filename}:`, mediaError.message);
          throw new Error(`Erreur upload média: ${media.filename}`);
        }
      }
    }

    // Création du tweet
    const tweetData = {
      text: tweet.content
    };

    // Ajout des médias si il y en a
    if (mediaIds.length > 0) {
      tweetData.media = { media_ids: mediaIds };
    }

    // Publication
    const result = await adminTwitterClient.v2.tweet(tweetData);
    console.log(`✅ Tweet publié avec succès: ${result.data.id}`);

    return result.data;

  } catch (error) {
    console.error('❌ Erreur publication Twitter:', error.message);
    throw new Error(`Publication Twitter échouée: ${error.message}`);
  }
}
// Fonction de vérification et publication des tweets programmés
async function checkAndPublishScheduledTweets() {
  try {
    const now = new Date();
    console.log(`⏰ Vérification tweets programmés à ${now.toLocaleString()}`);

    if (!adminData.scheduledTweets || adminData.scheduledTweets.length === 0) {
      console.log('ℹ️ Aucun tweet programmé');
      return;
    }

    const tweetsToPublish = adminData.scheduledTweets.filter(
      tweet => tweet.status === 'scheduled' && new Date(tweet.datetime) <= now
    );

    console.log(`📊 ${tweetsToPublish.length} tweets à publier sur ${adminData.scheduledTweets.length} total`);

    for (const tweet of tweetsToPublish) {
      console.log(`🚀 Début publication: "${tweet.content.substring(0, 50)}..."`);

      try {
        // Marquer comme "en cours de publication"
        tweet.status = 'publishing';
        await saveAdminData();

        // Publier sur Twitter
        const result = await publishTweetToTwitter(tweet);

        // Marquer comme publié
        tweet.status = 'published';
        tweet.publishedAt = now.toISOString();
        tweet.twitterId = result.id;
        tweet.twitterUrl = `https://twitter.com/user/status/${result.id}`;

        console.log(`✅ Tweet ${tweet.id} publié avec succès: ${result.id}`);

      } catch (error) {
        console.error(`❌ Erreur publication tweet ${tweet.id}:`, error.message);
        tweet.status = 'failed';
        tweet.error = error.message;
        tweet.failedAt = now.toISOString();
      }
    }

    // Sauvegarder les changements si des tweets ont été traités
    if (tweetsToPublish.length > 0) {
      await saveAdminData();
      console.log(`💾 Statuts mis à jour pour ${tweetsToPublish.length} tweets`);
    }

  } catch (error) {
    console.error('❌ Erreur globale vérification tweets:', error.message);
  }
}
// Route de debug pour voir l'état des tweets
app.get('/api/admin/debug-tweets', async (req, res) => {
  try {
    const now = new Date();
    const tweetsInfo = (adminData.scheduledTweets || []).map(tweet => ({
      id: tweet.id,
      content: tweet.content.substring(0, 50) + '...',
      status: tweet.status,
      scheduledFor: tweet.datetime,
      shouldBePublished: new Date(tweet.datetime) <= now,
      timeUntilPublish: new Date(tweet.datetime) - now,
      hasMedia: tweet.media ? tweet.media.length : 0,
      twitterId: tweet.twitterId || null,
      error: tweet.error || null
    }));

    res.json({
      success: true,
      currentTime: now.toISOString(),
      totalTweets: adminData.scheduledTweets ? adminData.scheduledTweets.length : 0,
      scheduled: tweetsInfo.filter(t => t.status === 'scheduled').length,
      published: tweetsInfo.filter(t => t.status === 'published').length,
      failed: tweetsInfo.filter(t => t.status === 'failed').length,
      tweets: tweetsInfo
    });
  } catch (error) {
    console.error('❌ Erreur debug tweets:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Route get tweets admin
app.get('/api/admin/tweets', async (req, res) => {
  try {
    const data = adminData.scheduledTweets.map(tweet => ({
      ...tweet,
      media: (tweet.media || []).map(m => ({ ...m, url: m.url || `http://localhost:${PORT}/Uploads/admin/${m.filename}` }))
    }));
    const etag = generateETag(data);
    if (req.get('If-None-Match') === etag) return res.status(304).send();
    res.set('ETag', etag);
    res.json(data);
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur tweets' });
  }
});

// Route delete tweet admin
app.delete('/api/admin/tweets/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const idx = adminData.scheduledTweets.findIndex(t => t.id === parseInt(id));
    if (idx === -1) return res.status(404).json({ success: false, error: 'Non trouvé' });
    const tweet = adminData.scheduledTweets[idx];
    if (tweet.media) {
      for (const m of tweet.media) {
        const fp = path.join(__dirname, 'Uploads', 'admin', m.filename);
        await fs.unlink(fp).catch(() => {});
      }
    }
    adminData.scheduledTweets.splice(idx, 1);
    await saveAdminData();
    res.json({ success: true, message: 'Supprimé' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur delete' });
  }
});

// Route publish tweet admin
app.post('/api/admin/tweets/:id/publish', async (req, res) => {
  try {
    const { id } = req.params;
    const { content } = req.body;
    const tweet = adminData.scheduledTweets.find(t => t.id === parseInt(id));
    if (!tweet || tweet.status !== 'scheduled') return res.status(400).json({ success: false, error: 'Invalide' });
    const result = await publishAdminTweetToTwitter(tweet, content || tweet.content);
    tweet.status = 'published';
    tweet.publishedAt = new Date().toISOString();
    tweet.twitterId = result.data.id;
    tweet.lastModified = new Date().toISOString();
    await saveAdminData();
    res.json({ success: true, message: 'Publié', result: result.data });
  } catch (error) {
    tweet.status = 'failed';
    tweet.error = error.message;
    tweet.lastModified = new Date().toISOString();
    await saveAdminData();
    res.status(500).json({ success: false, error: 'Erreur publish' });
  }
});
//admin route edn
// Démarrer le serveur
async function startServer() {
  // Init admin
await testAdminTwitterConnection();
await loadAdminData();
startAdminScheduleChecker();
console.log('✅ Système admin intégré (Twitter hardcodé + Firebase)');
  try {
    console.log('🔄 Initialisation du serveur avec système de templates...');
    console.log(`📋 Templates disponibles: ${Object.keys(tweetTemplates).join(', ')}`);
    startScheduleChecker();
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`   - GET  /admin (page admin)`);
console.log(`   - GET  /api/admin/user-communities`);
console.log(`   - POST /api/admin/update-tweet-community`);
console.log(`   - POST /api/admin/learn-style`);
console.log(`   - POST /api/admin/generate-tweets`);
console.log(`   - POST /api/admin/regenerate-tweet`);
console.log(`   - POST /api/admin/learn-content`);
console.log(`   - GET  /api/admin/tweets-history`);
console.log(`   - POST /api/admin/tweet-used`);
console.log(`   - POST /api/admin/delete-tweet`);
console.log(`   - POST /api/admin/edit-tweet`);
console.log(`   - POST /api/admin/schedule-tweet`);
console.log(`   - GET  /api/admin/tweets`);
console.log(`   - DELETE /api/admin/tweets/:id`);
console.log(`   - POST /api/admin/tweets/:id/publish`);
      console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`);
      console.log(`📊 Interface web: http://localhost:${PORT}`);
      console.log(`🔄 API endpoints disponibles:`);
      console.log(`   - GET  /api/extension-login (public)`);
      console.log(`   - POST /api/refresh-token (public)`);
      console.log(`   - POST /api/login`);
      console.log(`   - POST /api/logout`);
      console.log(`   - GET  /api/auth-status`);
      console.log(`   - GET  /api/twitter-auth`);
      console.log(`   - GET  /api/twitter-callback`);
      console.log(`   - POST /api/twitter-refresh`);
      console.log(`   - POST /api/twitter-logout`);
      console.log(`   - GET  /api/user`);
      console.log(`   - POST /api/learn-style`);
      console.log(`   - POST /api/generate-tweets (avec templates)`);
      console.log(`   - POST /api/regenerate-tweet (avec templates)`);
      console.log(`   - POST /api/learn-content`);
      console.log(`   - GET  /api/tweets-history`);
      console.log(`   - POST /api/tweet-used`);
      console.log(`   - POST /api/edit-tweet`);
      console.log(`   - POST /api/schedule-tweet`);
      console.log(`   - GET  /api/tweets`);
      console.log(`   - DELETE /api/tweets/:id`);
      console.log(`   - POST /api/tweets/:id/publish`);
      console.log(`   - GET  /api/user-stats`);
      console.log(`   - GET  /api/subscription-status`);
      console.log(`   - POST /api/create-checkout`);
      console.log(`   - POST /webhook/polar`);
      console.log(`   - GET  /health`);
      console.log(`✅ Serveur prêt avec système de templates avancé! 🎯`);
      console.log(`🔧 Templates structurels:`);
      Object.entries(tweetTemplates).forEach(([key, template]) => {
        console.log(`   - ${key}: "${template.structure}"`);
      });
    });
  } catch (error) {
    console.error('❌ Erreur lors du démarrage du serveur:', error.message, error.stack);
    process.exit(1);
  }
}
// Démarrer la vérification automatique des tweets programmés
console.log('🕐 Démarrage du système de vérification des tweets programmés...');
setInterval(checkAndPublishScheduledTweets, 30000); // Vérifier toutes les 30 secondes

// Vérification immédiate au démarrage
setTimeout(() => {
  console.log('🚀 Vérification initiale des tweets programmés...');
  checkAndPublishScheduledTweets();
}, 5000); // Attendre 5 secondes après le démarrage

// Appeler la fonction pour démarrer le serveur
startServer();

