/*
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const { TwitterApi } = require('twitter-api-v2');
const fs = require('fs').promises;
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'If-None-Match'],
  credentials: true
}));
app.use(express.json());

// Configure Multer for file uploads
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadPath = path.join(__dirname, 'uploads');
    await fs.mkdir(uploadPath, { recursive: true });
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
    cb(null, `${uniqueSuffix}-${file.originalname}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'video/mp4'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Type de fichier non supporté'), false);
    }
  }
});

// Serve static files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// API Keys
const GROQ_API_KEY = process.env.GROQ_API_KEY || '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';
if (!process.env.TWITTER_APP_KEY || !process.env.TWITTER_APP_SECRET || !process.env.TWITTER_ACCESS_TOKEN || !process.env.TWITTER_ACCESS_SECRET) {
  console.error('❌ Erreur: Variables d\'environnement Twitter manquantes. Vérifiez votre fichier .env.');
  process.exit(1);
}

// Twitter API Client
const twitterClient = new TwitterApi({
  appKey: process.env.TWITTER_APP_KEY,
  appSecret: process.env.TWITTER_APP_SECRET,
  accessToken: process.env.TWITTER_ACCESS_TOKEN,
  accessSecret: process.env.TWITTER_ACCESS_SECRET,
});

// Test Twitter connection on startup
async function testTwitterConnection() {
  try {
    const me = await twitterClient.v2.me();
    console.log('✅ Connexion Twitter réussie:', me.data.username);
    return me.data.id;
  } catch (error) {
    console.error('❌ Échec de la connexion Twitter:', error.message);
    process.exit(1);
  }
}

// Storage
let userStyle = {
  writings: [],
  patterns: [],
  vocabulary: new Set(),
  tone: 'neutral',
  styleProgress: 0,
  lastModified: new Date().toISOString()
};
let generatedTweetsHistory = [];
let scheduledTweets = [];
let dataLock = false;
let userId = null;
let tweetIdCounter = 1;

// File paths for persistence
const USER_STYLE_FILE = path.join(__dirname, 'userStyle.json');
const TWEETS_HISTORY_FILE = path.join(__dirname, 'tweetsHistory.json');
const SCHEDULED_TWEETS_FILE = path.join(__dirname, 'scheduledTweets.json');

// Load data from files
async function loadPersistedData() {
  try {
    const userStyleData = await fs.readFile(USER_STYLE_FILE, 'utf8');
    userStyle = JSON.parse(userStyleData, (key, value) => {
      if (key === 'vocabulary') return new Set(value);
      return value;
    });
    console.log('✅ Loaded userStyle from file');
  } catch (error) {
    console.log('ℹ️ No userStyle file found, using default');
  }

  try {
    const tweetsHistoryData = await fs.readFile(TWEETS_HISTORY_FILE, 'utf8');
    generatedTweetsHistory = JSON.parse(tweetsHistoryData);
    console.log('✅ Loaded tweetsHistory from file');
  } catch (error) {
    console.log('ℹ️ No tweetsHistory file found, using default');
  }

  try {
    const scheduledTweetsData = await fs.readFile(SCHEDULED_TWEETS_FILE, 'utf8');
    scheduledTweets = JSON.parse(scheduledTweetsData);
    console.log('✅ Loaded scheduledTweets from file');
  } catch (error) {
    console.log('ℹ️ No scheduledTweets file found, using default');
  }
}

// Save data to files
async function savePersistedData() {
  if (dataLock) {
    console.log('🔒 Data save skipped due to lock');
    return;
  }
  dataLock = true;
  try {
    await fs.writeFile(USER_STYLE_FILE, JSON.stringify(userStyle, (key, value) => {
      if (value instanceof Set) return Array.from(value);
      return value;
    }, 2));
    await fs.writeFile(TWEETS_HISTORY_FILE, JSON.stringify(generatedTweetsHistory, null, 2));
    await fs.writeFile(SCHEDULED_TWEETS_FILE, JSON.stringify(scheduledTweets, null, 2));
    console.log('✅ Data saved to files');
  } catch (error) {
    console.error('❌ Error saving data to files:', error.message);
  } finally {
    dataLock = false;
  }
}

// Generate ETag
function generateETag(data) {
  return crypto.createHash('md5').update(JSON.stringify(data)).digest('hex');
}

// Tone detection
function detectTone(text) {
  const positiveWords = ['great', 'awesome', 'fantastic', 'love', 'happy', 'good'];
  const negativeWords = ['bad', 'terrible', 'hate', 'sad', 'problem', 'fail'];
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

// Axios instance for Groq API
const axiosInstance = axios.create({
  timeout: 15000,
  headers: {
    'Authorization': `Bearer ${GROQ_API_KEY}`,
    'Content-Type': 'application/json'
  }
});

// Utility functions
function escapeHtml(text) {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/\n/g, ' ')
    .replace(/\r/g, ' ')
    .replace(/\t/g, ' ');
}

// Route to fetch user's X Communities
app.get('/api/user-communities', async (req, res) => {
  try {
    console.log('🔍 Fetching communities for user:', userId);
    // Placeholder: X API v2 communities endpoint not supported in twitter-api-v2
    // Replace with actual endpoint when available
    let communities = [];
    try {
      const response = await twitterClient.v2.get('communities', { user_id: userId });
      communities = response.data.map(community => ({
        id: community.id,
        name: community.name
      }));
    } catch (apiError) {
      console.warn('⚠️ Communities endpoint not supported or failed:', apiError.message);
      communities = []; // Fallback to empty array
    }
    res.json({
      success: true,
      data: communities
    });
  } catch (error) {
    console.error('❌ Erreur récupération communautés:', error.message);
    res.status(500).json({
      success: false,
      error: 'Erreur récupération communautés',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to update community for a scheduled tweet
app.post('/api/update-tweet-community', async (req, res) => {
  try {
    const { tweetId, tweetIndex, communityId } = req.body;

    if (!tweetId || tweetIndex === undefined) {
      return res.status(400).json({ success: false, error: 'tweetId et tweetIndex requis' });
    }

    const scheduledTweet = scheduledTweets.find(t => t.tweetId === tweetId && t.tweetIndex === parseInt(tweetIndex));
    if (!scheduledTweet) {
      return res.status(404).json({ success: false, error: 'Tweet programmé non trouvé' });
    }

    scheduledTweet.communityId = communityId || null;
    scheduledTweet.lastModified = new Date().toISOString();
    await savePersistedData();

    res.json({
      success: true,
      message: 'Communauté mise à jour',
      data: { lastModified: scheduledTweet.lastModified }
    });
  } catch (error) {
    console.error('❌ Erreur mise à jour communauté:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur mise à jour communauté',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to save user style
app.post('/api/learn-style', async (req, res) => {
  try {
    const { styleText } = req.body;

    if (!styleText || styleText.trim() === '') {
      return res.status(400).json({ success: false, error: 'styleText requis' });
    }

    const trimmedText = styleText.trim();
    userStyle.writings.push({ text: trimmedText, timestamp: new Date() });
    const words = trimmedText.toLowerCase().match(/\b\w+\b/g) || [];
    words.forEach(word => userStyle.vocabulary.add(word));
    userStyle.tone = detectTone(trimmedText);
    userStyle.styleProgress += 1;
    userStyle.lastModified = new Date().toISOString();

    if (userStyle.writings.length > 50) {
      userStyle.writings = userStyle.writings.slice(-50);
    }

    await savePersistedData();
    res.json({
      success: true,
      message: 'Style appris avec succès',
      data: {
        styleProgress: userStyle.styleProgress,
        lastModified: userStyle.lastModified
      }
    });
  } catch (error) {
    console.error('❌ Erreur apprentissage style:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur apprentissage style',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to generate tweets
app.post('/api/generate-tweets', async (req, res) => {
  try {
    const { userComment, originalTweet, context, modeFilter } = req.body;

    if (!userComment || userComment.trim() === '') {
      return res.status(400).json({ success: false, error: 'userComment requis' });
    }

    console.log(`🔍 Génération tweets pour: ${userComment.substring(0, 50)}...`);

    const styleContext = userStyle.writings.length > 0 ?
      `\n\nUser style (tone: ${userStyle.tone}, words: ${Array.from(userStyle.vocabulary).slice(-5).join(', ')}):\n${userStyle.writings.slice(-3).map(w => `- "${w.text}"`).join('\n')}` : '';

    const modes = [
      'tweet-viral', 'critique-constructive', 'thread-twitter', 'reformulation-simple',
      'angle-contrarian', 'storytelling', 'question-provocante', 'metaphore-creative', 'style-personnel'
    ];

    const modePrompts = {
      'tweet-viral': `Generate a viral tweet based on: "${userComment}". Secondary context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'critique-constructive': `Generate a constructive critique tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'thread-twitter': `Generate the first tweet of a thread based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'reformulation-simple': `Generate a simple reformulation tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'angle-contrarian': `Generate a contrarian angle tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'storytelling': `Generate a storytelling tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'question-provocante': `Generate a provocative question tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'metaphore-creative': `Generate a creative metaphor tweet for: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'style-personnel': `Generate a personal style tweet based on: "${userComment}". Style (tone: ${userStyle.tone}, words: ${Array.from(userStyle.vocabulary).slice(-5).join(', ')}). Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`
    };

    const filteredModes = modeFilter ? [modeFilter] : modes;
    const prompts = filteredModes.map(mode => modePrompts[mode]);

    userStyle.writings.push({ text: userComment.trim(), timestamp: new Date() });
    userStyle.tone = detectTone(userComment.trim());
    userStyle.styleProgress += 1;
    userStyle.lastModified = new Date().toISOString();

    if (userStyle.writings.length > 50) {
      userStyle.writings = userStyle.writings.slice(-50);
    }

    const promises = prompts.map(async (prompt, index) => {
      try {
        const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
          messages: [
            {
              role: 'system',
              content: 'Tweet expert. Generate original tweets based on user comment. Secondary context: original tweet. Max 280 chars, no hashtags/emojis. Respond only with the tweet.'
            },
            { role: 'user', content: prompt }
          ],
          model: 'llama3-8b-8192',
          temperature: 0.7,
          max_tokens: 100
        });

        return {
          success: true,
          tweet: response.data.choices[0].message.content.trim(),
          mode: filteredModes[index]
        };
      } catch (error) {
        console.error(`❌ Erreur mode ${filteredModes[index]}:`, error.message);
        return {
          success: false,
          tweet: `Error: Tweet generation failed for ${filteredModes[index]}`,
          mode: filteredModes[index],
          error: error.message
        };
      }
    });

    const results = await Promise.all(promises);
    const generatedTweets = results.map(r => r.tweet);
    const usedModes = results.map(r => r.mode);

    const tweetData = {
      id: Date.now().toString(),
      timestamp: new Date().toISOString(),
      lastModified: new Date().toISOString(),
      originalTweet: originalTweet || null,
      userComment: userComment.trim(),
      context: context || null,
      generatedTweets,
      modesUsed: usedModes,
      used: false
    };

    generatedTweetsHistory.push(tweetData);
    if (generatedTweetsHistory.length > 100) {
      generatedTweetsHistory = generatedTweetsHistory.slice(-100);
    }

    await savePersistedData();

    console.log('✅ Tweets générés:', generatedTweets.length);
    res.json({
      success: true,
      data: tweetData,
      lastModified: tweetData.lastModified
    });
  } catch (error) {
    console.error('❌ Erreur génération tweets:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur génération tweets',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to regenerate a tweet
app.post('/api/regenerate-tweet', async (req, res) => {
  try {
    const { tweetId, tweetIndex, mode } = req.body;

    if (!tweetId || tweetIndex === undefined || !mode) {
      return res.status(400).json({ success: false, error: 'tweetId, tweetIndex et mode requis' });
    }

    const tweetGroup = generatedTweetsHistory.find(t => t.id === tweetId);
    if (!tweetGroup) {
      return res.status(404).json({ success: false, error: 'Groupe tweets non trouvé' });
    }

    if (tweetIndex < 0 || tweetIndex >= tweetGroup.generatedTweets.length) {
      return res.status(400).json({ success: false, error: 'Index tweet invalide' });
    }

    const styleContext = userStyle.writings.length > 0 ?
      `\n\nUser style (tone: ${userStyle.tone}, words: ${Array.from(userStyle.vocabulary).slice(-5).join(', ')}):\n${userStyle.writings.slice(-3).map(w => `- "${w.text}"`).join('\n')}` : '';

    const modePrompts = {
      'tweet-viral': `Generate a viral tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'critique-constructive': `Generate a constructive critique tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'thread-twitter': `Generate the first tweet of a thread based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'reformulation-simple': `Generate a simple reformulation tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'angle-contrarian': `Generate a contrarian angle tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'storytelling': `Generate a storytelling tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'question-provocante': `Generate a provocative question tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'metaphore-creative': `Generate a creative metaphor tweet for: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'style-personnel': `Generate a personal style tweet based on: "${tweetGroup.userComment}". Style (tone: ${userStyle.tone}, words: ${Array.from(userStyle.vocabulary).slice(-5).join(', ')}). Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`
    };

    const prompt = modePrompts[mode];
    if (!prompt) {
      return res.status(400).json({ success: false, error: 'Mode invalide' });
    }

    const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
      messages: [
        {
          role: 'system',
          content: 'Tweet expert. Generate original tweets based on user comment. Secondary context: original tweet. Max 280 chars, no hashtags/emojis. Respond only with the tweet.'
        },
        { role: 'user', content: prompt }
      ],
      model: 'llama3-8b-8192',
      temperature: 0.7,
      max_tokens: 100
    });

    const newTweet = response.data.choices[0].message.content.trim();
    tweetGroup.generatedTweets[tweetIndex] = newTweet;
    tweetGroup.modesUsed[tweetIndex] = mode;
    tweetGroup.lastModified = new Date().toISOString();

    await savePersistedData();

    res.json({
      success: true,
      data: { tweet: newTweet, mode, lastModified: tweetGroup.lastModified }
    });
  } catch (error) {
    console.error('❌ Erreur régénération tweet:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur régénération tweet',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to learn about ragebait or viral content
app.post('/api/learn-content', async (req, res) => {
  try {
    const { type } = req.body;

    if (!['ragebait', 'viral'].includes(type)) {
      return res.status(400).json({ success: false, error: 'Type contenu invalide' });
    }

    const prompt = type === 'ragebait' ?
      'Explain ragebait, how it works on social media, 3 example ragebait tweets. In French, max 500 chars.' :
      'Explain viral content on social media, 3 example viral tweets. In French, max 500 chars.';

    const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
      messages: [
        { role: 'system', content: 'Social media expert. Concise explanation, examples in French, respect char limit.' },
        { role: 'user', content: prompt }
      ],
      model: 'llama3-8b-8192',
      temperature: 0.7,
      max_tokens: 200
    });

    const content = response.data.choices[0].message.content.trim();
    res.json({ success: true, data: content });
  } catch (error) {
    console.error('❌ Erreur info contenu:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur récupération info contenu',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to get tweets history
app.get('/api/tweets-history', (req, res) => {
  try {
    const data = generatedTweetsHistory.slice(-30).reverse().map(group => ({
      ...group,
      generatedTweets: group.generatedTweets || [],
      modesUsed: group.modesUsed || []
    }));
    const etag = generateETag(data);
    if (req.get('If-None-Match') === etag) {
      return res.status(304).send();
    }
    res.set('ETag', etag);
    res.json({
      success: true,
      data,
      lastModified: data[0]?.lastModified || new Date().toISOString()
    });
  } catch (error) {
    console.error('❌ Erreur historique tweets:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur récupération historique',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to mark tweet as used
app.post('/api/tweet-used', async (req, res) => {
  try {
    const { tweetId } = req.body;

    if (!tweetId) {
      return res.status(400).json({ success: false, error: 'tweetId requis' });
    }

    const tweetIndex = generatedTweetsHistory.findIndex(t => t.id === tweetId);
    if (tweetIndex === -1) {
      return res.status(404).json({ success: false, error: 'Tweet non trouvé' });
    }

    generatedTweetsHistory[tweetIndex].used = true;
    generatedTweetsHistory[tweetIndex].used_at = new Date().toISOString();
    generatedTweetsHistory[tweetIndex].lastModified = new Date().toISOString();
    await savePersistedData();

    res.json({
      success: true,
      message: 'Tweet marqué utilisé',
      data: { lastModified: generatedTweetsHistory[tweetIndex].lastModified }
    });
  } catch (error) {
    console.error('❌ Erreur mise à jour tweet:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur mise à jour tweet',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to delete a tweet
app.post('/api/delete-tweet', async (req, res) => {
  try {
    const { tweetId, tweetIndex } = req.body;

    if (!tweetId || tweetIndex === undefined) {
      return res.status(400).json({ success: false, error: 'tweetId et tweetIndex requis' });
    }

    const tweetGroup = generatedTweetsHistory.find(t => t.id === tweetId);
    if (!tweetGroup) {
      return res.status(404).json({ success: false, error: 'Groupe tweets non trouvé' });
    }

    if (tweetIndex < 0 || tweetIndex >= tweetGroup.generatedTweets.length) {
      return res.status(400).json({ success: false, error: 'Index tweet invalide' });
    }

    tweetGroup.generatedTweets.splice(tweetIndex, 1);
    tweetGroup.modesUsed.splice(tweetIndex, 1);
    tweetGroup.lastModified = new Date().toISOString();

    const scheduledTweetIndex = scheduledTweets.findIndex(t => t.tweetId === tweetId && t.tweetIndex === parseInt(tweetIndex));
    if (scheduledTweetIndex !== -1) {
      const tweet = scheduledTweets[scheduledTweetIndex];
      if (tweet.media && tweet.media.length > 0) {
        for (const media of tweet.media) {
          try {
            const filePath = path.join(__dirname, 'uploads', media.filename);
            if (await fs.access(filePath).then(() => true).catch(() => false)) {
              await fs.unlink(filePath);
              console.log(`✅ Fichier média supprimé: ${media.filename}`);
            }
          } catch (err) {
            console.error(`❌ Erreur suppression fichier ${media.filename}:`, err.message);
          }
        }
      }
      scheduledTweets.splice(scheduledTweetIndex, 1);
    }

    await savePersistedData();

    res.json({
      success: true,
      message: 'Tweet supprimé',
      data: {
        remainingCount: tweetGroup.generatedTweets.length,
        lastModified: tweetGroup.lastModified
      }
    });
  } catch (error) {
    console.error('❌ Erreur suppression tweet:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur suppression tweet',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to edit a tweet
app.post('/api/edit-tweet', async (req, res) => {
  try {
    const { tweetId, tweetIndex, newText } = req.body;

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

    const tweetGroup = generatedTweetsHistory.find(t => t.id === tweetId);
    if (!tweetGroup) {
      return res.status(404).json({ success: false, error: 'Groupe tweets non trouvé' });
    }

    if (tweetIndex < 0 || tweetIndex >= tweetGroup.generatedTweets.length) {
      return res.status(400).json({ success: false, error: 'Index tweet invalide' });
    }

    console.log(`📝 Modification tweet ${tweetId}[${tweetIndex}]: "${tweetGroup.generatedTweets[tweetIndex]}" → "${trimmedText}"`);

    userStyle.writings.push({ text: trimmedText, timestamp: new Date() });
    const words = trimmedText.toLowerCase().match(/\b\w+\b/g) || [];
    words.forEach(word => userStyle.vocabulary.add(word));
    userStyle.tone = detectTone(trimmedText);
    userStyle.styleProgress += 1;
    userStyle.lastModified = new Date().toISOString();

    if (userStyle.writings.length > 50) {
      userStyle.writings = userStyle.writings.slice(-50);
    }

    tweetGroup.generatedTweets[tweetIndex] = trimmedText;
    tweetGroup.lastModified = new Date().toISOString();

    const scheduledTweet = scheduledTweets.find(t => t.tweetId === tweetId && t.tweetIndex === parseInt(tweetIndex));
    if (scheduledTweet) {
      scheduledTweet.content = trimmedText;
      scheduledTweet.lastModified = new Date().toISOString();
    }

    await savePersistedData();

    res.json({
      success: true,
      message: 'Tweet modifié',
      data: {
        tweet: trimmedText,
        index: tweetIndex,
        lastModified: tweetGroup.lastModified,
        styleProgress: userStyle.styleProgress
      }
    });
  } catch (error) {
    console.error('❌ Erreur modification tweet:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur modification tweet',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to schedule a tweet
app.post('/api/schedule-tweet', upload.array('media', 4), async (req, res) => {
  try {
    const { content, datetime, tweetId, tweetIndex, communityId } = req.body;

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

    const tweetGroup = generatedTweetsHistory.find(t => t.id === tweetId);
    if (!tweetGroup) {
      return res.status(404).json({ success: false, error: 'Groupe tweets non trouvé' });
    }

    if (parseInt(tweetIndex) < 0 || parseInt(tweetIndex) >= tweetGroup.generatedTweets.length) {
      return res.status(400).json({ success: false, error: 'Index tweet invalide' });
    }

    const media = req.files ? req.files.map(file => ({
      id: Date.now() + Math.random(),
      filename: file.filename,
      originalName: file.originalname,
      path: file.path,
      url: `http://localhost:${PORT}/uploads/${file.filename}`,
      mimetype: file.mimetype,
      type: file.mimetype.startsWith('image/') ? 'image' : 'video'
    })) : [];

    const tweet = {
      id: tweetIdCounter++,
      content: trimmedContent,
      datetime: scheduleDate.toISOString(),
      createdAt: now.toISOString(),
      lastModified: now.toISOString(),
      media,
      status: 'scheduled',
      tweetId,
      tweetIndex: parseInt(tweetIndex),
      communityId: communityId || null
    };

    // Remove old tweet and its media
    const existingIndex = scheduledTweets.findIndex(t => t.tweetId === tweetId && t.tweetIndex === parseInt(tweetIndex));
    if (existingIndex !== -1) {
      const oldTweet = scheduledTweets[existingIndex];
      scheduledTweets.splice(existingIndex, 1);
      if (oldTweet.media && oldTweet.media.length > 0) {
        for (const media of oldTweet.media) {
          try {
            const filePath = path.join(__dirname, 'uploads', media.filename);
            if (await fs.access(filePath).then(() => true).catch(() => false)) {
              await fs.unlink(filePath);
              console.log(`✅ Fichier média supprimé: ${media.filename}`);
            }
          } catch (err) {
            console.error(`❌ Erreur suppression fichier ${media.filename}:`, err.message);
          }
        }
      }
    }

    scheduledTweets.push(tweet);
    await savePersistedData();

    console.log('✅ Tweet programmé:', {
      id: tweet.id,
      content: trimmedContent.substring(0, 50) + '...',
      datetime: scheduleDate.toLocaleString(),
      mediaCount: media.length,
      communityId: tweet.communityId
    });

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
          type: m.type
        }))
      }
    });
  } catch (error) {
    console.error('❌ Erreur programmation tweet:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur programmation tweet',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to get all scheduled tweets
app.get('/api/tweets', async (req, res) => {
  try {
    const data = scheduledTweets.map(tweet => ({
      ...tweet,
      media: (tweet.media || []).map(media => ({
        id: media.id,
        filename: media.filename,
        originalName: media.originalName,
        url: media.url || `http://localhost:${PORT}/uploads/${media.filename}`,
        mimetype: media.mimetype || 'application/octet-stream',
        type: media.type || (media.mimetype && media.mimetype.startsWith('image/') ? 'image' : 'video')
      }))
    }));
    const etag = generateETag(data);
    if (req.get('If-None-Match') === etag) {
      return res.status(304).send();
    }
    res.set('ETag', etag);
    res.json(data);
  } catch (error) {
    console.error('❌ Erreur récupération tweets programmés:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur récupération tweets programmés',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to delete a scheduled tweet
app.delete('/api/tweets/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const tweetIndex = scheduledTweets.findIndex(t => t.id === parseInt(id));

    if (tweetIndex === -1) {
      return res.status(404).json({ success: false, error: 'Tweet programmé non trouvé' });
    }

    const tweet = scheduledTweets[tweetIndex];
    if (tweet.media && tweet.media.length > 0) {
      for (const media of tweet.media) {
        try {
          const filePath = path.join(__dirname, 'Uploads', media.filename);
          if (await fs.access(filePath).then(() => true).catch(() => false)) {
            await fs.unlink(filePath);
            console.log(`✅ Fichier média supprimé: ${media.filename}`);
          }
        } catch (err) {
          console.error(`❌ Erreur suppression fichier ${media.filename}:`, err.message);
        }
      }
    }

    scheduledTweets.splice(tweetIndex, 1);
    await savePersistedData();

    console.log('🗑️ Tweet supprimé:', id);
    res.json({
      success: true,
      message: 'Tweet programmé supprimé'
    });
  } catch (error) {
    console.error('❌ Erreur suppression tweet programmé:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur suppression tweet programmé',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to publish a scheduled tweet
app.post('/api/tweets/:id/publish', async (req, res) => {
  try {
    const { id } = req.params;
    const { content } = req.body;

    const tweet = scheduledTweets.find(t => t.id === parseInt(id));
    if (!tweet) {
      return res.status(404).json({ success: false, error: 'Tweet programmé non trouvé' });
    }

    if (tweet.status !== 'scheduled') {
      return res.status(400).json({ success: false, error: 'Tweet non programmé' });
    }

    const result = await publishTweetToTwitter(tweet, content || tweet.content);

    tweet.status = 'published';
    tweet.publishedAt = new Date().toISOString();
    tweet.twitterId = result.data.id;
    tweet.lastModified = new Date().toISOString();
    await savePersistedData();

    res.json({
      success: true,
      message: 'Tweet publié',
      result: result.data
    });
  } catch (error) {
    console.error('❌ Erreur publication tweet:', error);
    res.status(error.code === 403 ? 403 : 500).json({
      success: false,
      error: 'Erreur publication tweet',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Function to publish tweet to Twitter
async function publishTweetToTwitter(tweet, content) {
  try {
    console.log('🚀 Publication du tweet:', tweet.id);

    let mediaIds = [];
    if (tweet.media && tweet.media.length > 0) {
      console.log('📎 Upload des médias...');
      for (const media of tweet.media) {
        const filePath = path.join(__dirname, 'Uploads', media.filename);
        if (!await fs.access(filePath).then(() => true).catch(() => false)) {
          throw new Error(`Fichier média introuvable: ${media.filename}`);
        }
        const mediaId = await twitterClient.v1.uploadMedia(filePath, { mimeType: media.mimetype });
        mediaIds.push(mediaId);
        console.log('✅ Média uploadé:', media.filename);
      }
    }

    const tweetOptions = { text: content };
    if (mediaIds.length > 0) {
      tweetOptions.media = { media_ids: mediaIds };
    }
    if (tweet.communityId) {
      tweetOptions.community = { community_id: tweet.communityId };
    }

    const result = await twitterClient.v2.tweet(tweetOptions);

    console.log('✅ Tweet publié avec succès:', result.data.id);

    // Clean up media files after posting
    if (tweet.media && tweet.media.length > 0) {
      for (const media of tweet.media) {
        try {
          const filePath = path.join(__dirname, 'Uploads', media.filename);
          if (await fs.access(filePath).then(() => true).catch(() => false)) {
            await fs.unlink(filePath);
            console.log(`✅ Fichier média supprimé: ${media.filename}`);
          }
        } catch (err) {
          console.error(`❌ Erreur suppression fichier ${media.filename}:`, err.message);
        }
      }
    }

    return result;
  } catch (error) {
    console.error('❌ Erreur publication Twitter:', error.message);
    throw error;
  }
}

// Schedule checker for publishing tweets
function startScheduleChecker() {
  console.log('⏰ Démarrage du vérificateur de tweets...');
  setInterval(async () => {
    const now = new Date();
    console.log(`🔍 Vérification des tweets à ${now.toISOString()}`);
    const tweetsToPublish = scheduledTweets.filter(tweet =>
      tweet.status === 'scheduled' && new Date(tweet.datetime) <= now
    );

    if (tweetsToPublish.length === 0) {
      console.log('ℹ️ Aucun tweet à publier');
      return;
    }

    console.log(`📝 ${tweetsToPublish.length} tweet(s) à publier`);

    for (const tweet of tweetsToPublish) {
      try {
        await publishTweetToTwitter(tweet, tweet.content);
        tweet.status = 'published';
        tweet.publishedAt = new Date().toISOString();
        tweet.lastModified = new Date().toISOString();
        console.log(`✅ Tweet publié: ${tweet.content.substring(0, 30)}...`);
      } catch (error) {
        console.error(`❌ Erreur publication tweet ${tweet.id}:`, error.message);
        tweet.status = 'failed';
        tweet.error = error.message;
        tweet.lastModified = new Date().toISOString();
      }
    }

    await savePersistedData();
  }, 30000); // Check every 30 seconds
}

// Route for health check
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '2.0.8',
    tweetsCount: generatedTweetsHistory.length,
    scheduledTweetsCount: scheduledTweets.length,
    userStyleWritings: userStyle.writings.length,
    styleProgress: userStyle.styleProgress
  });
});

// Route for web interface
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('❌ Erreur globale:', error);
  res.status(500).json({
    success: false,
    error: 'Erreur serveur interne',
    details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
  });
});

// Initialize data and start server
async function startServer() {
  try {
    userId = await testTwitterConnection();
    await loadPersistedData();
    startScheduleChecker();
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`);
      console.log(`📊 Interface web: http://localhost:${PORT}`);
      console.log(`🔄 API endpoints:`);
      console.log(`   - GET  /api/user-communities`);
      console.log(`   - POST /api/update-tweet-community`);
      console.log(`   - POST /api/generate-tweets`);
      console.log(`   - POST /api/regenerate-tweet`);
      console.log(`   - POST /api/edit-tweet`);
      console.log(`   - POST /api/delete-tweet`);
      console.log(`   - POST /api/learn-style`);
      console.log(`   - POST /api/learn-content`);
      console.log(`   - POST /api/schedule-tweet`);
      console.log(`   - GET  /api/tweets`);
      console.log(`   - DELETE /api/tweets/:id`);
      console.log(`   - POST /api/tweets/:id/publish`);
      console.log(`   - GET  /api/tweets-history`);
      console.log(`   - GET  /health`);
      console.log(`📈 Historique: ${generatedTweetsHistory.length} groupes tweets`);
      console.log(`🕒 Tweets programmés: ${scheduledTweets.length}`);
      console.log(`✍️ Style utilisateur: ${userStyle.writings.length} échantillons`);
      console.log(`📊 Progression style: ${userStyle.styleProgress}/10000`);
    });
  } catch (error) {
    console.error('❌ Erreur démarrage:', error);
    process.exit(1);
  }
}

startServer();

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n👋 Arrêt du serveur...');
  await savePersistedData();
  process.exit(0);
});*/


/*
make sure we succeeed to schedule to send image to update the statut (programme, ...)
and yeah that's it

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const { TwitterApi } = require('twitter-api-v2');
const fs = require('fs').promises;
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'If-None-Match'],
  credentials: true
}));
app.use(express.json());

// Configure Multer for file uploads
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadPath = path.join(__dirname, 'uploads');
    await fs.mkdir(uploadPath, { recursive: true });
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
    cb(null, `${uniqueSuffix}-${file.originalname}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'video/mp4'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Type de fichier non supporté'), false);
    }
  }
});

// Serve static files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// API Keys validation
const GROQ_API_KEY = process.env.GROQ_API_KEY || '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';
if (!process.env.TWITTER_APP_KEY || !process.env.TWITTER_APP_SECRET ||
    !process.env.TWITTER_ACCESS_TOKEN || !process.env.TWITTER_ACCESS_SECRET) {
  console.error('❌ Erreur: Variables d\'environnement Twitter manquantes. Vérifiez votre fichier .env.');
  console.error('Requis: TWITTER_APP_KEY, TWITTER_APP_SECRET, TWITTER_ACCESS_TOKEN, TWITTER_ACCESS_SECRET');
  process.exit(1);
}

// Twitter API Client
let twitterClient;
try {
  twitterClient = new TwitterApi({
    appKey: process.env.TWITTER_APP_KEY,
    appSecret: process.env.TWITTER_APP_SECRET,
    accessToken: process.env.TWITTER_ACCESS_TOKEN,
    accessSecret: process.env.TWITTER_ACCESS_SECRET,
  });
} catch (error) {
  console.error('❌ Erreur initialisation client Twitter:', error.message);
  process.exit(1);
}

// Test Twitter connection
async function testTwitterConnection() {
  try {
    console.log('🔄 Test de connexion Twitter...');
    const me = await twitterClient.v2.me();
    console.log('✅ Connexion Twitter réussie:', me.data.username);
    return me.data.id;
  } catch (error) {
    console.error('❌ Échec de la connexion Twitter:', error.message);
    if (error.code === 401) {
      console.error('❌ Erreur d\'authentification: Vérifiez vos clés API Twitter');
    } else if (error.code === 403) {
      console.error('❌ Accès refusé: Vérifiez les permissions de votre app Twitter');
    }
    process.exit(1);
  }
}

// Storage
let userStyle = {
  writings: [],
  patterns: [],
  vocabulary: new Set(),
  tone: 'neutral',
  styleProgress: 0,
  lastModified: new Date().toISOString()
};
let generatedTweetsHistory = [];
let scheduledTweets = [];
let dataLock = false;
let userId = null;
let tweetIdCounter = 1;

// File paths for persistence
const USER_STYLE_FILE = path.join(__dirname, 'userStyle.json');
const TWEETS_HISTORY_FILE = path.join(__dirname, 'tweetsHistory.json');
const SCHEDULED_TWEETS_FILE = path.join(__dirname, 'scheduledTweets.json');

// Load data from files
async function loadPersistedData() {
  try {
    const userStyleData = await fs.readFile(USER_STYLE_FILE, 'utf8');
    userStyle = JSON.parse(userStyleData, (key, value) => {
      if (key === 'vocabulary') return new Set(value);
      return value;
    });
    console.log('✅ Loaded userStyle from file');
  } catch (error) {
    console.log('ℹ️ No userStyle file found, using default');
  }

  try {
    const tweetsHistoryData = await fs.readFile(TWEETS_HISTORY_FILE, 'utf8');
    generatedTweetsHistory = JSON.parse(tweetsHistoryData);
    if (generatedTweetsHistory.length > 0) {
      const maxId = Math.max(...generatedTweetsHistory.map(t => parseInt(t.id) || 0));
      if (maxId >= tweetIdCounter) tweetIdCounter = maxId + 1;
    }
    console.log('✅ Loaded tweetsHistory from file');
  } catch (error) {
    console.log('ℹ️ No tweetsHistory file found, using default');
  }

  try {
    const scheduledTweetsData = await fs.readFile(SCHEDULED_TWEETS_FILE, 'utf8');
    scheduledTweets = JSON.parse(scheduledTweetsData, (key, value) => {
      if (key === 'datetime' || key === 'createdAt' || key === 'lastModified' || key === 'publishedAt' || key === 'failedAt') {
        return value ? new Date(value) : null;
      }
      return value;
    });
    if (scheduledTweets.length > 0) {
      const maxId = Math.max(...scheduledTweets.map(t => t.id || 0));
      if (maxId >= tweetIdCounter) tweetIdCounter = maxId + 1;
    }
    console.log('✅ Loaded scheduledTweets from file');
  } catch (error) {
    console.log('ℹ️ No scheduledTweets file found, using default');
  }
}

// Save data to files
async function savePersistedData() {
  if (dataLock) {
    console.log('🔒 Data save skipped due to lock');
    return;
  }
  dataLock = true;
  try {
    await fs.writeFile(USER_STYLE_FILE, JSON.stringify(userStyle, (key, value) => {
      if (value instanceof Set) return Array.from(value);
      return value;
    }, 2));
    await fs.writeFile(TWEETS_HISTORY_FILE, JSON.stringify(generatedTweetsHistory, null, 2));
    await fs.writeFile(SCHEDULED_TWEETS_FILE, JSON.stringify(scheduledTweets, null, 2));
    console.log('✅ Data saved to files');
  } catch (error) {
    console.error('❌ Error saving data to files:', error.message);
  } finally {
    dataLock = false;
  }
}

// Generate ETag
function generateETag(data) {
  return crypto.createHash('md5').update(JSON.stringify(data)).digest('hex');
}

// Tone detection
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

// Axios instance for Groq API
const axiosInstance = axios.create({
  timeout: 15000,
  headers: {
    'Authorization': `Bearer ${GROQ_API_KEY}`,
    'Content-Type': 'application/json'
  }
});

// Route to fetch user's X Communities
app.get('/api/user-communities', async (req, res) => {
  try {
    console.log('🔍 Fetching communities for user:', userId);
    // Twitter API v2 does not support communities endpoint, return empty array as fallback
    res.json({ success: true, data: [] });
  } catch (error) {
    console.error('❌ Erreur récupération communautés:', error.message);
    res.status(500).json({
      success: false,
      error: 'Erreur récupération communautés',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to update community for a scheduled tweet
app.post('/api/update-tweet-community', async (req, res) => {
  try {
    const { tweetId, tweetIndex, communityId } = req.body;

    if (!tweetId || tweetIndex === undefined) {
      return res.status(400).json({ success: false, error: 'tweetId et tweetIndex requis' });
    }

    const scheduledTweet = scheduledTweets.find(t => t.tweetId === tweetId && t.tweetIndex === parseInt(tweetIndex));
    if (!scheduledTweet) {
      return res.status(404).json({ success: false, error: 'Tweet programmé non trouvé' });
    }

    scheduledTweet.communityId = communityId && communityId.trim() ? communityId.trim() : null;
    scheduledTweet.lastModified = new Date();
    await savePersistedData();

    res.json({
      success: true,
      message: 'Communauté mise à jour',
      data: { lastModified: scheduledTweet.lastModified }
    });
  } catch (error) {
    console.error('❌ Erreur mise à jour communauté:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur mise à jour communauté',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to save user style
app.post('/api/learn-style', async (req, res) => {
  try {
    const { styleText } = req.body;

    if (!styleText || styleText.trim() === '') {
      return res.status(400).json({ success: false, error: 'styleText requis' });
    }

    const trimmedText = styleText.trim();
    userStyle.writings.push({ text: trimmedText, timestamp: new Date() });
    const words = trimmedText.toLowerCase().match(/\b\w+\b/g) || [];
    words.forEach(word => userStyle.vocabulary.add(word));
    userStyle.tone = detectTone(trimmedText);
    userStyle.styleProgress = Math.min(userStyle.styleProgress + 1, 10000);
    userStyle.lastModified = new Date();

    if (userStyle.writings.length > 50) {
      userStyle.writings = userStyle.writings.slice(-50);
    }

    await savePersistedData();
    res.json({
      success: true,
      message: 'Style appris avec succès',
      data: {
        styleProgress: userStyle.styleProgress,
        lastModified: userStyle.lastModified
      }
    });
  } catch (error) {
    console.error('❌ Erreur apprentissage style:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur apprentissage style',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to generate tweets
app.post('/api/generate-tweets', async (req, res) => {
  try {
    const { userComment, originalTweet, context, modeFilter } = req.body;

    if (!userComment || userComment.trim() === '') {
      return res.status(400).json({ success: false, error: 'userComment requis' });
    }

    console.log(`🔍 Génération tweets pour: ${userComment.substring(0, 50)}...`);

    const styleContext = userStyle.writings.length > 0 ?
      `\n\nUser style (tone: ${userStyle.tone}, words: ${Array.from(userStyle.vocabulary).slice(-5).join(', ')}):\n${userStyle.writings.slice(-3).map(w => `- "${w.text}"`).join('\n')}` : '';

    const modes = [
      'tweet-viral', 'critique-constructive', 'thread-twitter', 'reformulation-simple',
      'angle-contrarian', 'storytelling', 'question-provocante', 'metaphore-creative', 'style-personnel'
    ];

    const modePrompts = {
      'tweet-viral': `Generate a viral tweet based on: "${userComment}". Secondary context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'critique-constructive': `Generate a constructive critique tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'thread-twitter': `Generate the first tweet of a thread based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'reformulation-simple': `Generate a simple reformulation tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'angle-contrarian': `Generate a contrarian angle tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'storytelling': `Generate a storytelling tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'question-provocante': `Generate a provocative question tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'metaphore-creative': `Generate a creative metaphor tweet for: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'style-personnel': `Generate a personal style tweet based on: "${userComment}". Style (tone: ${userStyle.tone}, words: ${Array.from(userStyle.vocabulary).slice(-5).join(', ')}). Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`
    };

    const filteredModes = modeFilter && modes.includes(modeFilter) ? [modeFilter] : modes;
    const prompts = filteredModes.map(mode => modePrompts[mode]);

    userStyle.writings.push({ text: userComment.trim(), timestamp: new Date() });
    userStyle.tone = detectTone(userComment.trim());
    userStyle.styleProgress = Math.min(userStyle.styleProgress + 1, 10000);
    userStyle.lastModified = new Date();

    if (userStyle.writings.length > 50) {
      userStyle.writings = userStyle.writings.slice(-50);
    }

    const promises = prompts.map(async (prompt, index) => {
      try {
        const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
          messages: [
            {
              role: 'system',
              content: 'Tweet expert. Generate original tweets based on user comment. Secondary context: original tweet. Max 280 chars, no hashtags/emojis. Respond only with the tweet.'
            },
            { role: 'user', content: prompt }
          ],
          model: 'llama3-8b-8192',
          temperature: 0.7,
          max_tokens: 100
        });

        const tweet = response.data.choices[0].message.content.trim();
        if (tweet.length > 280) {
          console.warn(`⚠️ Tweet trop long pour mode ${filteredModes[index]}: ${tweet.length} chars`);
          return { success: false, tweet: tweet.substring(0, 280), mode: filteredModes[index], error: 'Tweet trop long' };
        }
        return { success: true, tweet, mode: filteredModes[index] };
      } catch (error) {
        console.error(`❌ Erreur mode ${filteredModes[index]}:`, error.message);
        return {
          success: false,
          tweet: `Erreur: Échec génération pour ${filteredModes[index]}`,
          mode: filteredModes[index],
          error: error.message
        };
      }
    });

    const results = await Promise.all(promises);
    const generatedTweets = results.map(r => r.tweet);
    const usedModes = results.map(r => r.mode);

    const tweetData = {
      id: uuidv4(),
      timestamp: new Date(),
      lastModified: new Date(),
      originalTweet: originalTweet || null,
      userComment: userComment.trim(),
      context: context || null,
      generatedTweets,
      modesUsed: usedModes,
      used: false
    };

    generatedTweetsHistory.push(tweetData);
    if (generatedTweetsHistory.length > 100) {
      generatedTweetsHistory = generatedTweetsHistory.slice(-100);
    }

    await savePersistedData();

    console.log('✅ Tweets générés:', generatedTweets.length);
    res.json({
      success: true,
      data: tweetData,
      lastModified: tweetData.lastModified
    });
  } catch (error) {
    console.error('❌ Erreur génération tweets:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur génération tweets',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to regenerate a tweet
app.post('/api/regenerate-tweet', async (req, res) => {
  try {
    const { tweetId, tweetIndex, mode } = req.body;

    if (!tweetId || tweetIndex === undefined || !mode) {
      return res.status(400).json({ success: false, error: 'tweetId, tweetIndex et mode requis' });
    }

    const tweetGroup = generatedTweetsHistory.find(t => t.id === tweetId);
    if (!tweetGroup) {
      return res.status(404).json({ success: false, error: 'Groupe tweets non trouvé' });
    }

    if (!Number.isInteger(parseInt(tweetIndex)) || tweetIndex < 0 || tweetIndex >= tweetGroup.generatedTweets.length) {
      return res.status(400).json({ success: false, error: 'Index tweet invalide' });
    }

    const styleContext = userStyle.writings.length > 0 ?
      `\n\nUser style (tone: ${userStyle.tone}, words: ${Array.from(userStyle.vocabulary).slice(-5).join(', ')}):\n${userStyle.writings.slice(-3).map(w => `- "${w.text}"`).join('\n')}` : '';

    const modePrompts = {
      'tweet-viral': `Generate a viral tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'critique-constructive': `Generate a constructive critique tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'thread-twitter': `Generate the first tweet of a thread based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'reformulation-simple': `Generate a simple reformulation tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'angle-contrarian': `Generate a contrarian angle tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'storytelling': `Generate a storytelling tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'question-provocante': `Generate a provocative question tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'metaphore-creative': `Generate a creative metaphor tweet for: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'style-personnel': `Generate a personal style tweet based on: "${tweetGroup.userComment}". Style (tone: ${userStyle.tone}, words: ${Array.from(userStyle.vocabulary).slice(-5).join(', ')}). Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`
    };

    const prompt = modePrompts[mode];
    if (!prompt) {
      return res.status(400).json({ success: false, error: 'Mode invalide' });
    }

    const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
      messages: [
        {
          role: 'system',
          content: 'Tweet expert. Generate original tweets based on user comment. Secondary context: original tweet. Max 280 chars, no hashtags/emojis. Respond only with the tweet.'
        },
        { role: 'user', content: prompt }
      ],
      model: 'llama3-8b-8192',
      temperature: 0.7,
      max_tokens: 100
    });

    const newTweet = response.data.choices[0].message.content.trim();
    if (newTweet.length > 280) {
      console.warn(`⚠️ Tweet régénéré trop long: ${newTweet.length} chars`);
      return res.status(400).json({ success: false, error: 'Tweet régénéré dépasse 280 chars' });
    }

    tweetGroup.generatedTweets[tweetIndex] = newTweet;
    tweetGroup.modesUsed[tweetIndex] = mode;
    tweetGroup.lastModified = new Date();

    const scheduledTweet = scheduledTweets.find(t => t.tweetId === tweetId && t.tweetIndex === parseInt(tweetIndex));
    if (scheduledTweet) {
      scheduledTweet.content = newTweet;
      scheduledTweet.lastModified = new Date();
    }

    await savePersistedData();

    res.json({
      success: true,
      data: { tweet: newTweet, mode, lastModified: tweetGroup.lastModified }
    });
  } catch (error) {
    console.error('❌ Erreur régénération tweet:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur régénération tweet',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to learn about ragebait or viral content
app.post('/api/learn-content', async (req, res) => {
  try {
    const { type } = req.body;

    if (!['ragebait', 'viral'].includes(type)) {
      return res.status(400).json({ success: false, error: 'Type contenu invalide' });
    }

    const prompt = type === 'ragebait' ?
      'Explain ragebait, how it works on social media, 3 example ragebait tweets. In French, max 500 chars.' :
      'Explain viral content on social media, 3 example viral tweets. In French, max 500 chars.';

    const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
      messages: [
        { role: 'system', content: 'Social media expert. Concise explanation, examples in French, respect char limit.' },
        { role: 'user', content: prompt }
      ],
      model: 'llama3-8b-8192',
      temperature: 0.7,
      max_tokens: 200
    });

    const content = response.data.choices[0].message.content.trim();
    res.json({ success: true, data: content });
  } catch (error) {
    console.error('❌ Erreur info contenu:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur récupération info contenu',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to get tweets history
app.get('/api/tweets-history', (req, res) => {
  try {
    const data = generatedTweetsHistory.slice(-30).reverse().map(group => ({
      ...group,
      generatedTweets: group.generatedTweets || [],
      modesUsed: group.modesUsed || [],
      timestamp: new Date(group.timestamp),
      lastModified: new Date(group.lastModified)
    }));
    const etag = generateETag(data);
    if (req.get('If-None-Match') === etag) {
      return res.status(304).send();
    }
    res.set('ETag', etag);
    res.json({
      success: true,
      data,
      lastModified: data[0]?.lastModified || new Date()
    });
  } catch (error) {
    console.error('❌ Erreur historique tweets:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur récupération historique',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to mark tweet as used
app.post('/api/tweet-used', async (req, res) => {
  try {
    const { tweetId } = req.body;

    if (!tweetId) {
      return res.status(400).json({ success: false, error: 'tweetId requis' });
    }

    const tweetGroup = generatedTweetsHistory.find(t => t.id === tweetId);
    if (!tweetGroup) {
      return res.status(404).json({ success: false, error: 'Tweet non trouvé' });
    }

    tweetGroup.used = true;
    tweetGroup.used_at = new Date();
    tweetGroup.lastModified = new Date();
    await savePersistedData();

    res.json({
      success: true,
      message: 'Tweet marqué utilisé',
      data: { lastModified: tweetGroup.lastModified }
    });
  } catch (error) {
    console.error('❌ Erreur mise à jour tweet:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur mise à jour tweet',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to edit a tweet
app.post('/api/edit-tweet', async (req, res) => {
  try {
    const { tweetId, tweetIndex, newText } = req.body;

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

    const tweetGroup = generatedTweetsHistory.find(t => t.id === tweetId);
    if (!tweetGroup) {
      return res.status(404).json({ success: false, error: 'Groupe tweets non trouvé' });
    }

    if (!Number.isInteger(parseInt(tweetIndex)) || tweetIndex < 0 || tweetIndex >= tweetGroup.generatedTweets.length) {
      return res.status(400).json({ success: false, error: 'Index tweet invalide' });
    }

    console.log(`📝 Modification tweet ${tweetId}[${tweetIndex}]: "${tweetGroup.generatedTweets[tweetIndex]}" → "${trimmedText}"`);

    userStyle.writings.push({ text: trimmedText, timestamp: new Date() });
    const words = trimmedText.toLowerCase().match(/\b\w+\b/g) || [];
    words.forEach(word => userStyle.vocabulary.add(word));
    userStyle.tone = detectTone(trimmedText);
    userStyle.styleProgress = Math.min(userStyle.styleProgress + 1, 10000);
    userStyle.lastModified = new Date();

    if (userStyle.writings.length > 50) {
      userStyle.writings = userStyle.writings.slice(-50);
    }

    tweetGroup.generatedTweets[tweetIndex] = trimmedText;
    tweetGroup.lastModified = new Date();

    const scheduledTweet = scheduledTweets.find(t => t.tweetId === tweetId && t.tweetIndex === parseInt(tweetIndex));
    if (scheduledTweet) {
      scheduledTweet.content = trimmedText;
      scheduledTweet.lastModified = new Date();
    }

    await savePersistedData();

    res.json({
      success: true,
      message: 'Tweet modifié',
      data: {
        tweet: trimmedText,
        index: parseInt(tweetIndex),
        lastModified: tweetGroup.lastModified,
        styleProgress: userStyle.styleProgress
      }
    });
  } catch (error) {
    console.error('❌ Erreur modification tweet:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur modification tweet',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to schedule a tweet
app.post('/api/schedule-tweet', upload.array('media', 4), async (req, res) => {
  try {
    const { content, datetime, tweetId, tweetIndex, communityId } = req.body;

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

    const tweetGroup = generatedTweetsHistory.find(t => t.id === tweetId);
    if (!tweetGroup) {
      return res.status(404).json({ success: false, error: 'Groupe tweets non trouvé' });
    }

    if (!Number.isInteger(parseInt(tweetIndex)) || parseInt(tweetIndex) < 0 || parseInt(tweetIndex) >= tweetGroup.generatedTweets.length) {
      return res.status(400).json({ success: false, error: 'Index tweet invalide' });
    }

    const media = req.files ? req.files.map(file => ({
      id: uuidv4(),
      filename: file.filename,
      originalName: file.originalname,
      path: file.path,
      url: `http://localhost:${PORT}/uploads/${file.filename}`,
      mimetype: file.mimetype,
      type: file.mimetype.startsWith('image/') ? 'image' : 'video'
    })) : [];

    const tweet = {
      id: tweetIdCounter++,
      content: trimmedContent,
      datetime: scheduleDate,
      createdAt: new Date(),
      lastModified: new Date(),
      media,
      status: 'scheduled',
      tweetId,
      tweetIndex: parseInt(tweetIndex),
      communityId: communityId && communityId.trim() ? communityId.trim() : null
    };

    // Remove old tweet and its media
    const existingIndex = scheduledTweets.findIndex(t => t.tweetId === tweetId && t.tweetIndex === parseInt(tweetIndex));
    if (existingIndex !== -1) {
      const oldTweet = scheduledTweets[existingIndex];
      scheduledTweets.splice(existingIndex, 1);
      if (oldTweet.media && oldTweet.media.length > 0) {
        for (const media of oldTweet.media) {
          try {
            const filePath = path.join(__dirname, 'Uploads', media.filename);
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

    scheduledTweets.push(tweet);
    await savePersistedData();

    console.log('✅ Tweet programmé:', {
      id: tweet.id,
      content: trimmedContent.substring(0, 50) + '...',
      datetime: scheduleDate.toLocaleString(),
      mediaCount: media.length,
      communityId: tweet.communityId
    });

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
          type: m.type
        }))
      }
    });
  } catch (error) {
    console.error('❌ Erreur programmation tweet:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur programmation tweet',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to get all scheduled tweets
app.get('/api/tweets', async (req, res) => {
  try {
    const data = scheduledTweets.map(tweet => ({
      ...tweet,
      media: (tweet.media || []).map(media => ({
        id: media.id,
        filename: media.filename,
        originalName: media.originalName,
        url: media.url || `http://localhost:${PORT}/uploads/${media.filename}`,
        mimetype: media.mimetype || 'application/octet-stream',
        type: media.type || (media.mimetype && media.mimetype.startsWith('image/') ? 'image' : 'video')
      }))
    }));
    const etag = generateETag(data);
    if (req.get('If-None-Match') === etag) {
      return res.status(304).send();
    }
    res.set('ETag', etag);
    res.json(data);
  } catch (error) {
    console.error('❌ Erreur récupération tweets programmés:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur récupération tweets programmés',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to delete a scheduled tweet
app.delete('/api/tweets/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const tweetIndex = scheduledTweets.findIndex(t => t.id === parseInt(id));

    if (tweetIndex === -1) {
      return res.status(404).json({ success: false, error: 'Tweet programmé non trouvé' });
    }

    const tweet = scheduledTweets[tweetIndex];
    if (tweet.media && tweet.media.length > 0) {
      for (const media of tweet.media) {
        try {
          const filePath = path.join(__dirname, 'Uploads', media.filename);
          if (await fs.access(filePath).then(() => true).catch(() => false)) {
            await fs.unlink(filePath);
            console.log(`✅ Fichier média supprimé: ${media.filename}`);
          }
        } catch (err) {
          console.warn(`⚠️ Erreur suppression fichier ${media.filename}:`, err.message);
        }
      }
    }

    scheduledTweets.splice(tweetIndex, 1);
    await savePersistedData();

    console.log('🗑️ Tweet programmé supprimé:', id);
    res.json({
      success: true,
      message: 'Tweet programmé supprimé'
    });
  } catch (error) {
    console.error('❌ Erreur suppression tweet programmé:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur suppression tweet programmé',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to delete a tweet from history
app.post('/api/delete-tweet', async (req, res) => {
  try {
    const { tweetId, tweetIndex } = req.body;

    if (!tweetId || tweetIndex === undefined) {
      return res.status(400).json({ success: false, error: 'tweetId et tweetIndex requis' });
    }

    const tweetGroup = generatedTweetsHistory.find(t => t.id === tweetId);
    if (!tweetGroup) {
      return res.status(404).json({ success: false, error: 'Groupe tweets non trouvé' });
    }

    if (!Number.isInteger(parseInt(tweetIndex)) || tweetIndex < 0 || tweetIndex >= tweetGroup.generatedTweets.length) {
      return res.status(400).json({ success: false, error: 'Index tweet invalide' });
    }

    const scheduledTweetIndex = scheduledTweets.findIndex(t => t.tweetId === tweetId && t.tweetIndex === parseInt(tweetIndex));
    if (scheduledTweetIndex !== -1) {
      const tweet = scheduledTweets[scheduledTweetIndex];
      if (tweet.media && tweet.media.length > 0) {
        for (const media of tweet.media) {
          try {
            const filePath = path.join(__dirname, 'Uploads', media.filename);
            if (await fs.access(filePath).then(() => true).catch(() => false)) {
              await fs.unlink(filePath);
              console.log(`✅ Fichier média supprimé: ${media.filename}`);
            }
          } catch (err) {
            console.warn(`⚠️ Erreur suppression fichier ${media.filename}:`, err.message);
          }
        }
      }
      scheduledTweets.splice(scheduledTweetIndex, 1);
    }

    tweetGroup.generatedTweets.splice(tweetIndex, 1);
    tweetGroup.modesUsed.splice(tweetIndex, 1);
    tweetGroup.lastModified = new Date();

    if (tweetGroup.generatedTweets.length === 0) {
      generatedTweetsHistory = generatedTweetsHistory.filter(t => t.id !== tweetId);
    }

    await savePersistedData();

    res.json({
      success: true,
      message: 'Tweet supprimé',
      data: {
        remainingCount: tweetGroup.generatedTweets.length,
        lastModified: tweetGroup.lastModified
      }
    });
  } catch (error) {
    console.error('❌ Erreur suppression tweet:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur suppression tweet',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Route to publish a scheduled tweet immediately
app.post('/api/tweets/:id/publish', async (req, res) => {
  try {
    const { id } = req.params;
    const { content } = req.body;

    const tweet = scheduledTweets.find(t => t.id === parseInt(id));
    if (!tweet) {
      return res.status(404).json({ success: false, error: 'Tweet programmé non trouvé' });
    }

    if (tweet.status !== 'scheduled') {
      return res.status(400).json({ success: false, error: 'Tweet non programmé' });
    }

    const result = await publishTweetToTwitter(tweet, content || tweet.content);

    tweet.status = 'published';
    tweet.publishedAt = new Date();
    tweet.twitterId = result.data.id;
    tweet.lastModified = new Date();
    await savePersistedData();

    console.log('✅ Tweet publié manuellement:', tweet.id);

    res.json({
      success: true,
      message: 'Tweet publié',
      result: result.data
    });
  } catch (error) {
    console.error('❌ Erreur publication tweet:', error);
    const tweet = scheduledTweets.find(t => t.id === parseInt(req.params.id));
    if (tweet) {
      tweet.status = 'failed';
      tweet.error = error.message;
      tweet.lastModified = new Date();
      tweet.failedAt = new Date();
      await savePersistedData();
    }

    res.status(error.code === 403 ? 403 : 500).json({
      success: false,
      error: 'Erreur publication tweet',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
    });
  }
});

// Function to publish tweet to Twitter
async function publishTweetToTwitter(tweet, content) {
  try {
    console.log('🚀 Publication du tweet:', tweet.id);

    let mediaIds = [];
    if (tweet.media && tweet.media.length > 0) {
      console.log('📎 Upload des médias...');
      for (const media of tweet.media) {
        const filePath = path.join(__dirname, 'Uploads', media.filename);
        try {
          await fs.access(filePath);
          const mediaId = await twitterClient.v1.uploadMedia(filePath, {
            mimeType: media.mimetype
          });
          mediaIds.push(mediaId);
          console.log('✅ Média uploadé:', media.filename);
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

    console.log('✅ Tweet publié avec succès:', result.data.id);

    // Clean up media files after successful posting
    if (tweet.media && tweet.media.length > 0) {
      for (const media of tweet.media) {
        try {
          const filePath = path.join(__dirname, 'Uploads', media.filename);
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
    console.error('❌ Erreur publication Twitter:', error.message);
    throw error;
  }
}

// Schedule checker for publishing tweets
function startScheduleChecker() {
  console.log('⏰ Démarrage du vérificateur de tweets programmés...');

  const checkInterval = setInterval(async () => {
    try {
      const now = new Date();
      console.log(`🔍 Vérification des tweets programmés à ${now.toLocaleString()}`);

      const tweetsToPublish = scheduledTweets.filter(tweet =>
        tweet.status === 'scheduled' && new Date(tweet.datetime) <= now
      );

      if (tweetsToPublish.length === 0) {
        console.log('ℹ️ Aucun tweet à publier maintenant');
        return;
      }

      console.log(`📝 ${tweetsToPublish.length} tweet(s) à publier`);

      for (const tweet of tweetsToPublish) {
        try {
          console.log(`🚀 Tentative de publication du tweet ${tweet.id}: "${tweet.content.substring(0, 50)}..."`);

          const result = await publishTweetToTwitter(tweet, tweet.content);

          tweet.status = 'published';
          tweet.publishedAt = new Date();
          tweet.twitterId = result.data.id;
          tweet.lastModified = new Date();

          console.log(`✅ Tweet ${tweet.id} publié avec succès: ${result.data.id}`);
        } catch (error) {
          console.error(`❌ Erreur publication tweet ${tweet.id}:`, error.message);
          tweet.status = 'failed';
          tweet.error = error.message;
          tweet.lastModified = new Date();
          tweet.failedAt = new Date();
        }
      }

      await savePersistedData();
    } catch (error) {
      console.error('❌ Erreur dans le vérificateur de tweets:', error.message);
    }
  }, 30000); // Check every 30 seconds

  process.scheduleChecker = checkInterval;
}

// Route for health check
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date(),
    version: '2.2.0',
    tweetsCount: generatedTweetsHistory.length,
    scheduledTweetsCount: scheduledTweets.length,
    scheduledActiveCount: scheduledTweets.filter(t => t.status === 'scheduled').length,
    publishedCount: scheduledTweets.filter(t => t.status === 'published').length,
    failedCount: scheduledTweets.filter(t => t.status === 'failed').length,
    userStyleWritings: userStyle.writings.length,
    styleProgress: userStyle.styleProgress,
    userId: userId
  });
});

// Route for web interface
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('❌ Erreur globale:', error);
  res.status(500).json({
    success: false,
    error: 'Erreur serveur interne',
    details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne'
  });
});

// Initialize data and start server
async function startServer() {
  try {
    console.log('🔄 Initialisation du serveur...');

    // Test Twitter connection
    userId = await testTwitterConnection();

    // Load persisted data
    await loadPersistedData();

    // Start the schedule checker
    startScheduleChecker();

    // Start the Express server
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`);
      console.log(`📊 Interface web: http://localhost:${PORT}`);
      console.log(`🔄 API endpoints disponibles:`);
      console.log(`   - GET  /api/user-communities`);
      console.log(`   - POST /api/update-tweet-community`);
      console.log(`   - POST /api/generate-tweets`);
      console.log(`   - POST /api/regenerate-tweet`);
      console.log(`   - POST /api/edit-tweet`);
      console.log(`   - POST /api/delete-tweet`);
      console.log(`   - POST /api/learn-style`);
      console.log(`   - POST /api/learn-content`);
      console.log(`   - POST /api/schedule-tweet`);
      console.log(`   - GET  /api/tweets`);
      console.log(`   - DELETE /api/tweets/:id`);
      console.log(`   - POST /api/tweets/:id/publish`);
      console.log(`   - GET  /api/tweets-history`);
      console.log(`   - POST /api/tweet-used`);
      console.log(`   - GET  /health`);
      console.log(`📈 Statistiques:`);
      console.log(`   - Historique: ${generatedTweetsHistory.length} groupes tweets`);
      console.log(`   - Tweets programmés: ${scheduledTweets.length}`);
      console.log(`   - Tweets actifs: ${scheduledTweets.filter(t => t.status === 'scheduled').length}`);
      console.log(`   - Style utilisateur: ${userStyle.writings.length} échantillons`);
      console.log(`   - Progression style: ${userStyle.styleProgress}`);
      console.log(`   - User ID: ${userId}`);
      console.log('✅ Serveur prêt!');
    });
  } catch (error) {
    console.error('❌ Erreur lors du démarrage du serveur:', error.message);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n👋 Arrêt gracieux du serveur...');
  if (process.scheduleChecker) {
    clearInterval(process.scheduleChecker);
    console.log('⏰ Vérificateur de tweets arrêté');
  }
  await savePersistedData();
  console.log('💾 Données sauvegardées');
  console.log('✅ Serveur arrêté proprement');
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('\n👋 Signal SIGTERM reçu, arrêt du serveur...');
  if (process.scheduleChecker) {
    clearInterval(process.scheduleChecker);
  }
  await savePersistedData();
  process.exit(0);
});



voici le server corrige le 401 error que j'ai a

// Start the server

/*
voici le server corrige le 401 error que j'ai et assure toi que le log out marche
bref corrige le server pour que la bullefocntionne

// startServer();*/
// const express = require('express');
// const cors = require('cors');
// const axios = require('axios');
// const path = require('path');
// const { TwitterApi } = require('twitter-api-v2');
// const fs = require('fs').promises;
// const multer = require('multer');
// const { v4: uuidv4 } = require('uuid');
// const crypto = require('crypto');
// const admin = require('firebase-admin');
// require('dotenv').config();
//
// const app = express();
// const PORT = process.env.PORT || 3000;
//
// // Initialize Firebase Admin SDK
// try {
//   const serviceAccount = require("./firebase-service-account.json");
//   admin.initializeApp({
//     credential: admin.credential.cert(serviceAccount)
//   });
//   console.log('✅ Firebase Admin initialisé');
// } catch (error) {
//   console.error('❌ Erreur initialisation Firebase Admin:', error.message, error.stack);
//   process.exit(1);
// }
//
// // Middleware
// app.use(cors({
//   origin: ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://127.0.0.1:8080', 'https://x.com'],
//   methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
//   allowedHeaders: ['Content-Type', 'If-None-Match', 'Authorization'],
//   credentials: true,
// }));
// app.use(express.json());
//
// // Middleware to verify Firebase ID token
// async function verifyToken(req, res, next) {
//   const authHeader = req.headers.authorization;
//   if (!authHeader || !authHeader.startsWith('Bearer ')) {
//     console.error('❌ Aucun ou mauvais en-tête Authorization');
//     return res.status(401).json({ success: false, error: 'Aucun ou mauvais en-tête Authorization' });
//   }
//
//   const idToken = authHeader.split('Bearer ')[1];
//   try {
//     console.log(`🔍 Vérification token: ${idToken.substring(0, 10)}...`);
//     const decodedToken = await admin.auth().verifyIdToken(idToken);
//     req.user = { uid: decodedToken.uid };
//     console.log('✅ Token vérifié, UID:', decodedToken.uid);
//     next();
//   } catch (error) {
//     console.error('❌ Erreur vérification token:', error.message, error.stack);
//     res.status(401).json({ success: false, error: 'Token invalide ou expiré', details: error.message });
//   }
// }
//
// // Configure Multer for file uploads
// const storage = multer.diskStorage({
//   destination: async (req, file, cb) => {
//     const uploadPath = path.join(__dirname, 'Uploads', req.user.uid);
//     await fs.mkdir(uploadPath, { recursive: true });
//     cb(null, uploadPath);
//   },
//   filename: (req, file, cb) => {
//     const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
//     cb(null, `${uniqueSuffix}-${file.originalname}`);
//   },
// });
// const upload = multer({
//   storage,
//   limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
//   fileFilter: (req, file, cb) => {
//     const allowedTypes = ['image/jpeg', 'image/png', 'video/mp4'];
//     if (allowedTypes.includes(file.mimetype)) {
//       cb(null, true);
//     } else {
//       cb(new Error('Type de fichier non supporté. Utilisez JPEG, PNG ou MP4.'), false);
//     }
//   },
// });
//
// // Serve static files
// app.use('/Uploads', express.static(path.join(__dirname, 'Uploads')));
// app.use(express.static(path.join(__dirname, 'public')));
//
// // API Keys validation
// const GROQ_API_KEY = process.env.GROQ_API_KEY || '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';
//
// // User-specific data storage
// const userData = new Map(); // In-memory store for user data
// const tweetIdCounters = new Map(); // Per-user tweet ID counter
//
// // File paths for user-specific persistence
// function getUserFilePaths(uid) {
//   return {
//     userStyleFile: path.join(__dirname, 'data', uid, 'userStyle.json'),
//     tweetsHistoryFile: path.join(__dirname, 'data', uid, 'tweetsHistory.json'),
//     scheduledTweetsFile: path.join(__dirname, 'data', uid, 'scheduledTweets.json'),
//     twitterTokensFile: path.join(__dirname, 'data', uid, 'twitterTokens.json'),
//   };
// }
//
// // Initialize user data
// async function initializeUserData(uid) {
//   if (!userData.has(uid)) {
//     console.log(`🔄 Initialisation données pour UID: ${uid}`);
//     const defaultUserStyle = {
//       writings: [],
//       patterns: [],
//       vocabulary: new Set(),
//       tone: 'neutral',
//       styleProgress: 0,
//       lastModified: new Date().toISOString(),
//     };
//     userData.set(uid, {
//       userStyle: defaultUserStyle,
//       generatedTweetsHistory: [],
//       scheduledTweets: [],
//       twitterClient: null,
//       twitterTokens: null,
//       dataLock: false,
//     });
//     tweetIdCounters.set(uid, 1);
//
//     const { userStyleFile, tweetsHistoryFile, scheduledTweetsFile, twitterTokensFile } = getUserFilePaths(uid);
//     const userDir = path.dirname(userStyleFile);
//
//     try {
//       // Créer le dossier utilisateur s'il n'existe pas
//       await fs.mkdir(userDir, { recursive: true });
//       console.log(`✅ Dossier créé: ${userDir}`);
//     } catch (error) {
//       console.error(`❌ Erreur création dossier ${userDir}:`, error.message, error.stack);
//       throw new Error(`Échec création dossier utilisateur: ${error.message}`);
//     }
//
//     try {
//       const userStyleData = await fs.readFile(userStyleFile, 'utf8');
//       userData.get(uid).userStyle = JSON.parse(userStyleData, (key, value) => {
//         if (key === 'vocabulary') return new Set(value);
//         return value;
//       });
//       console.log(`✅ Loaded userStyle for user ${uid}`);
//     } catch (error) {
//       if (error.code === 'ENOENT') {
//         console.log(`ℹ️ Aucun fichier userStyle pour ${uid}, utilisation des valeurs par défaut`);
//       } else {
//         console.error(`❌ Erreur lecture ${userStyleFile}:`, error.message, error.stack);
//         throw new Error(`Échec lecture userStyle: ${error.message}`);
//       }
//     }
//
//     try {
//       const tweetsHistoryData = await fs.readFile(tweetsHistoryFile, 'utf8');
//       userData.get(uid).generatedTweetsHistory = JSON.parse(tweetsHistoryData);
//       if (userData.get(uid).generatedTweetsHistory.length > 0) {
//         const maxId = Math.max(...userData.get(uid).generatedTweetsHistory.map(t => parseInt(t.id) || 0));
//         if (maxId >= tweetIdCounters.get(uid)) tweetIdCounters.set(uid, maxId + 1);
//       }
//       console.log(`✅ Loaded tweetsHistory for user ${uid}`);
//     } catch (error) {
//       if (error.code === 'ENOENT') {
//         console.log(`ℹ️ Aucun fichier tweetsHistory pour ${uid}, utilisation des valeurs par défaut`);
//       } else {
//         console.error(`❌ Erreur lecture ${tweetsHistoryFile}:`, error.message, error.stack);
//         throw new Error(`Échec lecture tweetsHistory: ${error.message}`);
//       }
//     }
//
//     try {
//       const scheduledTweetsData = await fs.readFile(scheduledTweetsFile, 'utf8');
//       userData.get(uid).scheduledTweets = JSON.parse(scheduledTweetsData, (key, value) => {
//         if (key === 'datetime' || key === 'createdAt' || key === 'lastModified' || key === 'publishedAt' || key === 'failedAt') {
//           return value ? new Date(value) : null;
//         }
//         return value;
//       });
//       if (userData.get(uid).scheduledTweets.length > 0) {
//         const maxId = Math.max(...userData.get(uid).scheduledTweets.map(t => t.id || 0));
//         if (maxId >= tweetIdCounters.get(uid)) tweetIdCounters.set(uid, maxId + 1);
//       }
//       console.log(`✅ Loaded scheduledTweets for user ${uid}`);
//     } catch (error) {
//       if (error.code === 'ENOENT') {
//         console.log(`ℹ️ Aucun fichier scheduledTweets pour ${uid}, utilisation des valeurs par défaut`);
//       } else {
//         console.error(`❌ Erreur lecture ${scheduledTweetsFile}:`, error.message, error.stack);
//         throw new Error(`Échec lecture scheduledTweets: ${error.message}`);
//       }
//     }
//
//     try {
//       const twitterTokensData = await fs.readFile(twitterTokensFile, 'utf8');
//       const tokens = JSON.parse(twitterTokensData);
//       userData.get(uid).twitterTokens = tokens;
//       userData.get(uid).twitterClient = new TwitterApi({
//         appKey: process.env.TWITTER_APP_KEY,
//         appSecret: process.env.TWITTER_APP_SECRET,
//         accessToken: tokens.accessToken,
//         accessSecret: tokens.accessSecret,
//       });
//       console.log(`✅ Loaded Twitter tokens for user ${uid}`);
//     } catch (error) {
//       if (error.code === 'ENOENT') {
//         console.log(`ℹ️ Aucun fichier twitterTokens pour ${uid}, l'utilisateur doit s'authentifier`);
//       } else {
//         console.error(`❌ Erreur lecture ${twitterTokensFile}:`, error.message, error.stack);
//         throw new Error(`Échec lecture twitterTokens: ${error.message}`);
//       }
//     }
//   }
// }
//
// // Save user-specific data to files
// async function saveUserData(uid) {
//   const user = userData.get(uid);
//   if (!user || user.dataLock) {
//     console.log(`🔒 Sauvegarde données ignorée pour ${uid} (verrou ou données absentes)`);
//     return;
//   }
//   user.dataLock = true;
//   const { userStyleFile, tweetsHistoryFile, scheduledTweetsFile, twitterTokensFile } = getUserFilePaths(uid);
//   try {
//     await fs.mkdir(path.dirname(userStyleFile), { recursive: true });
//     await fs.writeFile(userStyleFile, JSON.stringify(user.userStyle, (key, value) => {
//       if (value instanceof Set) return Array.from(value);
//       return value;
//     }, 2));
//     await fs.writeFile(tweetsHistoryFile, JSON.stringify(user.generatedTweetsHistory, null, 2));
//     await fs.writeFile(scheduledTweetsFile, JSON.stringify(user.scheduledTweets, null, 2));
//     if (user.twitterTokens) {
//       await fs.writeFile(twitterTokensFile, JSON.stringify(user.twitterTokens, null, 2));
//     }
//     console.log(`✅ Données sauvegardées pour ${uid}`);
//   } catch (error) {
//     console.error(`❌ Erreur sauvegarde données pour ${uid}:`, error.message, error.stack);
//     throw new Error(`Échec sauvegarde données: ${error.message}`);
//   } finally {
//     user.dataLock = false;
//   }
// }
//
// // Generate ETag
// function generateETag(data) {
//   return crypto.createHash('md5').update(JSON.stringify(data)).digest('hex');
// }
//
// // Tone detection
// function detectTone(text) {
//   const positiveWords = ['great', 'awesome', 'fantastic', 'love', 'happy', 'good', 'excellent', 'amazing'];
//   const negativeWords = ['bad', 'terrible', 'hate', 'sad', 'problem', 'fail', 'awful', 'horrible'];
//   const words = text.toLowerCase().split(/\s+/);
//   let positiveCount = 0;
//   let negativeCount = 0;
//
//   words.forEach(word => {
//     if (positiveWords.includes(word)) positiveCount++;
//     if (negativeWords.includes(word)) negativeCount++;
//   });
//
//   if (positiveCount > negativeCount) return 'positive';
//   if (negativeCount > positiveCount) return 'negative';
//   return 'neutral';
// }
//
// // Axios instance for Groq API
// const axiosInstance = axios.create({
//   timeout: 15000,
//   headers: {
//     'Authorization': `Bearer ${GROQ_API_KEY}`,
//     'Content-Type': 'application/json',
//   },
// });
//
// // Twitter OAuth 2.0 setup
// const twitterOAuthClient = new TwitterApi({
//   appKey: process.env.TWITTER_APP_KEY,
//   appSecret: process.env.TWITTER_APP_SECRET,
// });
//
// // Route to initiate Twitter OAuth
// app.get('/api/twitter-auth', verifyToken, async (req, res) => {
//   try {
//     const uid = req.user.uid;
//     const authLink = await twitterOAuthClient.generateAuthLink('http://localhost:3000/api/twitter-callback', {
//       authAccessType: 'write',
//       scope: ['tweet.read', 'tweet.write', 'users.read'],
//     });
//     userData.get(uid).twitterAuthState = authLink.state; // Store state for verification
//     res.json({ success: true, authUrl: authLink.url });
//   } catch (error) {
//     console.error(`❌ Erreur initiation auth Twitter pour ${req.user.uid}:`, error.message, error.stack);
//     res.status(500).json({ success: false, error: 'Échec initiation auth Twitter' });
//   }
// });
//
// // Route to handle Twitter OAuth callback
// app.get('/api/twitter-callback', verifyToken, async (req, res) => {
//   try {
//     const { code, state } = req.query;
//     const uid = req.user.uid;
//     await initializeUserData(uid);
//     const user = userData.get(uid);
//
//     if (!user.twitterAuthState || user.twitterAuthState !== state) {
//       return res.status(400).json({ success: false, error: 'Paramètre state invalide' });
//     }
//
//     const { accessToken, refreshToken, accessSecret } = await twitterOAuthClient.login(code);
//     user.twitterTokens = { accessToken, accessSecret, refreshToken };
//     user.twitterClient = new TwitterApi({
//       appKey: process.env.TWITTER_APP_KEY,
//       appSecret: process.env.TWITTER_APP_SECRET,
//       accessToken,
//       accessSecret,
//     });
//
//     await saveUserData(uid);
//     delete user.twitterAuthState; // Clear state after use
//
//     res.redirect('http://localhost:3000/');
//   } catch (error) {
//     console.error(`❌ Erreur callback Twitter pour ${req.user.uid}:`, error.message, error.stack);
//     res.status(500).json({ success: false, error: 'Échec authentification Twitter' });
//   }
// });
//
// // Route to initiate extension login
// app.get('/api/extension-login', (req, res) => {
//   const loginPage = `
//     <!DOCTYPE html>
//     <html lang="fr">
//     <head>
//       <meta charset="UTF-8">
//       <title>TwitterFlow - Connexion Extension</title>
//       <script src="https://www.gstatic.com/firebasejs/10.7.1/firebase-app-compat.js"></script>
//       <script src="https://www.gstatic.com/firebasejs/10.7.1/firebase-auth-compat.js"></script>
//       <style>
//         body {
//           font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
//           display: flex;
//           justify-content: center;
//           align-items: center;
//           height: 100vh;
//           margin: 0;
//           background: #1a1a1a;
//           color: white;
//         }
//         .container {
//           text-align: center;
//           padding: 20px;
//           border-radius: 10px;
//           background: rgba(255, 255, 255, 0.05);
//           box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
//         }
//         button {
//           padding: 10px 20px;
//           margin: 10px;
//           border: none;
//           border-radius: 5px;
//           background: #007BFE;
//           color: white;
//           cursor: pointer;
//           font-size: 16px;
//         }
//         button:hover { background: #005bb5; }
//       </style>
//     </head>
//     <body>
//       <div class="container">
//         <h2>Connexion à TwitterFlow</h2>
//         <p>Connectez-vous pour utiliser l'extension.</p>
//         <button onclick="signInWithGoogle()">Connexion avec Google</button>
//         <button onclick="signInWithEmail()">Connexion avec Email</button>
//         <div id="error" style="color: #ff6b6b; margin-top: 10px;"></div>
//       </div>
//       <script>
//         const firebaseConfig = {
//           apiKey: "AIzaSyCh0EeCbrm-LzHYOJAYTuQlJJzTFBs-xjo",
//           authDomain: "ropainx-b13da.firebaseapp.com",
//           projectId: "ropainx-b13da",
//           storageBucket: "ropainx-b13da.firebasestorage.app",
//           messagingSenderId: "293729340264",
//           appId: "1:293729340264:web:89bbcdc6197a05520b64dd",
//           measurementId: "G-H3T6EF9E4H"
//         };
//         firebase.initializeApp(firebaseConfig);
//         const auth = firebase.auth();
//
//         function signInWithGoogle() {
//           const provider = new firebase.auth.GoogleAuthProvider();
//           auth.signInWithPopup(provider)
//             .then(async (result) => {
//               const token = await result.user.getIdToken();
//               console.log('✅ Token généré:', token.substring(0, 10) + '...');
//               window.opener.postMessage({ type: 'TF_LOGIN', token, uid: result.user.uid }, 'https://x.com');
//               window.close();
//             })
//             .catch(error => {
//               console.error('❌ Erreur connexion Google:', error.message);
//               document.getElementById('error').innerText = 'Erreur: ' + error.message;
//             });
//         }
//
//         function signInWithEmail() {
//           const email = prompt('Entrez votre email:');
//           const password = prompt('Entrez votre mot de passe:');
//           if (email && password) {
//             auth.signInWithEmailAndPassword(email, password)
//               .then(async (result) => {
//                 const token = await result.user.getIdToken();
//                 console.log('✅ Token généré:', token.substring(0, 10) + '...');
//                 window.opener.postMessage({ type: 'TF_LOGIN', token, uid: result.user.uid }, 'https://x.com');
//                 window.close();
//               })
//               .catch(error => {
//                 console.error('❌ Erreur connexion Email:', error.message);
//                 document.getElementById('error').innerText = 'Erreur: ' + error.message;
//               });
//           }
//         }
//       </script>
//     </body>
//     </html>
//   `;
//   res.send(loginPage);
// });
//
// // Modified login route to handle extension login
// app.post('/api/login', verifyToken, async (req, res) => {
//   try {
//     const uid = req.user.uid;
//     console.log(`🔍 Connexion pour UID: ${uid}`);
//     await initializeUserData(uid);
//     res.json({ success: true, message: 'Connexion réussie', uid });
//   } catch (error) {
//     console.error(`❌ Erreur traitement connexion pour ${req.user.uid}:`, error.message, error.stack);
//     res.status(500).json({ success: false, error: 'Échec traitement connexion', details: error.message });
//   }
// });
//
// // Apply auth middleware to protected routes
// app.use('/api/*', verifyToken);
//
// // Route to save user style
// app.post('/api/learn-style', async (req, res) => {
//   try {
//     const { styleText } = req.body;
//     const uid = req.user.uid;
//     await initializeUserData(uid);
//     const user = userData.get(uid);
//
//     if (!styleText || styleText.trim() === '') {
//       return res.status(400).json({ success: false, error: 'styleText requis' });
//     }
//
//     const trimmedText = styleText.trim();
//     user.userStyle.writings.push({ text: trimmedText, timestamp: new Date() });
//     const words = trimmedText.toLowerCase().match(/\b\w+\b/g) || [];
//     words.forEach(word => user.userStyle.vocabulary.add(word));
//     user.userStyle.tone = detectTone(trimmedText);
//     user.userStyle.styleProgress = Math.min(user.userStyle.styleProgress + 1, 10000);
//     user.userStyle.lastModified = new Date();
//
//     if (user.userStyle.writings.length > 50) {
//       user.userStyle.writings = user.userStyle.writings.slice(-50);
//     }
//
//     await saveUserData(uid);
//     res.json({
//       success: true,
//       message: 'Style appris avec succès',
//       data: {
//         styleProgress: user.userStyle.styleProgress,
//         lastModified: user.userStyle.lastModified,
//       },
//     });
//   } catch (error) {
//     console.error(`❌ Erreur apprentissage style pour ${req.user.uid}:`, error.message, error.stack);
//     res.status(500).json({
//       success: false,
//       error: 'Erreur apprentissage style',
//       details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
//     });
//   }
// });
//
// // Route to generate tweets
// app.post('/api/generate-tweets', async (req, res) => {
//   try {
//     const { userComment, originalTweet, context, modeFilter } = req.body;
//     const uid = req.user.uid;
//     await initializeUserData(uid);
//     const user = userData.get(uid);
//
//     if (!userComment || userComment.trim() === '') {
//       return res.status(400).json({ success: false, error: 'userComment requis' });
//     }
//
//     console.log(`🔍 Génération tweets pour ${uid}: ${userComment.substring(0, 50)}...`);
//
//     const styleContext = user.userStyle.writings.length > 0 ?
//       `\n\nUser style (tone: ${user.userStyle.tone}, words: ${Array.from(user.userStyle.vocabulary).slice(-5).join(', ')}):\n${user.userStyle.writings.slice(-3).map(w => `- "${w.text}"`).join('\n')}` : '';
//
//     const modes = [
//       'tweet-viral', 'critique-constructive', 'thread-twitter', 'reformulation-simple',
//       'angle-contrarian', 'storytelling', 'question-provocante', 'metaphore-creative', 'style-personnel',
//     ];
//
//     const modePrompts = {
//       'tweet-viral': `Generate a viral tweet based on: "${userComment}". Secondary context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
//       'critique-constructive': `Generate a constructive critique tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
//       'thread-twitter': `Generate the first tweet of a thread based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
//       'reformulation-simple': `Generate a simple reformulation tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
//       'angle-contrarian': `Generate a contrarian angle tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
//       'storytelling': `Generate a storytelling tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
//       'question-provocante': `Generate a provocative question tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
//       'metaphore-creative': `Generate a creative metaphor tweet for: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
//       'style-personnel': `Generate a personal style tweet based on: "${userComment}". Style (tone: ${user.userStyle.tone}, words: ${Array.from(user.userStyle.vocabulary).slice(-5).join(', ')}). Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
//     };
//
//     const filteredModes = modeFilter && modes.includes(modeFilter) ? [modeFilter] : modes;
//     const prompts = filteredModes.map(mode => modePrompts[mode]);
//
//     user.userStyle.writings.push({ text: userComment.trim(), timestamp: new Date() });
//     user.userStyle.tone = detectTone(userComment.trim());
//     user.userStyle.styleProgress = Math.min(user.userStyle.styleProgress + 1, 10000);
//     user.userStyle.lastModified = new Date();
//
//     if (user.userStyle.writings.length > 50) {
//       user.userStyle.writings = user.userStyle.writings.slice(-50);
//     }
//
//     const promises = prompts.map(async (prompt, index) => {
//       try {
//         const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
//           messages: [
//             {
//               role: 'system',
//               content: 'Tweet expert. Generate original tweets based on user comment. Secondary context: original tweet. Max 280 chars, no hashtags/emojis. Respond only with the tweet',
//             },
//             { role: 'user', content: prompt },
//           ],
//           model: 'llama3-8b-8192',
//           temperature: 0.7,
//           max_tokens: 100,
//         });
//
//         const tweet = response.data.choices[0].message.content.trim();
//         if (tweet.length > 280) {
//           console.warn(`⚠️ Tweet trop long pour mode ${filteredModes[index]}: ${tweet.length} chars`);
//           return { success: false, tweet: tweet.substring(0, 280), mode: filteredModes[index], error: 'Tweet trop long' };
//         }
//         return { success: true, tweet, mode: filteredModes[index] };
//       } catch (error) {
//         console.error(`❌ Erreur mode ${filteredModes[index]}:`, error.message, error.stack);
//         return {
//           success: false,
//           tweet: `Erreur: Échec génération pour ${filteredModes[index]}`,
//           mode: filteredModes[index],
//           error: error.message,
//         };
//       }
//     });
//
//     const results = await Promise.all(promises);
//     const generatedTweets = results.map(r => r.tweet);
//     const usedModes = results.map(r => r.mode);
//
//     const tweetData = {
//       id: uuidv4(),
//       timestamp: new Date(),
//       lastModified: new Date(),
//       originalTweet: originalTweet || null,
//       userComment: userComment.trim(),
//       context: context || null,
//       generatedTweets,
//       modesUsed: usedModes,
//       used: false,
//     };
//
//     user.generatedTweetsHistory.push(tweetData);
//     if (user.generatedTweetsHistory.length > 100) {
//       user.generatedTweetsHistory = user.generatedTweetsHistory.slice(-100);
//     }
//
//     await saveUserData(uid);
//
//     console.log(`✅ Tweets générés pour ${uid}: ${generatedTweets.length}`);
//     res.json({
//       success: true,
//       data: tweetData,
//       lastModified: tweetData.lastModified,
//     });
//   } catch (error) {
//     console.error(`❌ Erreur génération tweets pour ${req.user.uid}:`, error.message, error.stack);
//     res.status(500).json({
//       success: false,
//       error: 'Erreur génération tweets',
//       details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
//     });
//   }
// });
//
// // Route to regenerate a tweet
// app.post('/api/regenerate-tweet', async (req, res) => {
//   try {
//     const { tweetId, tweetIndex, mode } = req.body;
//     const uid = req.user.uid;
//     await initializeUserData(uid);
//     const user = userData.get(uid);
//
//     if (!tweetId || tweetIndex === undefined || !mode) {
//       return res.status(400).json({ success: false, error: 'tweetId, tweetIndex et mode requis' });
//     }
//
//     const tweetGroup = user.generatedTweetsHistory.find(t => t.id === tweetId);
//     if (!tweetGroup) {
//       return res.status(404).json({ success: false, error: 'Groupe tweets non trouvé' });
//     }
//
//     if (!Number.isInteger(parseInt(tweetIndex)) || tweetIndex < 0 || tweetIndex >= tweetGroup.generatedTweets.length) {
//       return res.status(400).json({ success: false, error: 'Index tweet invalide' });
//     }
//
//     const styleContext = user.userStyle.writings.length > 0 ?
//       `\n\nUser style (tone: ${user.userStyle.tone}, words: ${Array.from(user.userStyle.vocabulary).slice(-5).join(', ')}):\n${user.userStyle.writings.slice(-3).map(w => `- "${w.text}"`).join('\n')}` : '';
//
//     const modePrompts = {
//       'tweet-viral': `Generate a viral tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
//       'critique-constructive': `Generate a constructive critique tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
//       'thread-twitter': `Generate the first tweet of a thread based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
//       'reformulation-simple': `Generate a simple reformulation tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
//       'angle-contrarian': `Generate a contrarian angle tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
//       'storytelling': `Generate a storytelling tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
//       'question-provocante': `Generate a provocative question tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
//       'metaphore-creative': `Generate a creative metaphor tweet for: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
//       'style-personnel': `Generate a personal style tweet based on: "${tweetGroup.userComment}". Style (tone: ${user.userStyle.tone}, words: ${Array.from(user.userStyle.vocabulary).slice(-5).join(', ')}). Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
//     };
//
//     const prompt = modePrompts[mode];
//     if (!prompt) {
//       return res.status(400).json({ success: false, error: 'Mode invalide' });
//     }
//
//     const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
//       messages: [
//         {
//           role: 'system',
//           content: 'Tweet expert. Generate original tweets based on user comment. Secondary context: original tweet. Max 280 chars, no hashtags/emojis. Respond only with the tweet',
//         },
//         { role: 'user', content: prompt },
//       ],
//       model: 'llama3-8b-8192',
//       temperature: 0.7,
//       max_tokens: 100,
//     });
//
//     const newTweet = response.data.choices[0].message.content.trim();
//     if (newTweet.length > 280) {
//       console.warn(`⚠️ Tweet régénéré trop long: ${newTweet.length} chars`);
//       return res.status(400).json({ success: false, error: 'Tweet régénéré dépasse 280 chars' });
//     }
//
//     tweetGroup.generatedTweets[tweetIndex] = newTweet;
//     tweetGroup.modesUsed[tweetIndex] = mode;
//     tweetGroup.lastModified = new Date();
//
//     const scheduledTweet = user.scheduledTweets.find(t => t.tweetId === tweetId && t.tweetIndex === parseInt(tweetIndex));
//     if (scheduledTweet) {
//       scheduledTweet.content = newTweet;
//       scheduledTweet.lastModified = new Date();
//     }
//
//     await saveUserData(uid);
//
//     res.json({
//       success: true,
//       data: { tweet: newTweet, mode, lastModified: tweetGroup.lastModified },
//     });
//   } catch (error) {
//     console.error(`❌ Erreur régénération tweet pour ${req.user.uid}:`, error.message, error.stack);
//     res.status(500).json({
//       success: false,
//       error: 'Erreur régénération tweet',
//       details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
//     });
//   }
// });
//
// // Route to learn about ragebait or viral content
// app.post('/api/learn-content', async (req, res) => {
//   try {
//     const { type } = req.body;
//
//     if (!['ragebait', 'viral'].includes(type)) {
//       return res.status(400).json({ success: false, error: 'Type contenu invalide' });
//     }
//
//     const prompt = type === 'ragebait' ?
//       'Explain ragebait, how it works on social media, 3 example ragebait tweets. In French, max 500 chars.' :
//       'Explain viral content on social media, 3 example viral tweets. In French, max 500 chars.';
//
//     const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
//       messages: [
//         { role: 'system', content: 'Social media expert. Concise explanation, examples in French, respect char limit.' },
//         { role: 'user', content: prompt },
//       ],
//       model: 'llama3-8b-8192',
//       temperature: 0.7,
//       max_tokens: 200,
//     });
//
//     const content = response.data.choices[0].message.content.trim();
//     res.json({ success: true, data: content });
//   } catch (error) {
//     console.error(`❌ Erreur info contenu pour ${req.user.uid}:`, error.message, error.stack);
//     res.status(500).json({
//       success: false,
//       error: 'Erreur récupération info contenu',
//       details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
//     });
//   }
// });
//
// // Route to get tweets history
// app.get('/api/tweets-history', async (req, res) => {
//   try {
//     const uid = req.user.uid;
//     await initializeUserData(uid);
//     const user = userData.get(uid);
//
//     const data = user.generatedTweetsHistory.slice(-30).reverse().map(group => ({
//       ...group,
//       generatedTweets: group.generatedTweets || [],
//       modesUsed: group.modesUsed || [],
//       timestamp: new Date(group.timestamp),
//       lastModified: new Date(group.lastModified),
//     }));
//     const etag = generateETag(data);
//     if (req.get('If-None-Match') === etag) {
//       return res.status(304).send();
//     }
//     res.set('ETag', etag);
//     res.json({
//       success: true,
//       data,
//       lastModified: data[0]?.lastModified || new Date(),
//     });
//   } catch (error) {
//     console.error(`❌ Erreur historique tweets pour ${req.user.uid}:`, error.message, error.stack);
//     res.status(500).json({
//       success: false,
//       error: 'Erreur récupération historique',
//       details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
//     });
//   }
// });
//
// // Route to mark tweet as used
// app.post('/api/tweet-used', async (req, res) => {
//   try {
//     const { tweetId } = req.body;
//     const uid = req.user.uid;
//     await initializeUserData(uid);
//     const user = userData.get(uid);
//
//     if (!tweetId) {
//       return res.status(400).json({ success: false, error: 'tweetId requis' });
//     }
//
//     const tweetGroup = user.generatedTweetsHistory.find(t => t.id === tweetId);
//     if (!tweetGroup) {
//       return res.status(404).json({ success: false, error: 'Tweet non trouvé' });
//     }
//
//     tweetGroup.used = true;
//     tweetGroup.used_at = new Date();
//     tweetGroup.lastModified = new Date();
//     await saveUserData(uid);
//
//     res.json({
//       success: true,
//       message: 'Tweet marqué utilisé',
//       data: { lastModified: tweetGroup.lastModified },
//     });
//   } catch (error) {
//     console.error(`❌ Erreur mise à jour tweet pour ${req.user.uid}:`, error.message, error.stack);
//     res.status(500).json({
//       success: false,
//       error: 'Erreur mise à jour tweet',
//       details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
//     });
//   }
// });
//
// // Route to edit a tweet
// app.post('/api/edit-tweet', async (req, res) => {
//   try {
//     const { tweetId, tweetIndex, newText } = req.body;
//     const uid = req.user.uid;
//     await initializeUserData(uid);
//     const user = userData.get(uid);
//
//     if (!tweetId || tweetIndex === undefined || !newText) {
//       return res.status(400).json({ success: false, error: 'tweetId, tweetIndex et newText requis' });
//     }
//
//     const trimmedText = newText.trim();
//     if (trimmedText === '') {
//       return res.status(400).json({ success: false, error: 'Texte vide non autorisé' });
//     }
//
//     if (trimmedText.length > 280) {
//       return res.status(400).json({ success: false, error: 'Tweet dépasse 280 chars' });
//     }
//
//     const tweetGroup = user.generatedTweetsHistory.find(t => t.id === tweetId);
//     if (!tweetGroup) {
//       return res.status(404).json({ success: false, error: 'Groupe tweets non trouvé' });
//     }
//
//     if (!Number.isInteger(parseInt(tweetIndex)) || tweetIndex < 0 || tweetIndex >= tweetGroup.generatedTweets.length) {
//       return res.status(400).json({ success: false, error: 'Index tweet invalide' });
//     }
//
//     console.log(`📝 Modification tweet ${tweetId}[${tweetIndex}] pour ${uid}: "${tweetGroup.generatedTweets[tweetIndex]}" → "${trimmedText}"`);
//
//     user.userStyle.writings.push({ text: trimmedText, timestamp: new Date() });
//     const words = trimmedText.toLowerCase().match(/\b\w+\b/g) || [];
//     words.forEach(word => user.userStyle.vocabulary.add(word));
//     user.userStyle.tone = detectTone(trimmedText);
//     user.userStyle.styleProgress = Math.min(user.userStyle.styleProgress + 1, 10000);
//     user.userStyle.lastModified = new Date();
//
//     if (user.userStyle.writings.length > 50) {
//       user.userStyle.writings = user.userStyle.writings.slice(-50);
//     }
//
//     tweetGroup.generatedTweets[tweetIndex] = trimmedText;
//     tweetGroup.lastModified = new Date();
//
//     const scheduledTweet = user.scheduledTweets.find(t => t.tweetId === tweetId && t.tweetIndex === parseInt(tweetIndex));
//     if (scheduledTweet) {
//       scheduledTweet.content = trimmedText;
//       scheduledTweet.lastModified = new Date();
//     }
//
//     await saveUserData(uid);
//
//     res.json({
//       success: true,
//       message: 'Tweet modifié',
//       data: {
//         tweet: trimmedText,
//         index: parseInt(tweetIndex),
//         lastModified: tweetGroup.lastModified,
//         styleProgress: user.userStyle.styleProgress,
//       },
//     });
//   } catch (error) {
//     console.error(`❌ Erreur modification tweet pour ${req.user.uid}:`, error.message, error.stack);
//     res.status(500).json({
//       success: false,
//       error: 'Erreur modification tweet',
//       details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
//     });
//   }
// });
//
// // Route to schedule a tweet
// app.post('/api/schedule-tweet', upload.array('media', 4), async (req, res) => {
//   try {
//     const { content, datetime, tweetId, tweetIndex } = req.body;
//     const uid = req.user.uid;
//     await initializeUserData(uid);
//     const user = userData.get(uid);
//
//     if (!user.twitterClient) {
//       return res.status(403).json({ success: false, error: 'Compte Twitter non authentifié' });
//     }
//
//     if (!content || !datetime || !tweetId || tweetIndex === undefined) {
//       return res.status(400).json({ success: false, error: 'content, datetime, tweetId et tweetIndex requis' });
//     }
//
//     const trimmedContent = content.trim();
//     if (trimmedContent === '') {
//       return res.status(400).json({ success: false, error: 'Contenu vide non autorisé' });
//     }
//
//     if (trimmedContent.length > 280) {
//       return res.status(400).json({ success: false, error: 'Tweet dépasse 280 chars' });
//     }
//
//     const scheduleDate = new Date(datetime);
//     if (isNaN(scheduleDate.getTime())) {
//       return res.status(400).json({ success: false, error: 'Date/heure invalide' });
//     }
//
//     const now = new Date();
//     if (scheduleDate <= now) {
//       return res.status(400).json({ success: false, error: 'Date doit être future' });
//     }
//
//     const tweetGroup = user.generatedTweetsHistory.find(t => t.id === tweetId);
//     if (!tweetGroup) {
//       return res.status(404).json({ success: false, error: 'Groupe tweets non trouvé' });
//     }
//
//     if (!Number.isInteger(parseInt(tweetIndex)) || parseInt(tweetIndex) < 0 || parseInt(tweetIndex) >= tweetGroup.generatedTweets.length) {
//       return res.status(400).json({ success: false, error: 'Index tweet invalide' });
//     }
//
//     const media = req.files ? req.files.map(file => ({
//       id: uuidv4(),
//       filename: file.filename,
//       originalName: file.originalname,
//       path: file.path,
//       url: `http://localhost:${PORT}/Uploads/${uid}/${file.filename}`,
//       mimetype: file.mimetype,
//       type: file.mimetype.startsWith('image/') ? 'image' : 'video',
//     })) : [];
//
//     const tweet = {
//       id: tweetIdCounters.get(uid)++,
//       content: trimmedContent,
//       datetime: scheduleDate,
//       createdAt: new Date(),
//       lastModified: new Date(),
//       media,
//       status: 'scheduled',
//       tweetId,
//       tweetIndex: parseInt(tweetIndex),
//     };
//
//     const existingIndex = user.scheduledTweets.findIndex(t => t.tweetId === tweetId && t.tweetIndex === parseInt(tweetIndex));
//     if (existingIndex !== -1) {
//       const oldTweet = user.scheduledTweets[existingIndex];
//       user.scheduledTweets.splice(existingIndex, 1);
//       if (oldTweet.media && oldTweet.media.length > 0) {
//         for (const media of oldTweet.media) {
//           try {
//             const filePath = path.join(__dirname, 'Uploads', uid, media.filename);
//             if (await fs.access(filePath).then(() => true).catch(() => false)) {
//               await fs.unlink(filePath);
//               console.log(`✅ Fichier média supprimé: ${media.filename}`);
//             }
//           } catch (err) {
//             console.warn(`⚠️ Erreur suppression fichier ${media.filename}:`, err.message);
//           }
//         }
//       }
//     }
//
//     user.scheduledTweets.push(tweet);
//     await saveUserData(uid);
//
//     console.log(`✅ Tweet programmé pour ${uid}:`, {
//       id: tweet.id,
//       content: trimmedContent.substring(0, 50) + '...',
//       datetime: scheduleDate.toLocaleString(),
//       mediaCount: media.length,
//     });
//
//     res.json({
//       success: true,
//       tweet: {
//         ...tweet,
//         media: media.map(m => ({
//           id: m.id,
//           filename: m.filename,
//           originalName: m.originalName,
//           url: m.url,
//           mimetype: m.mimetype,
//           type: m.type,
//         })),
//       },
//     });
//   } catch (error) {
//     console.error(`❌ Erreur programmation tweet pour ${req.user.uid}:`, error.message, error.stack);
//     res.status(500).json({
//       success: false,
//       error: 'Erreur programmation tweet',
//       details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
//     });
//   }
// });
//
// // Route to get all scheduled tweets
// app.get('/api/tweets', async (req, res) => {
//   try {
//     const uid = req.user.uid;
//     await initializeUserData(uid);
//     const user = userData.get(uid);
//
//     const data = user.scheduledTweets.map(tweet => ({
//       ...tweet,
//       media: (tweet.media || []).map(media => ({
//         id: media.id,
//         filename: media.filename,
//         originalName: media.originalName,
//         url: media.url || `http://localhost:${PORT}/Uploads/${uid}/${media.filename}`,
//         mimetype: media.mimetype || 'application/octet-stream',
//         type: media.type || (media.mimetype && media.mimetype.startsWith('image/') ? 'image' : 'video'),
//       })),
//     }));
//     const etag = generateETag(data);
//     if (req.get('If-None-Match') === etag) {
//       return res.status(304).send();
//     }
//     res.set('ETag', etag);
//     res.json(data);
//   } catch (error) {
//     console.error(`❌ Erreur récupération tweets programmés pour ${req.user.uid}:`, error.message, error.stack);
//     res.status(500).json({
//       success: false,
//       error: 'Erreur récupération tweets programmés',
//       details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
//     });
//   }
// });
//
// // Route to delete a scheduled tweet
// app.delete('/api/tweets/:id', async (req, res) => {
//   try {
//     const { id } = req.params;
//     const uid = req.user.uid;
//     await initializeUserData(uid);
//     const user = userData.get(uid);
//
//     const tweetIndex = user.scheduledTweets.findIndex(t => t.id === parseInt(id));
//     if (tweetIndex === -1) {
//       return res.status(404).json({ success: false, error: 'Tweet programmé non trouvé' });
//     }
//
//     const tweet = user.scheduledTweets[tweetIndex];
//     if (tweet.media && tweet.media.length > 0) {
//       for (const media of tweet.media) {
//         try {
//           const filePath = path.join(__dirname, 'Uploads', uid, media.filename);
//           if (await fs.access(filePath).then(() => true).catch(() => false)) {
//             await fs.unlink(filePath);
//             console.log(`✅ Fichier média supprimé: ${media.filename}`);
//           }
//         } catch (err) {
//           console.warn(`⚠️ Erreur suppression fichier ${media.filename}:`, err.message);
//         }
//       }
//     }
//
//     user.scheduledTweets.splice(tweetIndex, 1);
//     await saveUserData(uid);
//
//     console.log(`🗑️ Tweet programmé supprimé pour ${uid}:`, id);
//     res.json({
//       success: true,
//       message: 'Tweet programmé supprimé',
//     });
//   } catch (error) {
//     console.error(`❌ Erreur suppression tweet programmé pour ${req.user.uid}:`, error.message, error.stack);
//     res.status(500).json({
//       success: false,
//       error: 'Erreur suppression tweet programmé',
//       details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
//     });
//   }
// });
//
// // Route to delete a tweet from history
// app.post('/api/delete-tweet', async (req, res) => {
//   try {
//     const { tweetId, tweetIndex } = req.body;
//     const uid = req.user.uid;
//     await initializeUserData(uid);
//     const user = userData.get(uid);
//
//     if (!tweetId || tweetIndex === undefined) {
//       return res.status(400).json({ success: false, error: 'tweetId et tweetIndex requis' });
//     }
//
//     const tweetGroup = user.generatedTweetsHistory.find(t => t.id === tweetId);
//     if (!tweetGroup) {
//       return res.status(404).json({ success: false, error: 'Groupe tweets non trouvé' });
//     }
//
//     if (!Number.isInteger(parseInt(tweetIndex)) || tweetIndex < 0 || tweetIndex >= tweetGroup.generatedTweets.length) {
//       return res.status(400).json({ success: false, error: 'Index tweet invalide' });
//     }
//
//     const scheduledTweetIndex = user.scheduledTweets.findIndex(t => t.tweetId === tweetId && t.tweetIndex === parseInt(tweetIndex));
//     if (scheduledTweetIndex !== -1) {
//       const tweet = user.scheduledTweets[scheduledTweetIndex];
//       if (tweet.media && tweet.media.length > 0) {
//         for (const media of tweet.media) {
//           try {
//             const filePath = path.join(__dirname, 'Uploads', uid, media.filename);
//             if (await fs.access(filePath).then(() => true).catch(() => false)) {
//               await fs.unlink(filePath);
//               console.log(`✅ Fichier média supprimé: ${media.filename}`);
//             }
//           } catch (err) {
//             console.warn(`⚠️ Erreur suppression fichier ${media.filename}:`, err.message);
//           }
//         }
//       }
//       user.scheduledTweets.splice(scheduledTweetIndex, 1);
//     }
//
//     tweetGroup.generatedTweets.splice(tweetIndex, 1);
//     tweetGroup.modesUsed.splice(tweetIndex, 1);
//     tweetGroup.lastModified = new Date();
//
//     if (tweetGroup.generatedTweets.length === 0) {
//       user.generatedTweetsHistory = user.generatedTweetsHistory.filter(t => t.id !== tweetId);
//     }
//
//     await saveUserData(uid);
//
//     res.json({
//       success: true,
//       message: 'Tweet supprimé',
//       data: {
//         remainingCount: tweetGroup.generatedTweets.length,
//         lastModified: tweetGroup.lastModified,
//       },
//     });
//   } catch (error) {
//     console.error(`❌ Erreur suppression tweet pour ${req.user.uid}:`, error.message, error.stack);
//     res.status(500).json({
//       success: false,
//       error: 'Erreur suppression tweet',
//       details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
//     });
//   }
// });
//
// // Route to publish a scheduled tweet immediately
// app.post('/api/tweets/:id/publish', async (req, res) => {
//   try {
//     const { id } = req.params;
//     const { content } = req.body;
//     const uid = req.user.uid;
//     await initializeUserData(uid);
//     const user = userData.get(uid);
//
//     if (!user.twitterClient) {
//       return res.status(403).json({ success: false, error: 'Compte Twitter non authentifié' });
//     }
//
//     const tweet = user.scheduledTweets.find(t => t.id === parseInt(id));
//     if (!tweet) {
//       return res.status(404).json({ success: false, error: 'Tweet programmé non trouvé' });
//     }
//
//     if (tweet.status !== 'scheduled') {
//       return res.status(400).json({ success: false, error: 'Tweet non programmé' });
//     }
//
//     const result = await publishTweetToTwitter(tweet, content || tweet.content, uid);
//
//     tweet.status = 'published';
//     tweet.publishedAt = new Date();
//     tweet.twitterId = result.data.id;
//     tweet.lastModified = new Date();
//     await saveUserData(uid);
//
//     console.log(`✅ Tweet publié manuellement pour ${uid}:`, tweet.id);
//
//     res.json({
//       success: true,
//       message: 'Tweet publié',
//       result: result.data,
//     });
//   } catch (error) {
//     console.error(`❌ Erreur publication tweet pour ${req.user.uid}:`, error.message, error.stack);
//     const user = userData.get(req.user.uid);
//     const tweet = user.scheduledTweets.find(t => t.id === parseInt(req.params.id));
//     if (tweet) {
//       tweet.status = 'failed';
//       tweet.error = error.message;
//       tweet.lastModified = new Date();
//       tweet.failedAt = new Date();
//       await saveUserData(req.user.uid);
//     }
//
//     res.status(error.code === 429 ? 429 : 500).json({
//       success: false,
//       error: 'Erreur publication tweet',
//       details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
//     });
//   }
// });
//
// // Function to publish tweet to Twitter with retry logic
// async function publishTweetToTwitter(tweet, content, uid) {
//   const maxRetries = 3;
//   let retryCount = 0;
//   const user = userData.get(uid);
//   const twitterClient = user.twitterClient;
//
//   if (!twitterClient) {
//     throw new Error('Aucun client Twitter disponible pour l\'utilisateur');
//   }
//
//   async function attemptPublish() {
//     try {
//       console.log(`🚀 Publication du tweet ${tweet.id} pour ${uid}`);
//
//       let mediaIds = [];
//       if (tweet.media && tweet.media.length > 0) {
//         console.log('📎 Upload des médias...');
//         for (const media of tweet.media) {
//           const filePath = path.join(__dirname, 'Uploads', uid, media.filename);
//           try {
//             await fs.access(filePath);
//             const mediaId = await twitterClient.v1.uploadMedia(filePath, {
//               mimeType: media.mimetype,
//             });
//             mediaIds.push(mediaId);
//             console.log(`✅ Média uploadé: ${media.filename}`);
//           } catch (fileError) {
//             console.warn(`⚠️ Fichier média introuvable, ignoré: ${media.filename}`);
//           }
//         }
//       }
//
//       const tweetOptions = { text: content };
//       if (mediaIds.length > 0) {
//         tweetOptions.media = { media_ids: mediaIds };
//       }
//
//       const result = await twitterClient.v2.tweet(tweetOptions);
//
//       console.log(`✅ Tweet publié avec succès: ${result.data.id}`);
//
//       if (tweet.media && tweet.media.length > 0) {
//         for (const media of tweet.media) {
//           try {
//             const filePath = path.join(__dirname, 'Uploads', uid, media.filename);
//             if (await fs.access(filePath).then(() => true).catch(() => false)) {
//               await fs.unlink(filePath);
//               console.log(`✅ Fichier média supprimé: ${media.filename}`);
//             }
//           } catch (err) {
//             console.warn(`⚠️ Erreur suppression fichier ${media.filename}:`, err.message);
//           }
//         }
//       }
//
//       return result;
//     } catch (error) {
//       if (error.code === 429 && retryCount < maxRetries) {
//         retryCount++;
//         const waitTime = Math.pow(2, retryCount) * 1000;
//         console.log(`⚠️ Limite de taux atteinte, nouvelle tentative dans ${waitTime/1000}s (tentative ${retryCount}/${maxRetries})`);
//         await new Promise(resolve => setTimeout(resolve, waitTime));
//         return attemptPublish();
//       }
//       console.error(`❌ Erreur publication Twitter pour ${uid}:`, error.message, error.stack);
//       throw error;
//     }
//   }
//
//   return attemptPublish();
// }
//
// // Schedule checker for publishing tweets
// function startScheduleChecker() {
//   console.log('⏰ Démarrage du vérificateur de tweets programmés...');
//
//   const checkInterval = setInterval(async () => {
//     try {
//       const now = new Date();
//       console.log(`🔍 Vérification des tweets programmés à ${now.toLocaleString()}`);
//
//       for (const [uid, user] of userData) {
//         if (!user.twitterClient) {
//           continue; // Skip users without Twitter authentication
//         }
//
//         const tweetsToPublish = user.scheduledTweets.filter(tweet =>
//           tweet.status === 'scheduled' && new Date(tweet.datetime) <= now
//         );
//
//         if (tweetsToPublish.length === 0) {
//           continue;
//         }
//
//         console.log(`📝 ${tweetsToPublish.length} tweet(s) à publier pour ${uid}`);
//
//         for (const tweet of tweetsToPublish) {
//           try {
//             console.log(`🚀 Tentative de publication du tweet ${tweet.id} pour ${uid}: "${tweet.content.substring(0, 50)}..."`);
//
//             const result = await publishTweetToTwitter(tweet, tweet.content, uid);
//
//             tweet.status = 'published';
//             tweet.publishedAt = new Date();
//             tweet.twitterId = result.data.id;
//             tweet.lastModified = new Date();
//
//             console.log(`✅ Tweet ${tweet.id} publié avec succès pour ${uid}: ${result.data.id}`);
//           } catch (error) {
//             console.error(`❌ Erreur publication tweet ${tweet.id} pour ${uid}:`, error.message, error.stack);
//             tweet.status = 'failed';
//             tweet.error = error.message;
//             tweet.lastModified = new Date();
//             tweet.failedAt = new Date();
//           }
//         }
//
//         await saveUserData(uid);
//       }
//     } catch (error) {
//       console.error('❌ Erreur dans le vérificateur de tweets:', error.message, error.stack);
//     }
//   }, 15000);
//
//   process.scheduleChecker = checkInterval;
// }
//
// // Route for web interface
// app.get('/', async (req, res) => {
//   const authHeader = req.headers.authorization;
//   let uid = 'anonymous';
//   if (authHeader && authHeader.startsWith('Bearer ')) {
//     try {
//       const idToken = authHeader.split('Bearer ')[1];
//       const decodedToken = await admin.auth().verifyIdToken(idToken);
//       uid = decodedToken.uid;
//       await initializeUserData(uid);
//     } catch (error) {
//       console.error('❌ Erreur vérification token pour /:', error.message, error.stack);
//     }
//   }
//
//   const html = await fs.readFile(path.join(__dirname, 'public', 'index.html'), 'utf8');
//   const modifiedHtml = html.replace(
//     '<!-- UID_PLACEHOLDER -->',
//     `<script>window.__USER_UID__ = "${uid}";</script>`
//   );
//   res.send(modifiedHtml);
// });
//
// // Route for health check
// app.get('/health', async (req, res) => {
//   const uid = req.user?.uid || 'anonymous';
//   await initializeUserData(uid);
//   const user = userData.get(uid) || { generatedTweetsHistory: [], scheduledTweets: [], userStyle: { writings: [], styleProgress: 0 } };
//
//   res.json({
//     status: 'OK',
//     timestamp: new Date(),
//     version: '2.2.3',
//     tweetsCount: user.generatedTweetsHistory.length,
//     scheduledTweetsCount: user.scheduledTweets.length,
//     scheduledActiveCount: user.scheduledTweets.filter(t => t.status === 'scheduled').length,
//     publishedCount: user.scheduledTweets.filter(t => t.status === 'published').length,
//     failedCount: user.scheduledTweets.filter(t => t.status === 'failed').length,
//     userStyleWritings: user.userStyle.writings.length,
//     styleProgress: user.userStyle.styleProgress,
//     userId: uid,
//     twitterAuthenticated: !!user.twitterClient,
//   });
// });
//
// // Error handling middleware
// app.use((error, req, res, next) => {
//   console.error(`❌ Erreur globale pour ${req.user?.uid || 'anonymous'}:`, error.message, error.stack);
//   res.status(error.message.includes('Type de fichier non supporté') ? 400 : 500).json({
//     success: false,
//     error: error.message.includes('Type de fichier non supporté') ? error.message : 'Erreur serveur interne',
//     details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
//   });
// });
//
// // Initialize data and start server
// async function startServer() {
//   try {
//     console.log('🔄 Initialisation du serveur...');
//     startScheduleChecker();
//
//     app.listen(PORT, '0.0.0.0', () => {
//       console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`);
//       console.log(`📊 Interface web: http://localhost:${PORT}`);
//       console.log(`🔄 API endpoints disponibles:`);
//       console.log(`   - GET  /api/twitter-auth`);
//       console.log(`   - GET  /api/twitter-callback`);
//       console.log(`   - GET  /api/extension-login`);
//       console.log(`   - POST /api/login`);
//       console.log(`   - POST /api/learn-style`);
//       console.log(`   - POST /api/generate-tweets`);
//       console.log(`   - POST /api/regenerate-tweet`);
//       console.log(`   - POST /api/learn-content`);
//       console.log(`   - GET  /api/tweets-history`);
//       console.log(`   - POST /api/tweet-used`);
//       console.log(`   - POST /api/edit-tweet`);
//       console.log(`   - POST /api/schedule-tweet`);
//       console.log(`   - GET  /api/tweets`);
//       console.log(`   - DELETE /api/tweets/:id`);
//       console.log(`   - POST /api/tweets/:id/publish`);
//       console.log(`   - GET  /health`);
//       console.log(`✅ Serveur prêt!`);
//     });
//   } catch (error) {
//     console.error('❌ Erreur lors du démarrage du serveur:', error.message, error.stack);
//     process.exit(1);
//   }
// }
//
// // Graceful shutdown
// process.on('SIGINT', async () => {
//   console.log('\n👋 Arrêt gracieux du serveur...');
//   if (process.scheduleChecker) {
//     clearInterval(process.scheduleChecker);
//     console.log('⏰ Vérificateur de tweets arrêté');
//   }
//   for (const uid of userData.keys()) {
//     await saveUserData(uid);
//   }
//   console.log('💾 Données sauvegardées');
//   console.log('✅ Serveur arrêté proprement');
//   process.exit(0);
// });
//
// process.on('SIGTERM', async () => {
//   console.log('\n👋 Signal SIGTERM reçu, arrêt du serveur...');
//   if (process.scheduleChecker) {
//     clearInterval(process.scheduleChecker);
//   }
//   for (const uid of userData.keys()) {
//     await saveUserData(uid);
//   }
//   process.exit(0);
// });
//
// // Start the server
// startServer();*/




/*

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
const session = require('express-session');
const passport = require('passport');
const TwitterStrategy = require('passport-twitter').Strategy;
require('dotenv').config();

// Initialisation de l'application Express
const app = express();
const PORT = process.env.PORT || 3000;

// Initialisation de Firebase Admin SDK
// Utilisé pour vérifier les tokens Firebase et gérer les sessions utilisateur
try {
  const serviceAccount = require('./firebase-service-account.json');
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
  console.log('✅ Firebase Admin initialisé');
} catch (error) {
  console.error('❌ Erreur initialisation Firebase Admin:', error.message, error.stack);
  process.exit(1);
}

// Configuration des middlewares
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://127.0.0.1:8080', 'https://x.com'],
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'If-None-Match', 'Authorization', 'X-User-ID', 'Accept', 'Origin', 'X-Requested-With'],
  credentials: true,
}));
app.use(express.json());

// Middleware de session pour Passport
app.use(session({
  secret: process.env.SESSION_SECRET || 'your_session_secret', // Utilisez une clé secrète forte depuis .env
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // true en production pour HTTPS
    maxAge: 24 * 60 * 60 * 1000, // 24 heures
  }
}));

// Initialisation de Passport
app.use(passport.initialize());
app.use(passport.session());

// Configuration de la stratégie Twitter pour Passport
passport.use(new TwitterStrategy({
  consumerKey: process.env.TWITTER_CONSUMER_KEY,
  consumerSecret: process.env.TWITTER_CONSUMER_SECRET,
  callbackURL: 'http://localhost:3000/auth/twitter/callback',
  includeEmail: true, // Optionnel, si vous voulez l'email
}, async (token, tokenSecret, profile, done) => {
  try {
    // Ici, vous pouvez créer ou trouver l'utilisateur dans votre base de données
    // Pour cet exemple, on utilise le profile Twitter comme utilisateur
    const user = {
      id: profile.id,
      username: profile.username,
      displayName: profile.displayName,
      profilePicture: profile.photos ? profile.photos[0].value : null,
      twitterToken: token,
      twitterTokenSecret: tokenSecret,
    };

    // Associez à Firebase si nécessaire, ou stockez dans votre Map userData
    // Pour simplifier, on retourne l'utilisateur
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

// Sérialisation de l'utilisateur pour la session
passport.serializeUser((user, done) => {
  done(null, user.id); // Sérialise uniquement l'ID
});

// Désérialisation de l'utilisateur depuis la session
passport.deserializeUser((id, done) => {
  // Récupérez l'utilisateur depuis votre base de données ou Map par ID
  // Pour cet exemple, supposons que vous avez une fonction findUserById
  findUserById(id, (err, user) => {
    done(err, user);
  });
});

// Fonction placeholder pour findUserById (adaptez à votre stockage)
function findUserById(id, callback) {
  // Exemple: Cherchez dans userData ou une DB
  for (const [uid, user] of userData) {
    if (user.id === id) {
      return callback(null, user);
    }
  }
  callback(new Error('User not found'));
}

// Middleware pour vérifier le token Firebase
async function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('❌ Aucun ou mauvais en-tête Authorization', { path: req.path, authHeader });
    return res.status(401).json({ success: false, error: 'Aucun ou mauvais en-tête Authorization' });
  }

  const idToken = authHeader.split('Bearer ')[1];
  try {
    console.log(`🔍 Vérification token pour ${req.path}: ${idToken.substring(0, 10)}...`);
    const decodedToken = await admin.auth().verifyIdToken(idToken, true);
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

// Route pour rafraîchir le token Firebase
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

// Route d'authentification Twitter
app.get('/auth/twitter', passport.authenticate('twitter', { scope: ['email'] }));

// Callback Twitter
app.get('/auth/twitter/callback',
  passport.authenticate('twitter', { failureRedirect: '/login' }),
  (req, res) => {
    // Rediriger et fermer la popup
    res.send(`<script>
      window.opener.postMessage({
        type: 'TF_LOGIN_SUCCESS',
        user: ${JSON.stringify(req.user)}
      }, '*');
      window.close();
    </script>`);
  }
);

// Statut d'authentification
app.get('/api/auth-status', (req, res) => {
  res.json({
    authenticated: !!req.user,
    user: req.user || null
  });
});

// Test d'authentification
app.get('/api/test-auth', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Non authentifié' });
  }
  res.json({ success: true, user: req.user });
});

// Route pour la déconnexion
app.post('/api/logout', verifyToken, async (req, res) => {
  try {
    const uid = req.user.uid;
    console.log(`🔍 Déconnexion pour UID: ${uid}`);
    await admin.auth().revokeRefreshTokens(uid);
    userData.delete(uid);
    tweetIdCounters.delete(uid);
    console.log(`✅ Déconnexion réussie pour UID: ${uid}`);
    res.json({ success: true, message: 'Déconnexion réussie' });
  } catch (error) {
    console.error(`❌ Erreur déconnexion pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({ success: false, error: 'Échec déconnexion', details: error.message });
  }
});

// Configuration de Multer pour l'upload de fichiers
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadPath = path.join(__dirname, 'Uploads', req.user.uid);
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

// Servir les fichiers statiques
app.use('/Uploads', express.static(path.join(__dirname, 'Uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// Clés API
const GROQ_API_KEY = process.env.GROQ_API_KEY || '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';

// Stockage des données utilisateur
const userData = new Map();
const tweetIdCounters = new Map();

// Chemins des fichiers pour la persistance des données utilisateur
function getUserFilePaths(uid) {
  return {
    userStyleFile: path.join(__dirname, 'data', uid, 'userStyle.json'),
    tweetsHistoryFile: path.join(__dirname, 'data', uid, 'tweetsHistory.json'),
    scheduledTweetsFile: path.join(__dirname, 'data', uid, 'scheduledTweets.json'),
    twitterTokensFile: path.join(__dirname, 'data', uid, 'twitterTokens.json'),
  };
}

// Initialisation des données utilisateur
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
      twitterUser: null, // Stocke username, handle, profile_picture
      dataLock: false,
      sessionStart: new Date(),
    });
    tweetIdCounters.set(uid, 1);

    const { userStyleFile, tweetsHistoryFile, scheduledTweetsFile, twitterTokensFile } = getUserFilePaths(uid);
    const userDir = path.dirname(userStyleFile);

    try {
      await fs.mkdir(userDir, { recursive: true });
      console.log(`✅ Dossier créé: ${userDir}`);
    } catch (error) {
      console.error(`❌ Erreur création dossier ${userDir}:`, error.message, error.stack);
      throw new Error(`Échec création dossier utilisateur: ${error.message}`);
    }

    try {
      const userStyleData = await fs.readFile(userStyleFile, 'utf8').catch(() => '{}');
      userData.get(uid).userStyle = {
        ...defaultUserStyle,
        ...JSON.parse(userStyleData, (key, value) => {
          if (key === 'vocabulary') return new Set(value);
          return value;
        }),
      };
      console.log(`✅ Loaded userStyle for user ${uid}`);
    } catch (error) {
      console.error(`❌ Erreur lecture ${userStyleFile}:`, error.message, error.stack);
    }

    try {
      const tweetsHistoryData = await fs.readFile(tweetsHistoryFile, 'utf8').catch(() => '[]');
      userData.get(uid).generatedTweetsHistory = JSON.parse(tweetsHistoryData);
      if (userData.get(uid).generatedTweetsHistory.length > 0) {
        const maxId = Math.max(...userData.get(uid).generatedTweetsHistory.map(t => parseInt(t.id) || 0));
        if (maxId >= tweetIdCounters.get(uid)) tweetIdCounters.set(uid, maxId + 1);
      }
      console.log(`✅ Loaded tweetsHistory for user ${uid}`);
    } catch (error) {
      console.error(`❌ Erreur lecture ${tweetsHistoryFile}:`, error.message, error.stack);
    }

    try {
      const scheduledTweetsData = await fs.readFile(scheduledTweetsFile, 'utf8').catch(() => '[]');
      userData.get(uid).scheduledTweets = JSON.parse(scheduledTweetsData, (key, value) => {
        if (key === 'datetime' || key === 'createdAt' || key === 'lastModified' || key === 'publishedAt' || key === 'failedAt') {
          return value ? new Date(value) : null;
        }
        return value;
      });
      if (userData.get(uid).scheduledTweets.length > 0) {
        const maxId = Math.max(...userData.get(uid).scheduledTweets.map(t => t.id || 0));
        if (maxId >= tweetIdCounters.get(uid)) tweetIdCounters.set(uid, maxId + 1);
      }
      console.log(`✅ Loaded scheduledTweets for user ${uid}`);
    } catch (error) {
      console.error(`❌ Erreur lecture ${scheduledTweetsFile}:`, error.message, error.stack);
    }

    try {
      const twitterTokensData = await fs.readFile(twitterTokensFile, 'utf8').catch(() => null);
      if (twitterTokensData) {
        const tokens = JSON.parse(twitterTokensData);
        const tokensObj = tokens.twitterTokens || tokens; // Compatibilité avec ancien format
        userData.get(uid).twitterTokens = tokensObj;
        userData.get(uid).twitterClient = new TwitterApi(tokensObj.access_token);
        userData.get(uid).twitterUser = tokens.twitterUser || tokensObj.twitterUser;
        console.log(`✅ Loaded Twitter tokens for user ${uid}`);
      }
    } catch (error) {
      console.error(`❌ Erreur lecture ${twitterTokensFile}:`, error.message, error.stack);
    }
  }
}

// Sauvegarde des données utilisateur
async function saveUserData(uid) {
  const user = userData.get(uid);
  if (!user || user.dataLock) {
    console.log(`🔒 Sauvegarde données ignorée pour ${uid} (verrou ou données absentes)`);
    return;
  }
  user.dataLock = true;
  const { userStyleFile, tweetsHistoryFile, scheduledTweetsFile, twitterTokensFile } = getUserFilePaths(uid);
  try {
    await fs.mkdir(path.dirname(userStyleFile), { recursive: true });
    await Promise.all([
      fs.writeFile(userStyleFile, JSON.stringify(user.userStyle, (key, value) => {
        if (value instanceof Set) return Array.from(value);
        return value;
      }, 2)),
      fs.writeFile(tweetsHistoryFile, JSON.stringify(user.generatedTweetsHistory, null, 2)),
      fs.writeFile(scheduledTweetsFile, JSON.stringify(user.scheduledTweets, null, 2)),
      user.twitterTokens
        ? fs.writeFile(twitterTokensFile, JSON.stringify({
            twitterTokens: user.twitterTokens,
            twitterUser: user.twitterUser,
          }, null, 2))
        : Promise.resolve(),
    ]);
    console.log(`✅ Données sauvegardées pour ${uid}`);
  } catch (error) {
    console.error(`❌ Erreur sauvegarde données pour ${uid}:`, error.message, error.stack);
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

// Instance Axios pour l'API Groq
const axiosInstance = axios.create({
  timeout: 15000,
  headers: {
    Authorization: `Bearer ${GROQ_API_KEY}`,
    'Content-Type': 'application/json',
  },
});

// Configuration Twitter OAuth 2.0 avec PKCE
const twitterOAuthClient = new TwitterApi({
  clientId: process.env.TWITTER_CLIENT_ID,
  clientSecret: process.env.TWITTER_CLIENT_SECRET,
});

// Générer un code verifier et challenge pour PKCE
function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// Route pour initier l'authentification Twitter/X OAuth 2.0
app.get('/api/twitter-auth', verifyToken, async (req, res) => {
  try {
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    const authLink = await twitterOAuthClient.generateOAuth2AuthLink('http://localhost:3000/api/twitter-callback', {
      scope: ['tweet.read', 'tweet.write', 'users.read', 'offline.access'],
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    user.twitterAuthState = authLink.state;
    user.codeVerifier = codeVerifier;
    console.log(`✅ Auth Twitter initiée pour ${uid}, URL: ${authLink.url}`);
    res.json({ success: true, authUrl: authLink.url });
  } catch (error) {
    console.error(`❌ Erreur initiation auth Twitter pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({ success: false, error: 'Échec initiation auth Twitter', details: error.message });
  }
});

// Route pour gérer le callback Twitter/X OAuth
app.get('/api/twitter-callback', verifyToken, async (req, res) => {
  try {
    const { code, state } = req.query;
    const uid = req.user.uid;
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
      redirectUri: 'http://localhost:3000/api/twitter-callback',
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
    res.redirect('http://localhost:3000/');
  } catch (error) {
    console.error(`❌ Erreur callback Twitter pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({ success: false, error: 'Échec authentification Twitter', details: error.message });
  }
});

// Route pour rafraîchir le token Twitter/X
app.post('/api/twitter-refresh', verifyToken, async (req, res) => {
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
app.post('/api/twitter-logout', verifyToken, async (req, res) => {
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

// Route pour récupérer les données utilisateur Twitter/X
app.get('/api/user', verifyToken, async (req, res) => {
  try {
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    if (!user.twitterUser) {
      return res.status(404).json({ success: false, error: 'Utilisateur Twitter non authentifié' });
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
app.get('/api/user-stats', verifyToken, async (req, res) => {
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

// Route pour l'authentification via extension
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

// Route pour gérer la connexion via Firebase
app.post('/api/login', verifyToken, async (req, res) => {
  try {
    const uid = req.user.uid;
    console.log(`🔍 Connexion pour UID: ${uid}`);
    await initializeUserData(uid);
    res.json({ success: true, message: 'Connexion réussie', uid });
  } catch (error) {
    console.error(`❌ Erreur traitement connexion pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({ success: false, error: 'Échec traitement connexion', details: error.message });
  }
});

// Appliquer le middleware d'authentification aux routes API
app.use('/api/*', verifyToken);

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

// Route pour générer des tweets
app.post('/api/generate-tweets', async (req, res) => {
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
      'question-provocante',
      'metaphore-creative',
      'style-personnel',
    ];

    const modePrompts = {
      'tweet-viral': `Generate a viral tweet based on: "${userComment}". Secondary context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'critique-constructive': `Generate a constructive critique tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'thread-twitter': `Generate the first tweet of a thread based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'reformulation-simple': `Generate a simple reformulation tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'angle-contrarian': `Generate a contrarian angle tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'storytelling': `Generate a storytelling tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'question-provocante': `Generate a provocative question tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'metaphore-creative': `Generate a creative metaphor tweet for: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'style-personnel': `Generate a personal style tweet based on: "${userComment}". Style (tone: ${user.userStyle.tone}, words: ${Array.from(user.userStyle.vocabulary)
        .slice(-5)
        .join(', ')}). Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
    };

    const filteredModes = modeFilter && modes.includes(modeFilter) ? [modeFilter] : modes;
    const prompts = filteredModes.map(mode => modePrompts[mode]);

    user.userStyle.writings.push({ text: userComment.trim(), timestamp: new Date() });
    user.userStyle.tone = detectTone(userComment.trim());
    user.userStyle.styleProgress = Math.min(user.userStyle.styleProgress + 100, 10000);
    user.userStyle.lastModified = new Date();

    if (user.userStyle.writings.length > 50) {
      user.userStyle.writings = user.userStyle.writings.slice(-50);
    }

    const promises = prompts.map(async (prompt, index) => {
      try {
        const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
          messages: [
            {
              role: 'system',
              content:
                'Tweet expert. Generate original tweets based on user comment. Secondary context: original tweet. Max 280 chars, no hashtags/emojis. Respond only with the tweet',
            },
            { role: 'user', content: prompt },
          ],
          model: 'llama3-8b-8192',
          temperature: 0.7,
          max_tokens: 100,
        });

        const tweet = response.data.choices[0].message.content.trim();
        if (tweet.length > 280) {
          console.warn(`⚠️ Tweet trop long pour mode ${filteredModes[index]}: ${tweet.length} chars`);
          return { success: false, tweet: tweet.substring(0, 280), mode: filteredModes[index], error: 'Tweet trop long' };
        }
        return { success: true, tweet, mode: filteredModes[index] };
      } catch (error) {
        console.error(`❌ Erreur mode ${filteredModes[index]}:`, error.message, error.stack);
        return {
          success: false,
          tweet: `Erreur: Échec génération pour ${filteredModes[index]}`,
          mode: filteredModes[index],
          error: error.message,
        };
      }
    });

    const results = await Promise.all(promises);
    const generatedTweets = results.map(r => r.tweet);
    const usedModes = results.map(r => r.mode);

    const tweetData = {
      id: uuidv4(),
      timestamp: new Date(),
      lastModified: new Date(),
      originalTweet: originalTweet || null,
      userComment: userComment.trim(),
      context: context || null,
      generatedTweets,
      modesUsed: usedModes,
      used: false,
    };

    user.generatedTweetsHistory.push(tweetData);
    if (user.generatedTweetsHistory.length > 100) {
      user.generatedTweetsHistory = user.generatedTweetsHistory.slice(-100);
    }

    await saveUserData(uid);
    console.log(`✅ Tweets générés pour ${uid}: ${generatedTweets.length}`);
    res.json({
      success: true,
      data: tweetData,
      lastModified: tweetData.lastModified,
    });
  } catch (error) {
    console.error(`❌ Erreur génération tweets pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({
      success: false,
      error: 'Erreur génération tweets',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
    });
  }
});

// Route pour régénérer un tweet
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
      'tweet-viral': `Generate a viral tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'critique-constructive': `Generate a constructive critique tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'thread-twitter': `Generate the first tweet of a thread based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'reformulation-simple': `Generate a simple reformulation tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'angle-contrarian': `Generate a contrarian angle tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'storytelling': `Generate a storytelling tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'question-provocante': `Generate a provocative question tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'metaphore-creative': `Generate a creative metaphor tweet for: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'style-personnel': `Generate a personal style tweet based on: "${tweetGroup.userComment}". Style (tone: ${user.userStyle.tone}, words: ${Array.from(user.userStyle.vocabulary)
        .slice(-5)
        .join(', ')}). Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
    };

    const prompt = modePrompts[mode];
    if (!prompt) {
      return res.status(400).json({ success: false, error: 'Mode invalide' });
    }

    const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
      messages: [
        {
          role: 'system',
          content:
            'Tweet expert. Generate original tweets based on user comment. Secondary context: original tweet. Max 280 chars, no hashtags/emojis. Respond only with the tweet',
        },
        { role: 'user', content: prompt },
      ],
      model: 'llama3-8b-8192',
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
    tweetGroup.lastModified = new Date();

    const scheduledTweet = user.scheduledTweets.find(t => t.tweetId === tweetId && t.tweetIndex === parseInt(tweetIndex));
    if (scheduledTweet) {
      scheduledTweet.content = newTweet;
      scheduledTweet.lastModified = new Date();
    }

    await saveUserData(uid);
    console.log(`✅ Tweet régénéré pour ${uid}: ${newTweet.substring(0, 50)}...`);
    res.json({
      success: true,
      data: { tweet: newTweet, mode, lastModified: tweetGroup.lastModified },
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
      model: 'llama3-8b-8192',
      temperature: 0.7,
      max_tokens: 200,
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
        remainingCount: tweetGroup.generatedTweets.length,
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

// Route pour l'interface web
app.get('/', async (req, res) => {
  const authHeader = req.headers.authorization;
  let uid = 'anonymous';
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const idToken = authHeader.split('Bearer ')[1];
      const decodedToken = await admin.auth().verifyIdToken(idToken, true);
      uid = decodedToken.uid;
      await initializeUserData(uid);
    } catch (error) {
      console.error('❌ Erreur vérification token pour /:', error.message, error.stack);
    }
  }

  const html = await fs.readFile(path.join(__dirname, 'public', 'index.html'), 'utf8');
  const modifiedHtml = html.replace('<!-- UID_PLACEHOLDER -->', `<script>window.__USER_UID__ = "${uid}";</script>`);
  res.send(modifiedHtml);
});

// Route pour vérifier l'état du serveur
app.get('/health', async (req, res) => {
  const uid = req.user?.uid || 'anonymous';
  await initializeUserData(uid);
  const user = userData.get(uid) || {
    generatedTweetsHistory: [],
    scheduledTweets: [],
    userStyle: { writings: [], styleProgress: 0 },
  };

  res.json({
    status: 'OK',
    timestamp: new Date(),
    version: '2.2.4',
    tweetsCount: user.generatedTweetsHistory.length,
    scheduledTweetsCount: user.scheduledTweets.length,
    scheduledActiveCount: user.scheduledTweets.filter(t => t.status === 'scheduled').length,
    publishedCount: user.scheduledTweets.filter(t => t.status === 'published').length,
    failedCount: user.scheduledTweets.filter(t => t.status === 'failed').length,
    userStyleWritings: user.userStyle.writings.length,
    styleProgress: user.userStyle.styleProgress,
    userId: uid,
    twitterAuthenticated: !!user.twitterClient,
  });
});

// Middleware de gestion des erreurs
app.use((error, req, res, next) => {
  console.error(`❌ Erreur globale pour ${req.user?.uid || 'anonymous'}:`, error.message, error.stack);
  res.status(error.message.includes('Type de fichier non supporté') ? 400 : 500).json({
    success: false,
    error: error.message.includes('Type de fichier non supporté') ? error.message : 'Erreur serveur interne',
    details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
  });
});
// Démarrer le serveur
async function startServer() {
  try {
    console.log('🔄 Initialisation du serveur...');
    startScheduleChecker();
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`);
      console.log(`📊 Interface web: http://localhost:${PORT}`);
      console.log(`🔄 API endpoints disponibles:`);
      console.log(`   - GET  /api/twitter-auth`);
      console.log(`   - GET  /api/twitter-callback`);
      console.log(`   - POST /api/twitter-refresh`);
      console.log(`   - POST /api/twitter-logout`);
      console.log(`   - GET  /api/user`);
      console.log(`   - GET  /api/extension-login`);
      console.log(`   - POST /api/login`);
      console.log(`   - POST /api/logout`);
      console.log(`   - POST /api/refresh-token`);
      console.log(`   - POST /api/learn-style`);
      console.log(`   - POST /api/generate-tweets`);
      console.log(`   - POST /api/regenerate-tweet`);
      console.log(`   - POST /api/learn-content`);
      console.log(`   - GET  /api/tweets-history`);
      console.log(`   - POST /api/tweet-used`);
      console.log(`   - POST /api/edit-tweet`);
      console.log(`   - POST /api/schedule-tweet`);
      console.log(`   - GET  /api/tweets`);
      console.log(`   - DELETE /api/tweets/:id`);
      console.log(`   - POST /api/tweets/:id/publish`);
      console.log(`   - GET  /api/user-stats`);
      console.log(`   - GET  /health`);
      console.log(`✅ Serveur prêt!`);
    });
  } catch (error) {
    console.error('❌ Erreur lors du démarrage du serveur:', error.message, error.stack);
    process.exit(1); // ← Ajout du code d'erreur
  }
}

// Appeler la fonction pour démarrer le serveur
startServer(); // ← Cette ligne était manquante !*/






/*
//server 2
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
const session = require('express-session');
const passport = require('passport');
const TwitterStrategy = require('passport-twitter').Strategy;
require('dotenv').config();

// Stockage persistant pour les utilisateurs Twitter
const twitterUsersFile = path.join(__dirname, 'twitterUsers.json');
let twitterUsers = new Map();

async function loadTwitterUsers() {
  try {
    const data = await fs.readFile(twitterUsersFile, 'utf8');
    const users = JSON.parse(data);
    for (const [id, user] of Object.entries(users)) {
      twitterUsers.set(id, user);
    }
    console.log('✅ Loaded Twitter users');
  } catch (error) {
    if (error.code === 'ENOENT') {
      console.log('No twitterUsers.json found, starting empty');
    } else {
      console.error('❌ Error loading twitterUsers:', error.message, error.stack);
    }
  }
}

async function saveTwitterUsers() {
  try {
    await fs.writeFile(twitterUsersFile, JSON.stringify(Object.fromEntries(twitterUsers), null, 2));
    console.log('✅ Saved Twitter users');
  } catch (error) {
    console.error('❌ Error saving twitterUsers:', error.message, error.stack);
  }
}

// Initialisation de l'application Express
const app = express();
const PORT = process.env.PORT || 3000;

// Initialisation de Firebase Admin SDK
// Utilisé pour vérifier les tokens Firebase et gérer les sessions utilisateur
try {
  const serviceAccount = require('./firebase-service-account.json');
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
  console.log('✅ Firebase Admin initialisé');
} catch (error) {
  console.error('❌ Erreur initialisation Firebase Admin:', error.message, error.stack);
  process.exit(1);
}

// Configuration des middlewares
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://127.0.0.1:8080', 'https://x.com'],
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'If-None-Match', 'Authorization', 'X-User-ID', 'Accept', 'Origin', 'X-Requested-With'],
  credentials: true,
}));
app.use(express.json());

// Middleware de session pour Passport avec rolling pour prolonger la session
app.use(session({
  secret: process.env.SESSION_SECRET || 'your_session_secret', // Utilisez une clé secrète forte depuis .env
  resave: true, // Resave pour prolonger la session
  saveUninitialized: false,
  rolling: true, // Réinitialise le maxAge à chaque réponse
  cookie: {
    secure: process.env.NODE_ENV === 'production', // true en production pour HTTPS
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 jours
  }
}));

// Initialisation de Passport
app.use(passport.initialize());
app.use(passport.session());

// Configuration de la stratégie Twitter pour Passport
passport.use(new TwitterStrategy({
  consumerKey: process.env.TWITTER_CONSUMER_KEY,
  consumerSecret: process.env.TWITTER_CONSUMER_SECRET,
  callbackURL: 'http://localhost:3000/auth/twitter/callback',
  includeEmail: true, // Optionnel, si vous voulez l'email
}, async (token, tokenSecret, profile, done) => {
  try {
    // Ici, vous pouvez créer ou trouver l'utilisateur dans votre base de données
    // Pour cet exemple, on utilise le profile Twitter comme utilisateur
    const user = {
      id: profile.id,
      username: profile.username,
      displayName: profile.displayName,
      profilePicture: profile.photos ? profile.photos[0].value : null,
      twitterToken: token,
      twitterTokenSecret: tokenSecret,
    };

    // Stockez l'utilisateur dans la Map persistante
    twitterUsers.set(user.id, user);
    await saveTwitterUsers();

    // Associez à Firebase si nécessaire, ou stockez dans votre Map userData
    // Pour simplifier, on retourne l'utilisateur
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

// Sérialisation de l'utilisateur pour la session
passport.serializeUser((user, done) => {
  done(null, user.id); // Sérialise uniquement l'ID
});

// Désérialisation de l'utilisateur depuis la session
passport.deserializeUser((id, done) => {
  // Récupérez l'utilisateur depuis la Map persistante
  const user = twitterUsers.get(id);
  if (user) {
    done(null, user);
  } else {
    done(new Error('User not found'));
  }
});

// Middleware pour vérifier le token Firebase
async function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('❌ Aucun ou mauvais en-tête Authorization', { path: req.path, authHeader });
    return res.status(401).json({ success: false, error: 'Aucun ou mauvais en-tête Authorization' });
  }

  const idToken = authHeader.split('Bearer ')[1];
  try {
    console.log(`🔍 Vérification token pour ${req.path}: ${idToken.substring(0, 10)}...`);
    const decodedToken = await admin.auth().verifyIdToken(idToken, true);
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

// Route pour rafraîchir le token Firebase
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

// Route d'authentification Twitter
app.get('/auth/twitter', passport.authenticate('twitter', { scope: ['email'] }));

// Callback Twitter
app.get('/auth/twitter/callback',
  passport.authenticate('twitter', { failureRedirect: '/login' }),
  (req, res) => {
    // Rediriger et fermer la popup
    res.send(`<script>
      window.opener.postMessage({
        type: 'TF_LOGIN_SUCCESS',
        user: ${JSON.stringify(req.user)}
      }, '*');
      window.close();
    </script>`);
  }
);

// Statut d'authentification
app.get('/api/auth-status', (req, res) => {
  res.json({
    authenticated: !!req.user,
    user: req.user || null
  });
});

// Test d'authentification
app.get('/api/test-auth', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Non authentifié' });
  }
  res.json({ success: true, user: req.user });
});

// Route pour la déconnexion Twitter avec Passport
app.post('/api/logout-twitter', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ success: false, error: 'Non authentifié' });
  }

  const userId = req.user.id;
  req.logout((err) => {
    if (err) {
      console.error('❌ Erreur lors de req.logout:', err.message, err.stack);
      return res.status(500).json({ success: false, error: 'Échec déconnexion', details: err.message });
    }

    req.session.destroy((err) => {
      if (err) {
        console.error('❌ Erreur lors de session.destroy:', err.message, err.stack);
        return res.status(500).json({ success: false, error: 'Échec déconnexion', details: err.message });
      }

      twitterUsers.delete(userId);
      saveTwitterUsers();
      console.log(`✅ Déconnexion Twitter réussie pour ID: ${userId}`);
      res.json({ success: true, message: 'Déconnexion réussie' });
    });
  });
});

// Route pour la déconnexion Firebase (inchangée)
app.post('/api/logout', verifyToken, async (req, res) => {
  try {
    const uid = req.user.uid;
    console.log(`🔍 Déconnexion pour UID: ${uid}`);
    await admin.auth().revokeRefreshTokens(uid);
    userData.delete(uid);
    tweetIdCounters.delete(uid);
    console.log(`✅ Déconnexion réussie pour UID: ${uid}`);
    res.json({ success: true, message: 'Déconnexion réussie' });
  } catch (error) {
    console.error(`❌ Erreur déconnexion pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({ success: false, error: 'Échec déconnexion', details: error.message });
  }
});

// Configuration de Multer pour l'upload de fichiers
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadPath = path.join(__dirname, 'Uploads', req.user.uid);
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

// Servir les fichiers statiques
app.use('/Uploads', express.static(path.join(__dirname, 'Uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// Clés API
const GROQ_API_KEY = process.env.GROQ_API_KEY || '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';

// Stockage des données utilisateur
const userData = new Map();
const tweetIdCounters = new Map();

// Chemins des fichiers pour la persistance des données utilisateur
function getUserFilePaths(uid) {
  return {
    userStyleFile: path.join(__dirname, 'data', uid, 'userStyle.json'),
    tweetsHistoryFile: path.join(__dirname, 'data', uid, 'tweetsHistory.json'),
    scheduledTweetsFile: path.join(__dirname, 'data', uid, 'scheduledTweets.json'),
    twitterTokensFile: path.join(__dirname, 'data', uid, 'twitterTokens.json'),
  };
}

// Initialisation des données utilisateur
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
      twitterUser: null, // Stocke username, handle, profile_picture
      dataLock: false,
      sessionStart: new Date(),
    });
    tweetIdCounters.set(uid, 1);

    const { userStyleFile, tweetsHistoryFile, scheduledTweetsFile, twitterTokensFile } = getUserFilePaths(uid);
    const userDir = path.dirname(userStyleFile);

    try {
      await fs.mkdir(userDir, { recursive: true });
      console.log(`✅ Dossier créé: ${userDir}`);
    } catch (error) {
      console.error(`❌ Erreur création dossier ${userDir}:`, error.message, error.stack);
      throw new Error(`Échec création dossier utilisateur: ${error.message}`);
    }

    try {
      const userStyleData = await fs.readFile(userStyleFile, 'utf8').catch(() => '{}');
      userData.get(uid).userStyle = {
        ...defaultUserStyle,
        ...JSON.parse(userStyleData, (key, value) => {
          if (key === 'vocabulary') return new Set(value);
          return value;
        }),
      };
      console.log(`✅ Loaded userStyle for user ${uid}`);
    } catch (error) {
      console.error(`❌ Erreur lecture ${userStyleFile}:`, error.message, error.stack);
    }

    try {
      const tweetsHistoryData = await fs.readFile(tweetsHistoryFile, 'utf8').catch(() => '[]');
      userData.get(uid).generatedTweetsHistory = JSON.parse(tweetsHistoryData);
      if (userData.get(uid).generatedTweetsHistory.length > 0) {
        const maxId = Math.max(...userData.get(uid).generatedTweetsHistory.map(t => parseInt(t.id) || 0));
        if (maxId >= tweetIdCounters.get(uid)) tweetIdCounters.set(uid, maxId + 1);
      }
      console.log(`✅ Loaded tweetsHistory for user ${uid}`);
    } catch (error) {
      console.error(`❌ Erreur lecture ${tweetsHistoryFile}:`, error.message, error.stack);
    }

    try {
      const scheduledTweetsData = await fs.readFile(scheduledTweetsFile, 'utf8').catch(() => '[]');
      userData.get(uid).scheduledTweets = JSON.parse(scheduledTweetsData, (key, value) => {
        if (key === 'datetime' || key === 'createdAt' || key === 'lastModified' || key === 'publishedAt' || key === 'failedAt') {
          return value ? new Date(value) : null;
        }
        return value;
      });
      if (userData.get(uid).scheduledTweets.length > 0) {
        const maxId = Math.max(...userData.get(uid).scheduledTweets.map(t => t.id || 0));
        if (maxId >= tweetIdCounters.get(uid)) tweetIdCounters.set(uid, maxId + 1);
      }
      console.log(`✅ Loaded scheduledTweets for user ${uid}`);
    } catch (error) {
      console.error(`❌ Erreur lecture ${scheduledTweetsFile}:`, error.message, error.stack);
    }

    try {
      const twitterTokensData = await fs.readFile(twitterTokensFile, 'utf8').catch(() => null);
      if (twitterTokensData) {
        const tokens = JSON.parse(twitterTokensData);
        const tokensObj = tokens.twitterTokens || tokens; // Compatibilité avec ancien format
        userData.get(uid).twitterTokens = tokensObj;
        userData.get(uid).twitterClient = new TwitterApi(tokensObj.access_token);
        userData.get(uid).twitterUser = tokens.twitterUser || tokensObj.twitterUser;
        console.log(`✅ Loaded Twitter tokens for user ${uid}`);
      }
    } catch (error) {
      console.error(`❌ Erreur lecture ${twitterTokensFile}:`, error.message, error.stack);
    }
  }
}

// Sauvegarde des données utilisateur
async function saveUserData(uid) {
  const user = userData.get(uid);
  if (!user || user.dataLock) {
    console.log(`🔒 Sauvegarde données ignorée pour ${uid} (verrou ou données absentes)`);
    return;
  }
  user.dataLock = true;
  const { userStyleFile, tweetsHistoryFile, scheduledTweetsFile, twitterTokensFile } = getUserFilePaths(uid);
  try {
    await fs.mkdir(path.dirname(userStyleFile), { recursive: true });
    await Promise.all([
      fs.writeFile(userStyleFile, JSON.stringify(user.userStyle, (key, value) => {
        if (value instanceof Set) return Array.from(value);
        return value;
      }, 2)),
      fs.writeFile(tweetsHistoryFile, JSON.stringify(user.generatedTweetsHistory, null, 2)),
      fs.writeFile(scheduledTweetsFile, JSON.stringify(user.scheduledTweets, null, 2)),
      user.twitterTokens
        ? fs.writeFile(twitterTokensFile, JSON.stringify({
            twitterTokens: user.twitterTokens,
            twitterUser: user.twitterUser,
          }, null, 2))
        : Promise.resolve(),
    ]);
    console.log(`✅ Données sauvegardées pour ${uid}`);
  } catch (error) {
    console.error(`❌ Erreur sauvegarde données pour ${uid}:`, error.message, error.stack);
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

// Instance Axios pour l'API Groq
const axiosInstance = axios.create({
  timeout: 15000,
  headers: {
    Authorization: `Bearer ${GROQ_API_KEY}`,
    'Content-Type': 'application/json',
  },
});

// Configuration Twitter OAuth 2.0 avec PKCE
const twitterOAuthClient = new TwitterApi({
  clientId: process.env.TWITTER_CLIENT_ID,
  clientSecret: process.env.TWITTER_CLIENT_SECRET,
});

// Générer un code verifier et challenge pour PKCE
function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// Route pour initier l'authentification Twitter/X OAuth 2.0
app.get('/api/twitter-auth', verifyToken, async (req, res) => {
  try {
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    const authLink = await twitterOAuthClient.generateOAuth2AuthLink('http://localhost:3000/api/twitter-callback', {
      scope: ['tweet.read', 'tweet.write', 'users.read', 'offline.access'],
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    user.twitterAuthState = authLink.state;
    user.codeVerifier = codeVerifier;
    console.log(`✅ Auth Twitter initiée pour ${uid}, URL: ${authLink.url}`);
    res.json({ success: true, authUrl: authLink.url });
  } catch (error) {
    console.error(`❌ Erreur initiation auth Twitter pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({ success: false, error: 'Échec initiation auth Twitter', details: error.message });
  }
});

// Route pour gérer le callback Twitter/X OAuth
app.get('/api/twitter-callback', verifyToken, async (req, res) => {
  try {
    const { code, state } = req.query;
    const uid = req.user.uid;
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
      redirectUri: 'http://localhost:3000/api/twitter-callback',
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
    res.redirect('http://localhost:3000/');
  } catch (error) {
    console.error(`❌ Erreur callback Twitter pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({ success: false, error: 'Échec authentification Twitter', details: error.message });
  }
});

// Route pour rafraîchir le token Twitter/X
app.post('/api/twitter-refresh', verifyToken, async (req, res) => {
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
app.post('/api/twitter-logout', verifyToken, async (req, res) => {
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

// Route pour récupérer les données utilisateur Twitter/X
app.get('/api/user', verifyToken, async (req, res) => {
  try {
    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    if (!user.twitterUser) {
      return res.status(404).json({ success: false, error: 'Utilisateur Twitter non authentifié' });
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
app.get('/api/user-stats', verifyToken, async (req, res) => {
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

// Route pour récupérer l'interface de connexion via extension
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

// Route pour gérer la connexion via Firebase
app.post('/api/login', verifyToken, async (req, res) => {
  try {
    const uid = req.user.uid;
    console.log(`🔍 Connexion pour UID: ${uid}`);
    await initializeUserData(uid);
    res.json({ success: true, message: 'Connexion réussie', uid });
  } catch (error) {
    console.error(`❌ Erreur traitement connexion pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({ success: false, error: 'Échec traitement connexion', details: error.message });
  }
});

// Appliquer le middleware d'authentification aux routes API
app.use('/api/*', verifyToken);

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

// Route pour générer des tweets
app.post('/api/generate-tweets', async (req, res) => {
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
      'question-provocante',
      'metaphore-creative',
      'style-personnel',
    ];

    const modePrompts = {
      'tweet-viral': `Generate a viral tweet based on: "${userComment}". Secondary context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'critique-constructive': `Generate a constructive critique tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'thread-twitter': `Generate the first tweet of a thread based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'reformulation-simple': `Generate a simple reformulation tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'angle-contrarian': `Generate a contrarian angle tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'storytelling': `Generate a storytelling tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'question-provocante': `Generate a provocative question tweet based on: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'metaphore-creative': `Generate a creative metaphor tweet for: "${userComment}". Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'style-personnel': `Generate a personal style tweet based on: "${userComment}". Style (tone: ${user.userStyle.tone}, words: ${Array.from(user.userStyle.vocabulary)
        .slice(-5)
        .join(', ')}). Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
    };

    const filteredModes = modeFilter && modes.includes(modeFilter) ? [modeFilter] : modes;
    const prompts = filteredModes.map(mode => modePrompts[mode]);

    user.userStyle.writings.push({ text: userComment.trim(), timestamp: new Date() });
    user.userStyle.tone = detectTone(userComment.trim());
    user.userStyle.styleProgress = Math.min(user.userStyle.styleProgress + 100, 10000);
    user.userStyle.lastModified = new Date();

    if (user.userStyle.writings.length > 50) {
      user.userStyle.writings = user.userStyle.writings.slice(-50);
    }

    const promises = prompts.map(async (prompt, index) => {
      try {
        const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
          messages: [
            {
              role: 'system',
              content:
                'Tweet expert. Generate original tweets based on user comment. Secondary context: original tweet. Max 280 chars, no hashtags/emojis. Respond only with the tweet',
            },
            { role: 'user', content: prompt },
          ],
          model: 'llama3-8b-8192',
          temperature: 0.7,
          max_tokens: 100,
        });

        const tweet = response.data.choices[0].message.content.trim();
        if (tweet.length > 280) {
          console.warn(`⚠️ Tweet trop long pour mode ${filteredModes[index]}: ${tweet.length} chars`);
          return { success: false, tweet: tweet.substring(0, 280), mode: filteredModes[index], error: 'Tweet trop long' };
        }
        return { success: true, tweet, mode: filteredModes[index] };
      } catch (error) {
        console.error(`❌ Erreur mode ${filteredModes[index]}:`, error.message, error.stack);
        return {
          success: false,
          tweet: `Erreur: Échec génération pour ${filteredModes[index]}`,
          mode: filteredModes[index],
          error: error.message,
        };
      }
    });

    const results = await Promise.all(promises);
    const generatedTweets = results.map(r => r.tweet);
    const usedModes = results.map(r => r.mode);

    const tweetData = {
      id: uuidv4(),
      timestamp: new Date(),
      lastModified: new Date(),
      originalTweet: originalTweet || null,
      userComment: userComment.trim(),
      context: context || null,
      generatedTweets,
      modesUsed: usedModes,
      used: false,
    };

    user.generatedTweetsHistory.push(tweetData);
    if (user.generatedTweetsHistory.length > 100) {
      user.generatedTweetsHistory = user.generatedTweetsHistory.slice(-100);
    }

    await saveUserData(uid);
    console.log(`✅ Tweets générés pour ${uid}: ${generatedTweets.length}`);
    res.json({
      success: true,
      data: tweetData,
      lastModified: tweetData.lastModified,
    });
  } catch (error) {
    console.error(`❌ Erreur génération tweets pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({
      success: false,
      error: 'Erreur génération tweets',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
    });
  }
});

// Route pour régénérer un tweet
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
      'tweet-viral': `Generate a viral tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'critique-constructive': `Generate a constructive critique tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'thread-twitter': `Generate the first tweet of a thread based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'reformulation-simple': `Generate a simple reformulation tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'angle-contrarian': `Generate a contrarian angle tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'storytelling': `Generate a storytelling tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'question-provocante': `Generate a provocative question tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'metaphore-creative': `Generate a creative metaphor tweet for: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'style-personnel': `Generate a personal style tweet based on: "${tweetGroup.userComment}". Style (tone: ${user.userStyle.tone}, words: ${Array.from(user.userStyle.vocabulary)
        .slice(-5)
        .join(', ')}). Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
    };

    const prompt = modePrompts[mode];
    if (!prompt) {
      return res.status(400).json({ success: false, error: 'Mode invalide' });
    }

    const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
      messages: [
        {
          role: 'system',
          content:
            'Tweet expert. Generate original tweets based on user comment. Secondary context: original tweet. Max 280 chars, no hashtags/emojis. Respond only with the tweet',
        },
        { role: 'user', content: prompt },
      ],
      model: 'llama3-8b-8192',
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
    tweetGroup.lastModified = new Date();

    const scheduledTweet = user.scheduledTweets.find(t => t.tweetId === tweetId && t.tweetIndex === parseInt(tweetIndex));
    if (scheduledTweet) {
      scheduledTweet.content = newTweet;
      scheduledTweet.lastModified = new Date();
    }

    await saveUserData(uid);
    console.log(`✅ Tweet régénéré pour ${uid}: ${newTweet.substring(0, 50)}...`);
    res.json({
      success: true,
      data: { tweet: newTweet, mode, lastModified: tweetGroup.lastModified },
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
      model: 'llama3-8b-8192',
      temperature: 0.7,
      max_tokens: 200,
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

// Route pour l'interface web
app.get('/', async (req, res) => {
  const authHeader = req.headers.authorization;
  let uid = 'anonymous';
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const idToken = authHeader.split('Bearer ')[1];
      const decodedToken = await admin.auth().verifyIdToken(idToken, true);
      uid = decodedToken.uid;
      await initializeUserData(uid);
    } catch (error) {
      console.error('❌ Erreur vérification token pour /:', error.message, error.stack);
    }
  }

  const html = await fs.readFile(path.join(__dirname, 'public', 'index.html'), 'utf8');
  const modifiedHtml = html.replace('<!-- UID_PLACEHOLDER -->', `<script>window.__USER_UID__ = "${uid}";</script>`);
  res.send(modifiedHtml);
});

// Route pour vérifier l'état du serveur
app.get('/health', async (req, res) => {
  const uid = req.user?.uid || 'anonymous';
  await initializeUserData(uid);
  const user = userData.get(uid) || {
    generatedTweetsHistory: [],
    scheduledTweets: [],
    userStyle: { writings: [], styleProgress: 0 },
  };

  res.json({
    status: 'OK',
    timestamp: new Date(),
    version: '2.2.4',
    tweetsCount: user.generatedTweetsHistory.length,
    scheduledTweetsCount: user.scheduledTweets.length,
    scheduledActiveCount: user.scheduledTweets.filter(t => t.status === 'scheduled').length,
    publishedCount: user.scheduledTweets.filter(t => t.status === 'published').length,
    failedCount: user.scheduledTweets.filter(t => t.status === 'failed').length,
    userStyleWritings: user.userStyle.writings.length,
    styleProgress: user.userStyle.styleProgress,
    userId: uid,
    twitterAuthenticated: !!user.twitterClient,
  });
});

// Middleware de gestion des erreurs
app.use((error, req, res, next) => {
  console.error(`❌ Erreur globale pour ${req.user?.uid || 'anonymous'}:`, error.message, error.stack);
  res.status(error.message.includes('Type de fichier non supporté') ? 400 : 500).json({
    success: false,
    error: error.message.includes('Type de fichier non supporté') ? error.message : 'Erreur serveur interne',
    details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
  });
});
// Démarrer le serveur
async function startServer() {
  try {
    console.log('🔄 Initialisation du serveur...');
    await loadTwitterUsers(); // Charger les utilisateurs Twitter persistants
    startScheduleChecker();
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`);
      console.log(`📊 Interface web: http://localhost:${PORT}`);
      console.log(`🔄 API endpoints disponibles:`);
      console.log(`   - GET  /api/twitter-auth`);
      console.log(`   - GET  /api/twitter-callback`);
      console.log(`   - POST /api/twitter-refresh`);
      console.log(`   - POST /api/twitter-logout`);
      console.log(`   - POST /api/logout-twitter`); // Nouvelle route de logout
      console.log(`   - GET  /api/user`);
      console.log(`   - GET  /api/extension-login`);
      console.log(`   - POST /api/login`);
      console.log(`   - POST /api/logout`);
      console.log(`   - POST /api/refresh-token`);
      console.log(`   - POST /api/learn-style`);
      console.log(`   - POST /api/generate-tweets`);
      console.log(`   - POST /api/regenerate-tweet`);
      console.log(`   - POST /api/learn-content`);
      console.log(`   - GET  /api/tweets-history`);
      console.log(`   - POST /api/tweet-used`);
      console.log(`   - POST /api/edit-tweet`);
      console.log(`   - POST /api/schedule-tweet`);
      console.log(`   - GET  /api/tweets`);
      console.log(`   - DELETE /api/tweets/:id`);
      console.log(`   - POST /api/tweets/:id/publish`);
      console.log(`   - GET  /api/user-stats`);
      console.log(`   - GET  /health`);
      console.log(`✅ Serveur prêt!`);
    });
  } catch (error) {
    console.error('❌ Erreur lors du démarrage du serveur:', error.message, error.stack);
    process.exit(1); // ← Ajout du code d'erreur
  }
}

// Appeler la fonction pour démarrer le serveur
startServer(); // ← Cette ligne était manquante !*/


//code du haut
//code avec overlap d'auth






















/*

// server top

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
require('dotenv').config();
const serviceAccount = require(process.env.FIREBASE_SERVICE_ACCOUNT_PATH);
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
const db = admin.firestore(); // Define db after initialization

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

// Initialisation de l'application Express
const app = express();
const PORT = process.env.PORT || 3000;

//models
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
  'thread-twitter': ['basic', 'bullet_points'],
  'reformulation-simple': ['basic', 'oneliner'],
  'angle-contrarian': ['equation', 'oneliner'],
  'storytelling': ['basic', 'oneliner'],
  'question-provocante': ['oneliner', 'basic'],
  'metaphore-creative': ['equation', 'basic'],
  'style-personnel': ['basic', 'oneliner', 'bullet_points']
};

// Fonction pour sélectionner un template
function selectTemplate(mode) {
  const availableTemplates = templateModeMapping[mode] || Object.keys(tweetTemplates);
  const randomIndex = Math.floor(Math.random() * availableTemplates.length);
  return availableTemplates[randomIndex];
}


// Configuration des middlewares
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://127.0.0.1:8080', 'https://x.com'],
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'If-None-Match', 'Authorization', 'X-User-ID', 'Accept', 'Origin', 'X-Requested-With'],
  credentials: true,
}));
app.use(express.json());

// Middleware pour vérifier le token Firebase
async function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('❌ Aucun ou mauvais en-tête Authorization', { path: req.path, authHeader });
    return res.status(401).json({ success: false, error: 'Aucun ou mauvais en-tête Authorization' });
  }

  const idToken = authHeader.split('Bearer ')[1];
  try {
    console.log(`🔍 Vérification token pour ${req.path}: ${idToken.substring(0, 10)}...`);
    const decodedToken = await admin.auth().verifyIdToken(idToken, true);
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

// Route pour l'interface de connexion via extension (AVANT le middleware verifyToken)
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

// Route pour rafraîchir le token Firebase (AVANT le middleware verifyToken)
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

// Appliquer le middleware d'authentification Firebase aux routes API protégées
app.use('/api/*', verifyToken);

// Configuration de Multer pour l'upload de fichiers
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadPath = path.join(__dirname, 'Uploads', req.user.uid);
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

// Servir les fichiers statiques
app.use('/Uploads', express.static(path.join(__dirname, 'Uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// Clés API
const GROQ_API_KEY = process.env.GROQ_API_KEY;

// Stockage des données utilisateur
const userData = new Map();
const tweetIdCounters = new Map();

// Chemins des fichiers pour la persistance des données utilisateur
function getUserFilePaths(uid) {
  return {
    userStyleFile: path.join(__dirname, 'data', uid, 'userStyle.json'),
    tweetsHistoryFile: path.join(__dirname, 'data', uid, 'tweetsHistory.json'),
    scheduledTweetsFile: path.join(__dirname, 'data', uid, 'scheduledTweets.json'),
    twitterTokensFile: path.join(__dirname, 'data', uid, 'twitterTokens.json'),
  };
}

// Initialisation des données utilisateur
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
      twitterUser: null, // Stocke username, handle, profile_picture
      dataLock: false,
      sessionStart: new Date(),
    });
    tweetIdCounters.set(uid, 1);

    const { userStyleFile, tweetsHistoryFile, scheduledTweetsFile, twitterTokensFile } = getUserFilePaths(uid);
    const userDir = path.dirname(userStyleFile);

    try {
      await fs.mkdir(userDir, { recursive: true });
      console.log(`✅ Dossier créé: ${userDir}`);
    } catch (error) {
      console.error(`❌ Erreur création dossier ${userDir}:`, error.message, error.stack);
      throw new Error(`Échec création dossier utilisateur: ${error.message}`);
    }

    try {
      const userStyleData = await fs.readFile(userStyleFile, 'utf8').catch(() => '{}');
      userData.get(uid).userStyle = {
        ...defaultUserStyle,
        ...JSON.parse(userStyleData, (key, value) => {
          if (key === 'vocabulary') return new Set(value);
          return value;
        }),
      };
      console.log(`✅ Loaded userStyle for user ${uid}`);
    } catch (error) {
      console.error(`❌ Erreur lecture ${userStyleFile}:`, error.message, error.stack);
    }

    try {
      const tweetsHistoryData = await fs.readFile(tweetsHistoryFile, 'utf8').catch(() => '[]');
      userData.get(uid).generatedTweetsHistory = JSON.parse(tweetsHistoryData);
      if (userData.get(uid).generatedTweetsHistory.length > 0) {
        const maxId = Math.max(...userData.get(uid).generatedTweetsHistory.map(t => parseInt(t.id) || 0));
        if (maxId >= tweetIdCounters.get(uid)) tweetIdCounters.set(uid, maxId + 1);
      }
      console.log(`✅ Loaded tweetsHistory for user ${uid}`);
    } catch (error) {
      console.error(`❌ Erreur lecture ${tweetsHistoryFile}:`, error.message, error.stack);
    }

    try {
      const scheduledTweetsData = await fs.readFile(scheduledTweetsFile, 'utf8').catch(() => '[]');
      userData.get(uid).scheduledTweets = JSON.parse(scheduledTweetsData, (key, value) => {
        if (key === 'datetime' || key === 'createdAt' || key === 'lastModified' || key === 'publishedAt' || key === 'failedAt') {
          return value ? new Date(value) : null;
        }
        return value;
      });
      if (userData.get(uid).scheduledTweets.length > 0) {
        const maxId = Math.max(...userData.get(uid).scheduledTweets.map(t => t.id || 0));
        if (maxId >= tweetIdCounters.get(uid)) tweetIdCounters.set(uid, maxId + 1);
      }
      console.log(`✅ Loaded scheduledTweets for user ${uid}`);
    } catch (error) {
      console.error(`❌ Erreur lecture ${scheduledTweetsFile}:`, error.message, error.stack);
    }

    try {
      const twitterTokensData = await fs.readFile(twitterTokensFile, 'utf8').catch(() => null);
      if (twitterTokensData) {
        const tokens = JSON.parse(twitterTokensData);
        const tokensObj = tokens.twitterTokens || tokens; // Compatibilité avec ancien format
        userData.get(uid).twitterTokens = tokensObj;
        userData.get(uid).twitterClient = new TwitterApi(tokensObj.access_token);
        userData.get(uid).twitterUser = tokens.twitterUser || tokensObj.twitterUser;
        console.log(`✅ Loaded Twitter tokens for user ${uid}`);
      }
    } catch (error) {
      console.error(`❌ Erreur lecture ${twitterTokensFile}:`, error.message, error.stack);
    }
  }
}

// Middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: Missing or invalid token' });
  }

  const token = authHeader.split('Bearer ')[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken; // Attach decoded token to request
    next();
  } catch (error) {
    console.error('Error verifying Firebase token:', error.message);
    return res.status(401).json({ error: 'Unauthorized: Invalid token' });
  }
};

// Inside /api/ask-ai route
app.post('/api/ask-ai', authenticateToken, async (req, res) => {
  try {
    if (!process.env.GROQ_API_KEY) {
      console.error('GROQ_API_KEY is not defined in environment variables');
      return res.status(500).json({ error: 'Server configuration error: API key missing' });
    }
    // Validate API key format
    if (!process.env.GROQ_API_KEY.match(/^[a-zA-Z0-9_-]{32,}$/)) {
      console.error('Invalid GROQ_API_KEY format');
      return res.status(500).json({ error: 'Server configuration error: Invalid API key format' });
    }

    const { question } = req.body;
    if (!question || typeof question !== 'string' || question.trim().length === 0) {
      return res.status(400).json({ error: 'Invalid or missing question' });
    }

    const dns = require('dns').promises;

    async function checkDNS(hostname) {
      try {
        await dns.lookup(hostname);
        console.log(`DNS resolved for ${hostname}`);
        return true;
      } catch (error) {
        console.error(`DNS lookup failed for ${hostname}:`, error.message);
        return false;
      }
    }

    const aiResponse = await axios.post('https://api.groq.com/openai/v1/chat/completions', {
      messages: [
        { role: 'system', content: 'You are Grok, a conversational AI. Respond concisely and naturally to the user\'s question as if in a casual conversation.' },
        { role: 'user', content: question.trim() }
      ],
      model: 'llama3-8b-8192',
      temperature: 0.7,
      max_tokens: 100
    }, {
      headers: {
        'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
        'Content-Type': 'application/json'
      },
      timeout: 15000
    });

    const answer = aiResponse.data.choices?.[0]?.message?.content || 'No response from AI';
    res.status(200).json({ answer });
  } catch (error) {
    console.error('Error in /api/ask-ai:', {
      message: error.message,
      response: error.response?.data,
      status: error.response?.status,
      stack: error.stack
    });
    if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
      return res.status(503).json({ error: 'Unable to reach Groq API', details: 'Service unavailable, please check DNS or network settings' });
    }
    if (error.response) {
      if (error.response.status === 404) {
        return res.status(404).json({ error: 'API endpoint not found', details: 'Please check the Groq API documentation at https://console.groq.com/docs' });
      } else if (error.response.status === 401) {
        return res.status(401).json({ error: 'Invalid API key', details: error.response.data?.error || 'Authentication failed, please verify API key at https://console.groq.com' });
      } else if (error.response.status === 429) {
        return res.status(429).json({ error: 'Rate limit exceeded, please try again later', details: error.response.data?.error });
      } else if (error.response.status === 400) {
        return res.status(400).json({ error: 'Bad request', details: error.response.data?.error || 'Invalid request format, please verify API key at https://console.groq.com' });
      }
    }
    res.status(500).json({
      error: 'Server error',
      details: process.env.NODE_ENV === 'development' ? error.message + (error.response?.data?.error ? ` - ${error.response.data.error}` : '') : 'Internal server error'
    });
  }
});

// Sauvegarde des données utilisateur
async function saveUserData(uid) {
  const user = userData.get(uid);
  if (!user || user.dataLock) {
    console.log(`🔒 Sauvegarde données ignorée pour ${uid} (verrou ou données absentes)`);
    return;
  }
  user.dataLock = true;
  const { userStyleFile, tweetsHistoryFile, scheduledTweetsFile, twitterTokensFile } = getUserFilePaths(uid);
  try {
    await fs.mkdir(path.dirname(userStyleFile), { recursive: true });
    await Promise.all([
      fs.writeFile(userStyleFile, JSON.stringify(user.userStyle, (key, value) => {
        if (value instanceof Set) return Array.from(value);
        return value;
      }, 2)),
      fs.writeFile(tweetsHistoryFile, JSON.stringify(user.generatedTweetsHistory, null, 2)),
      fs.writeFile(scheduledTweetsFile, JSON.stringify(user.scheduledTweets, null, 2)),
      user.twitterTokens
        ? fs.writeFile(twitterTokensFile, JSON.stringify({
            twitterTokens: user.twitterTokens,
            twitterUser: user.twitterUser,
          }, null, 2))
        : Promise.resolve(),
    ]);
    console.log(`✅ Données sauvegardées pour ${uid}`);
  } catch (error) {
    console.error(`❌ Erreur sauvegarde données pour ${uid}:`, error.message, error.stack);
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

// Générer un code verifier et challenge pour PKCE
function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// Route pour gérer la connexion via Firebase
app.post('/api/login', async (req, res) => {
  try {
    const uid = req.user.uid;
    console.log(`🔍 Connexion pour UID: ${uid}`);
    await initializeUserData(uid);
    res.json({ success: true, message: 'Connexion réussie', uid });
  } catch (error) {
    console.error(`❌ Erreur traitement connexion pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({ success: false, error: 'Échec traitement connexion', details: error.message });
  }
});

// Route pour la déconnexion Firebase
app.post('/api/logout', async (req, res) => {
  try {
    const uid = req.user.uid;
    console.log(`🔍 Déconnexion pour UID: ${uid}`);
    await admin.auth().revokeRefreshTokens(uid);
    userData.delete(uid);
    tweetIdCounters.delete(uid);
    console.log(`✅ Déconnexion réussie pour UID: ${uid}`);
    res.json({ success: true, message: 'Déconnexion réussie' });
  } catch (error) {
    console.error(`❌ Erreur déconnexion pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({ success: false, error: 'Échec déconnexion', details: error.message });
  }
});

// Statut d'authentification Firebase
app.get('/api/auth-status', async (req, res) => {
  try {
    // Vérifier si l'utilisateur est connecté (Firebase OU Twitter)
    if (!req.user || !req.user.uid) {
      res.json({
        authenticated: true,
        user: user.twitterUser || { uid: uid }, // Données basiques
        twitterAuthenticated: true, // Toujours true si authentifié via Firebase
        uid: uid
      });
    }

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
    // Vérifier si l'utilisateur est connecté (Firebase OU Twitter)
    if (!req.user || !req.user.uid) {
      return res.status(401).json({ success: false, error: 'Non authentifié' });
    }

    const uid = req.user.uid;
    await initializeUserData(uid);
    const user = userData.get(uid);

    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    const authLink = await twitterOAuthClient.generateOAuth2AuthLink('http://localhost:3000/api/twitter-callback', {
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

// Route pour gérer le callback Twitter/X OAuth
app.get('/api/twitter-callback', async (req, res) => {
  try {
    const { code, state } = req.query;

    // Pour le callback, on doit récupérer l'UID depuis la query string ou session
    // Modification nécessaire: ajouter l'UID dans l'URL de callback
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
      redirectUri: 'http://localhost:3000/api/twitter-callback',
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
    res.redirect('http://localhost:3000/');
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

// Route pour générer des tweets
app.post('/api/generate-tweets', async (req, res) => {
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
      'question-provocante',
      'metaphore-creative',
      'style-personnel',
    ];

    const modePrompts = {
     'tweet-viral': (template) => `Generate a tweet using this EXACT structure: "${tweetTemplates[template].structure}"\nContent based on: "${userComment}"\nContext: "${originalTweet || ''}"\nExample of this structure: "${tweetTemplates[template].example}"\nFollow the structure precisely but adapt the content. Max 280 chars, no hashtags/emojis.${styleContext}`,
  'critique-constructive': (template) => `Generate a constructive critique tweet using this EXACT structure: "${tweetTemplates[template].structure}"\nContent based on: "${userComment}"\nContext: "${originalTweet || ''}"\nExample: "${tweetTemplates[template].example}"\nFollow the structure precisely. Max 280 chars, no hashtags/emojis.${styleContext}`,
  'thread-twitter': (template) => `Generate the first tweet of a thread using this EXACT structure: "${tweetTemplates[template].structure}"\nContent based on: "${userComment}"\nContext: "${originalTweet || ''}"\nExample: "${tweetTemplates[template].example}"\nFollow the structure precisely. Max 280 chars, no hashtags/emojis.${styleContext}`,
  'reformulation-simple': (template) => `Generate a simple reformulation using this EXACT structure: "${tweetTemplates[template].structure}"\nContent based on: "${userComment}"\nContext: "${originalTweet || ''}"\nExample: "${tweetTemplates[template].example}"\nFollow the structure precisely. Max 280 chars, no hashtags/emojis.${styleContext}`,
  'angle-contrarian': (template) => `Generate a contrarian angle using this EXACT structure: "${tweetTemplates[template].structure}"\nContent based on: "${userComment}"\nContext: "${originalTweet || ''}"\nExample: "${tweetTemplates[template].example}"\nFollow the structure precisely. Max 280 chars, no hashtags/emojis.${styleContext}`,
  'storytelling': (template) => `Generate a storytelling tweet using this EXACT structure: "${tweetTemplates[template].structure}"\nContent based on: "${userComment}"\nContext: "${originalTweet || ''}"\nExample: "${tweetTemplates[template].example}"\nFollow the structure precisely. Max 280 chars, no hashtags/emojis.${styleContext}`,
  'question-provocante': (template) => `Generate a provocative question using this EXACT structure: "${tweetTemplates[template].structure}"\nContent based on: "${userComment}"\nContext: "${originalTweet || ''}"\nExample: "${tweetTemplates[template].example}"\nFollow the structure precisely. Max 280 chars, no hashtags/emojis.${styleContext}`,
  'metaphore-creative': (template) => `Generate a creative metaphor using this EXACT structure: "${tweetTemplates[template].structure}"\nContent based on: "${userComment}"\nContext: "${originalTweet || ''}"\nExample: "${tweetTemplates[template].example}"\nFollow the structure precisely. Max 280 chars, no hashtags/emojis.${styleContext}`,
  'style-personnel': (template) => `Generate a personal style tweet using this EXACT structure: "${tweetTemplates[template].structure}"\nContent based on: "${userComment}"\nStyle (tone: ${user.userStyle.tone}, words: ${Array.from(user.userStyle.vocabulary).slice(-5).join(', ')})\nContext: "${originalTweet || ''}"\nExample: "${tweetTemplates[template].example}"\nFollow the structure precisely. Max 280 chars, no hashtags/emojis.${styleContext}`${Array.from(user.userStyle.vocabulary)
        .slice(-5)
        .join(', ')}). Context: "${originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
    };

    const filteredModes = modeFilter && modes.includes(modeFilter) ? [modeFilter] : modes;
const prompts = filteredModes.map(mode => {
  const selectedTemplate = selectTemplate(mode);
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
        const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
          messages: [
            {
              role: 'system',
              content:
                'Tweet expert. Generate original tweets based on user comment. Secondary context: original tweet. Max 280 chars, no hashtags/emojis. Respond only with the tweet without ""',
            },
            { role: 'user', content: prompt },
          ],
          model: 'llama3-8b-8192',
          temperature: 0.7,
          max_tokens: 100,
        });

        const tweet = response.data.choices[0].message.content.trim();
        if (tweet.length > 280) {
          console.warn(`⚠️ Tweet trop long pour mode ${filteredModes[index]}: ${tweet.length} chars`);
          return { success: false, tweet: tweet.substring(0, 280), mode: filteredModes[index], error: 'Tweet trop long' };
        }
        return { success: true, tweet, mode: filteredModes[index] };
      } catch (error) {
        console.error(`❌ Erreur mode ${filteredModes[index]}:`, error.message, error.stack);
        return {
          success: false,
          tweet: `Erreur: Échec génération pour ${filteredModes[index]}`,
          mode: filteredModes[index],
          error: error.message,
        };
      }
    });

    const results = await Promise.all(promises);
    const generatedTweets = results.map(r => r.tweet);
    const usedModes = results.map(r => r.mode);
// Ajouter avant la génération des prompts
const selectedTemplates = filteredModes.map(mode => selectTemplate(mode));

// Puis modifier les prompts pour utiliser les templates sélectionnés
const prompts = filteredModes.map((mode, index) => {
  const selectedTemplate = selectedTemplates[index];
  return modePrompts[mode](selectedTemplate);
});

// Et modifier tweetData pour inclure les templates
const tweetData = {
  id: uuidv4(),
  timestamp: new Date(),
  lastModified: new Date(),
  originalTweet: originalTweet || null,
  userComment: userComment.trim(),
  context: context || null,
  generatedTweets,
  modesUsed: usedModes,
  templatesUsed: selectedTemplates, // NOUVEAU
  used: false,
};
    user.generatedTweetsHistory.push(tweetData);
    if (user.generatedTweetsHistory.length > 100) {
      user.generatedTweetsHistory = user.generatedTweetsHistory.slice(-100);
    }

    await saveUserData(uid);
    console.log(`✅ Tweets générés pour ${uid}: ${generatedTweets.length}`);
    res.json({
      success: true,
      data: tweetData,
      lastModified: tweetData.lastModified,
    });
  } catch (error) {
    console.error(`❌ Erreur génération tweets pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({
      success: false,
      error: 'Erreur génération tweets',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
    });
  }
});

// Route pour régénérer un tweet
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
      'tweet-viral': `Generate a viral tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'critique-constructive': `Generate a constructive critique tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'thread-twitter': `Generate the first tweet of a thread based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'reformulation-simple': `Generate a simple reformulation tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'angle-contrarian': `Generate a contrarian angle tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'storytelling': `Generate a storytelling tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'question-provocante': `Generate a provocative question tweet based on: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'metaphore-creative': `Generate a creative metaphor tweet for: "${tweetGroup.userComment}". Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
      'style-personnel': `Generate a personal style tweet based on: "${tweetGroup.userComment}". Style (tone: ${user.userStyle.tone}, words: ${Array.from(user.userStyle.vocabulary)
        .slice(-5)
        .join(', ')}). Context: "${tweetGroup.originalTweet || ''}". Max 280 chars, no hashtags/emojis.${styleContext}`,
    };

    const prompt = modePrompts[mode];
    if (!prompt) {
      return res.status(400).json({ success: false, error: 'Mode invalide' });
    }

    const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
      messages: [
        {
          role: 'system',
          content:
            'Tweet expert. Generate original tweets based on user comment. Secondary context: original tweet. Max 280 chars, no hashtags/emojis. Respond only with the tweet',
        },
        { role: 'user', content: prompt },
      ],
      model: 'llama3-8b-8192',
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
    tweetGroup.lastModified = new Date();

    const scheduledTweet = user.scheduledTweets.find(t => t.tweetId === tweetId && t.tweetIndex === parseInt(tweetIndex));
    if (scheduledTweet) {
      scheduledTweet.content = newTweet;
      scheduledTweet.lastModified = new Date();
    }

    await saveUserData(uid);
    console.log(`✅ Tweet régénéré pour ${uid}: ${newTweet.substring(0, 50)}...`);
    res.json({
      success: true,
      data: { tweet: newTweet, mode, lastModified: tweetGroup.lastModified },
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
      model: 'llama3-8b-8192',
      temperature: 0.7,
      max_tokens: 200,
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





//polar stuf

app.get('/api/subscription-status', verifyToken, async (req, res) => {
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
app.post('/api/create-checkout', verifyToken, async (req, res) => {
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
//end polar stuff





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

// Route pour l'interface web
app.get('/', async (req, res) => {
  const authHeader = req.headers.authorization;
  let uid = 'anonymous';
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const idToken = authHeader.split('Bearer ')[1];
      const decodedToken = await admin.auth().verifyIdToken(idToken, true);
      uid = decodedToken.uid;
      await initializeUserData(uid);
    } catch (error) {
      console.error('❌ Erreur vérification token pour /:', error.message, error.stack);
    }
  }

  const html = await fs.readFile(path.join(__dirname, 'public', 'index.html'), 'utf8');
  const modifiedHtml = html.replace('<!-- UID_PLACEHOLDER -->', `<script>window.__USER_UID__ = "${uid}";</script>`);
  res.send(modifiedHtml);
});

// Route pour vérifier l'état du serveur
app.get('/health', async (req, res) => {
  try {
    const uid = req.user?.uid || 'anonymous';
    await initializeUserData(uid);
    const user = userData.get(uid) || {
      generatedTweetsHistory: [],
      scheduledTweets: [],
      userStyle: { writings: [], styleProgress: 0 },
    };

    res.json({
      status: 'OK',
      timestamp: new Date(),
      version: '2.3.0',
      tweetsCount: user.generatedTweetsHistory.length,
      scheduledTweetsCount: user.scheduledTweets.length,
      scheduledActiveCount: user.scheduledTweets.filter(t => t.status === 'scheduled').length,
      publishedCount: user.scheduledTweets.filter(t => t.status === 'published').length,
      failedCount: user.scheduledTweets.filter(t => t.status === 'failed').length,
      userStyleWritings: user.userStyle.writings.length,
      styleProgress: user.userStyle.styleProgress,
      userId: uid,
      twitterAuthenticated: !!user.twitterClient,
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
  console.error(`❌ Erreur globale pour ${req.user?.uid || 'anonymous'}:`, error.message, error.stack);
  res.status(error.message.includes('Type de fichier non supporté') ? 400 : 500).json({
    success: false,
    error: error.message.includes('Type de fichier non supporté') ? error.message : 'Erreur serveur interne',
    details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
  });
});

// Démarrer le serveur
async function startServer() {
  try {
    console.log('🔄 Initialisation du serveur...');
    startScheduleChecker();
    app.listen(PORT, '0.0.0.0', () => {
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
      console.log(`   - POST /api/generate-tweets`);
      console.log(`   - POST /api/regenerate-tweet`);
      console.log(`   - POST /api/learn-content`);
      console.log(`   - GET  /api/tweets-history`);
      console.log(`   - POST /api/tweet-used`);
      console.log(`   - POST /api/edit-tweet`);
      console.log(`   - POST /api/schedule-tweet`);
      console.log(`   - GET  /api/tweets`);
      console.log(`   - DELETE /api/tweets/:id`);
      console.log(`   - POST /api/tweets/:id/publish`);
      console.log(`   - GET  /api/user-stats`);
      console.log(`   - GET  /health`);
      console.log(`✅ Serveur prêt! (Firebase Auth uniquement)`);
    });
  } catch (error) {
    console.error('❌ Erreur lors du démarrage du serveur:', error.message, error.stack);
    process.exit(1);
  }
}

// Appeler la fonction pour démarrer le serveur
startServer();*/


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
require('dotenv').config();
const serviceAccount = require('./firebase-service-account.json'); // Assuming local file for development

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
  'question-provocante': ['oneliner', 'basic'],
  'metaphore-creative': ['equation', 'basic'],
  'style-personnel': ['basic', 'oneliner', 'bullet_points']
};

// Fonction pour sélectionner un template
function selectTemplate(mode) {
  const availableTemplates = templateModeMapping[mode] || Object.keys(tweetTemplates);
  const randomIndex = Math.floor(Math.random() * availableTemplates.length);
  return availableTemplates[randomIndex];
}

// Initialisation de l'application Express
const app = express();
const PORT = process.env.PORT || 3000;

// Configuration des middlewares
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://127.0.0.1:8080', 'https://x.com'],
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'If-None-Match', 'Authorization', 'X-User-ID', 'Accept', 'Origin', 'X-Requested-With'],
  credentials: true,
}));
app.use(express.json());

// Servir les fichiers statiques
app.use('/Uploads', express.static(path.join(__dirname, 'Uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// Initialisation Firebase Admin
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
const db = admin.firestore(); // Define db after initialization

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
function getUserFilePaths(uid) {
  return {
    userStyleFile: path.join(__dirname, 'data', uid, 'userStyle.json'),
    tweetsHistoryFile: path.join(__dirname, 'data', uid, 'tweetsHistory.json'),
    scheduledTweetsFile: path.join(__dirname, 'data', uid, 'scheduledTweets.json'),
    twitterTokensFile: path.join(__dirname, 'data', uid, 'twitterTokens.json'),
  };
}

// Initialisation des données utilisateur
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
      twitterUser: null, // Stocke username, handle, profile_picture
      dataLock: false,
      sessionStart: new Date(),
    });
    tweetIdCounters.set(uid, 1);

    const { userStyleFile, tweetsHistoryFile, scheduledTweetsFile, twitterTokensFile } = getUserFilePaths(uid);
    const userDir = path.dirname(userStyleFile);

    try {
      await fs.mkdir(userDir, { recursive: true });
      console.log(`✅ Dossier créé: ${userDir}`);
    } catch (error) {
      console.error(`❌ Erreur création dossier ${userDir}:`, error.message, error.stack);
      throw new Error(`Échec création dossier utilisateur: ${error.message}`);
    }

    try {
      const userStyleData = await fs.readFile(userStyleFile, 'utf8').catch(() => '{}');
      userData.get(uid).userStyle = {
        ...defaultUserStyle,
        ...JSON.parse(userStyleData, (key, value) => {
          if (key === 'vocabulary') return new Set(value);
          return value;
        }),
      };
      console.log(`✅ Loaded userStyle for user ${uid}`);
    } catch (error) {
      console.error(`❌ Erreur lecture ${userStyleFile}:`, error.message, error.stack);
    }

    try {
      const tweetsHistoryData = await fs.readFile(tweetsHistoryFile, 'utf8').catch(() => '[]');
      userData.get(uid).generatedTweetsHistory = JSON.parse(tweetsHistoryData);
      if (userData.get(uid).generatedTweetsHistory.length > 0) {
        const maxId = Math.max(...userData.get(uid).generatedTweetsHistory.map(t => parseInt(t.id) || 0));
        if (maxId >= tweetIdCounters.get(uid)) tweetIdCounters.set(uid, maxId + 1);
      }
      console.log(`✅ Loaded tweetsHistory for user ${uid}`);
    } catch (error) {
      console.error(`❌ Erreur lecture ${tweetsHistoryFile}:`, error.message, error.stack);
    }

    try {
      const scheduledTweetsData = await fs.readFile(scheduledTweetsFile, 'utf8').catch(() => '[]');
      userData.get(uid).scheduledTweets = JSON.parse(scheduledTweetsData, (key, value) => {
        if (key === 'datetime' || key === 'createdAt' || key === 'lastModified' || key === 'publishedAt' || key === 'failedAt') {
          return value ? new Date(value) : null;
        }
        return value;
      });
      if (userData.get(uid).scheduledTweets.length > 0) {
        const maxId = Math.max(...userData.get(uid).scheduledTweets.map(t => t.id || 0));
        if (maxId >= tweetIdCounters.get(uid)) tweetIdCounters.set(uid, maxId + 1);
      }
      console.log(`✅ Loaded scheduledTweets for user ${uid}`);
    } catch (error) {
      console.error(`❌ Erreur lecture ${scheduledTweetsFile}:`, error.message, error.stack);
    }

    try {
      const twitterTokensData = await fs.readFile(twitterTokensFile, 'utf8').catch(() => null);
      if (twitterTokensData) {
        const tokens = JSON.parse(twitterTokensData);
        const tokensObj = tokens.twitterTokens || tokens; // Compatibilité avec ancien format
        userData.get(uid).twitterTokens = tokensObj;
        userData.get(uid).twitterClient = new TwitterApi(tokensObj.access_token);
        userData.get(uid).twitterUser = tokens.twitterUser || tokensObj.twitterUser;
        console.log(`✅ Loaded Twitter tokens for user ${uid}`);
      }
    } catch (error) {
      console.error(`❌ Erreur lecture ${twitterTokensFile}:`, error.message, error.stack);
    }
  }
}

// Sauvegarde des données utilisateur
async function saveUserData(uid) {
  const user = userData.get(uid);
  if (!user || user.dataLock) {
    console.log(`🔒 Sauvegarde données ignorée pour ${uid} (verrou ou données absentes)`);
    return;
  }
  user.dataLock = true;
  const { userStyleFile, tweetsHistoryFile, scheduledTweetsFile, twitterTokensFile } = getUserFilePaths(uid);
  try {
    await fs.mkdir(path.dirname(userStyleFile), { recursive: true });
    await Promise.all([
      fs.writeFile(userStyleFile, JSON.stringify(user.userStyle, (key, value) => {
        if (value instanceof Set) return Array.from(value);
        return value;
      }, 2)),
      fs.writeFile(tweetsHistoryFile, JSON.stringify(user.generatedTweetsHistory, null, 2)),
      fs.writeFile(scheduledTweetsFile, JSON.stringify(user.scheduledTweets, null, 2)),
      user.twitterTokens
        ? fs.writeFile(twitterTokensFile, JSON.stringify({
            twitterTokens: user.twitterTokens,
            twitterUser: user.twitterUser,
          }, null, 2))
        : Promise.resolve(),
    ]);
    console.log(`✅ Données sauvegardées pour ${uid}`);
  } catch (error) {
    console.error(`❌ Erreur sauvegarde données pour ${uid}:`, error.message, error.stack);
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
    const uploadPath = path.join(__dirname, 'Uploads', req.user ? req.user.uid : 'anonymous');
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
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('❌ Aucun ou mauvais en-tête Authorization', { path: req.path, authHeader });
    return res.status(401).json({ success: false, error: 'Aucun ou mauvais en-tête Authorization' });
  }

  const idToken = authHeader.split('Bearer ')[1];
  try {
    console.log(`🔍 Vérification token pour ${req.path}: ${idToken.substring(0, 10)}...`);
    const decodedToken = await admin.auth().verifyIdToken(idToken, true);
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
app.post('/api/login', async (req, res) => {
  try {
    const uid = req.user.uid;
    console.log(`🔍 Connexion pour UID: ${uid}`);
    await initializeUserData(uid);
    res.json({ success: true, message: 'Connexion réussie', uid });
  } catch (error) {
    console.error(`❌ Erreur traitement connexion pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({ success: false, error: 'Échec traitement connexion', details: error.message });
  }
});

// Route pour la déconnexion Firebase
app.post('/api/logout', async (req, res) => {
  try {
    const uid = req.user.uid;
    console.log(`🔍 Déconnexion pour UID: ${uid}`);
    await admin.auth().revokeRefreshTokens(uid);
    userData.delete(uid);
    tweetIdCounters.delete(uid);
    console.log(`✅ Déconnexion réussie pour UID: ${uid}`);
    res.json({ success: true, message: 'Déconnexion réussie' });
  } catch (error) {
    console.error(`❌ Erreur déconnexion pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({ success: false, error: 'Échec déconnexion', details: error.message });
  }
});

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

    const authLink = await twitterOAuthClient.generateOAuth2AuthLink('http://localhost:3000/api/twitter-callback', {
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
      redirectUri: 'http://localhost:3000/api/twitter-callback',
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
    res.redirect('http://localhost:3000/');
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

// Route pour générer des tweets avec système de templates
app.post('/api/generate-tweets', async (req, res) => {
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
      'question-provocante',
      'metaphore-creative',
      'style-personnel',
    ];

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

      'question-provocante': (template) => `Write a provocative question tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
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
        const response = await axiosInstance.post('https://api.groq.com/openai/v1/chat/completions', {
          messages: [
            {
              role: 'system',
              content:
                'Tweet expert. Generate original tweets based on user comment using EXACT structure provided. Secondary context: original tweet. Max 280 chars, no hashtags/emojis. Respond only with the tweet without quotes',
            },
            { role: 'user', content: prompt },
          ],
          model: 'llama3-8b-8192',
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
        console.error(`❌ Erreur mode ${filteredModes[index]}:`, error.message, error.stack);
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

    const tweetData = {
      id: uuidv4(),
      timestamp: new Date(),
      lastModified: new Date(),
      originalTweet: originalTweet || null,
      userComment: userComment.trim(),
      context: context || null,
      generatedTweets,
      modesUsed: usedModes,
      templatesUsed: usedTemplates, // NOUVEAU
      used: false,
    };

    user.generatedTweetsHistory.push(tweetData);
    if (user.generatedTweetsHistory.length > 100) {
      user.generatedTweetsHistory = user.generatedTweetsHistory.slice(-100);
    }

    await saveUserData(uid);
    console.log(`✅ Tweets générés pour ${uid}: ${generatedTweets.length} avec templates: ${usedTemplates.join(', ')}`);
    res.json({
      success: true,
      data: tweetData,
      lastModified: tweetData.lastModified,
    });
  } catch (error) {
    console.error(`❌ Erreur génération tweets pour ${req.user.uid}:`, error.message, error.stack);
    res.status(500).json({
      success: false,
      error: 'Erreur génération tweets',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Erreur serveur interne',
    });
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

      'question-provocante': (template) => `Generate a provocative question tweet using this EXACT structure and RESPOND WITH THE TWEET ONLY without any note or remark , ONLY THE TWEEET , NO HASTAGS OR QUOTES OR ANYTHING,  RAW TEXT: "${tweetTemplates[template].structure}"
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
      model: 'llama3-8b-8192',
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
      model: 'llama3-8b-8192',
      temperature: 0.7,
      max_tokens: 200,
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

// Route pour l'interface web
app.get('/', async (req, res) => {
  const authHeader = req.headers.authorization;
  let uid = 'anonymous';
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const idToken = authHeader.split('Bearer ')[1];
      const decodedToken = await admin.auth().verifyIdToken(idToken, true);
      uid = decodedToken.uid;
      await initializeUserData(uid);
    } catch (error) {
      console.error('❌ Erreur vérification token pour /:', error.message, error.stack);
    }
  }

  const html = await fs.readFile(path.join(__dirname, 'public', 'index.html'), 'utf8');
  const modifiedHtml = html.replace('<!-- UID_PLACEHOLDER -->', `<script>window.__USER_UID__ = "${uid}";</script>`);
  res.send(modifiedHtml);
});

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

// Démarrer le serveur
async function startServer() {
  try {
    console.log('🔄 Initialisation du serveur avec système de templates...');
    console.log(`📋 Templates disponibles: ${Object.keys(tweetTemplates).join(', ')}`);
    startScheduleChecker();
    app.listen(PORT, '0.0.0.0', () => {
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

// Appeler la fonction pour démarrer le serveur
startServer();
