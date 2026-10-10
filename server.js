const express = require('express');
const http = require('node:http');
const https = require('node:https');
const { WebSocketServer, WebSocket } = require('ws');
const cors = require('cors');
const multer = require('multer');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { sendVerificationCode } = require('./mailer');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3678;
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Trust reverse proxy (nginx / Cloudflare) for correct client IPs in rate limiters
app.set('trust proxy', true);

// Rate Limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Слишком много попыток входа. Подождите немного.' },
});

const codeRequestLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Слишком много запросов кода. Попробуйте через 10 минут.' },
});

// Middlewares
app.use(cors());
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

// Secure static uploads: enforce nosniff and cross-origin resource policy
app.use('/uploads', (req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  next();
}, express.static(UPLOADS_DIR));

// Logging
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    console.log(`[${req.method}] ${req.originalUrl} -> ${res.statusCode} (${Date.now() - start}ms)`);
  });
  next();
});

// Multer for file uploads with extension sanitization (prevents Stored XSS via .html, .svg, scripts)
const DANGEROUS_EXTS = new Set([
  '.html', '.htm', '.xhtml', '.svg', '.xml', '.php', '.phtml', '.php3', '.php4', '.php5',
  '.js', '.mjs', '.cjs', '.jsp', '.asp', '.aspx', '.sh', '.bash', '.exe', '.bat', '.cmd',
  '.scr', '.vbs', '.py', '.pl', '.cgi', '.jar'
]);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    let ext = (path.extname(file.originalname) || '').toLowerCase();
    if (DANGEROUS_EXTS.has(ext)) {
      ext = '.bin';
    }
    cb(null, `${Date.now()}_${crypto.randomBytes(8).toString('hex')}${ext}`);
  },
});
const upload = multer({ storage, limits: { fileSize: 100 * 1024 * 1024 } });

// Helper to get base URL
function getBaseUrl(req) {
  const host = req.get('host') || `localhost:${PORT}`;
  const protocol = req.protocol === 'https' || req.get('x-forwarded-proto') === 'https' ? 'https' : 'http';
  return `${protocol}://${host}`;
}

// Password verification and hashing helpers
function verifyPassword(plain, stored) {
  if (!stored || !plain) return false;
  if (stored.startsWith('$2a$') || stored.startsWith('$2b$') || stored.startsWith('$2y$')) {
    return bcrypt.compareSync(plain, stored);
  }
  return stored === plain;
}

function hashPassword(plain) {
  return bcrypt.hashSync(plain, 10);
}

// Access control helpers
function getChatMember(chatId, userId) {
  return db.prepare('SELECT * FROM chat_members WHERE chatId = ? AND userId = ?').get(chatId, userId);
}

function isUserBlockedBy(targetUserId, checkingUserId) {
  return Boolean(db.prepare('SELECT 1 FROM blocked_users WHERE userId = ? AND blockedId = ?').get(checkingUserId, targetUserId));
}

// Authentication Middleware with Token TTL (60 days)
const TOKEN_TTL_MS = 60 * 24 * 60 * 60 * 1000;

function authRequired(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const token = authHeader.slice(7);
  const tokenRow = db.prepare('SELECT userId, createdAt FROM tokens WHERE token = ? AND type = ?').get(token, 'access');
  if (!tokenRow) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  if (tokenRow.createdAt) {
    const ageMs = Date.now() - new Date(tokenRow.createdAt).getTime();
    if (ageMs > TOKEN_TTL_MS) {
      db.prepare('DELETE FROM tokens WHERE token = ?').run(token);
      return res.status(401).json({ error: 'Token expired' });
    }
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(tokenRow.userId);
  if (!user) {
    return res.status(401).json({ error: 'User not found' });
  }
  req.user = user;
  next();
}

function optionalAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    const tokenRow = db.prepare('SELECT userId, createdAt FROM tokens WHERE token = ? AND type = ?').get(token, 'access');
    if (tokenRow) {
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(tokenRow.userId);
      if (user) req.user = user;
    }
  }
  next();
}

// WebSocket connections: userId -> Set<WebSocket>
const clients = new Map();

function addClient(userId, ws) {
  if (!clients.has(userId)) {
    clients.set(userId, new Set());
  }
  clients.get(userId).add(ws);
  broadcastPresence(userId, true);
}

function removeClient(userId, ws) {
  if (clients.has(userId)) {
    const set = clients.get(userId);
    set.delete(ws);
    if (set.size === 0) {
      clients.delete(userId);
      broadcastPresence(userId, false);
    }
  }
}

function isUserOnline(userId) {
  return clients.has(userId) && clients.get(userId).size > 0;
}

// 1-on-1 Audio Calls Signaling State
const activeCalls = new Map(); // callId -> { callerId, calleeId, status, timeoutTimer, createdAt, connectedAt }
const userCallMap = new Map(); // userId -> callId

function sendToUser(userId, message) {
  if (clients.has(userId)) {
    const data = typeof message === 'string' ? message : JSON.stringify(message);
    for (const ws of clients.get(userId)) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(data);
      }
    }
  }
}

function broadcastToChat(chatId, message, excludeUserId = null) {
  const members = db.prepare('SELECT userId FROM chat_members WHERE chatId = ?').all(chatId);
  const data = typeof message === 'string' ? message : JSON.stringify(message);
  for (const m of members) {
    if (excludeUserId && m.userId === excludeUserId) continue;
    sendToUser(m.userId, data);
  }
}

function broadcastMessageUpdate(chatId, rawMsg, extraPayload = {}) {
  const members = db.prepare('SELECT userId FROM chat_members WHERE chatId = ?').all(chatId);
  for (const m of members) {
    const formatted = formatMessage(rawMsg, m.userId);
    sendToUser(m.userId, JSON.stringify({
      type: 'message',
      payload: {
        chatId,
        ...formatted,
        ...extraPayload,
      },
    }));
  }
}

function broadcastMentionsRead(chatId, userId, unreadMentions = 0) {
  sendToUser(userId, JSON.stringify({
    type: 'mentions-read',
    payload: { chatId, unreadMentions }
  }));
}

function broadcastPresence(userId, online) {
  const presenceMsg = JSON.stringify({
    type: 'presence',
    payload: { userId, online },
  });
  // Send presence to user's peers
  const peers = db.prepare(`
    SELECT DISTINCT cm2.userId FROM chat_members cm1
    JOIN chat_members cm2 ON cm1.chatId = cm2.chatId
    WHERE cm1.userId = ? AND cm2.userId != ?
  `).all(userId, userId);
  for (const p of peers) {
    sendToUser(p.userId, presenceMsg);
  }
}

function formatUser(u, viewerId = null) {
  if (!u) return null;
  const isSelf = Boolean(viewerId && viewerId === u.id);
  let phone = '';
  if (isSelf) {
    phone = u.phone || '';
  } else {
    try {
      const p = db.prepare('SELECT phone FROM privacy_settings WHERE userId = ?').get(u.id);
      if (p && p.phone === 'everybody') {
        phone = u.phone || '';
      }
    } catch (_) {}
  }

  return {
    id: u.id,
    displayName: u.displayName || u.username || 'Пользователь',
    username: u.username || '',
    avatarUrl: u.avatarUrl || null,
    bio: u.bio || '',
    gender: u.gender || '',
    birthday: u.birthday || '',
    email: isSelf ? (u.email || '') : '',
    phone,
    profileMusicTitle: u.profileMusicTitle || null,
    profileMusicUrl: u.profileMusicUrl || null,
    online: isUserOnline(u.id),
    lastSeen: u.createdAt || new Date().toISOString(),
    coins: isSelf ? (u.coins !== undefined && u.coins !== null ? u.coins : 1000) : 0,
    verified: Boolean(u.verified),
    isVerified: Boolean(u.verified),
  };
}

function normalizeStorageKey(key) {
  if (!key) return null;
  if (typeof key === 'object') {
    key = key.url || key.storageKey || key.path || '';
  }
  if (typeof key !== 'string') return '';
  if (key.includes('/uploads/')) {
    return '/uploads/' + key.split('/uploads/')[1];
  }
  return key;
}

function formatPoll(poll, currentUserId) {
  if (!poll) return null;
  const options = (poll.options || []).map(opt => ({
    id: opt.id,
    text: opt.text || '',
    votes: typeof opt.votes === 'number' ? opt.votes : (opt.voterIds ? opt.voterIds.length : 0),
    voterIds: opt.voterIds || [],
  }));

  const allVoterIds = new Set(options.flatMap(o => o.voterIds || []));
  const myVotes = currentUserId
    ? options.filter(o => (o.voterIds || []).includes(currentUserId)).map(o => o.id)
    : (Array.isArray(poll.myVotes) ? poll.myVotes : []);

  return {
    question: poll.question || 'Опрос',
    options,
    myVotes,
    anonymous: poll.anonymous !== undefined ? Boolean(poll.anonymous) : true,
    multiple: Boolean(poll.multiple),
    quiz: Boolean(poll.quiz),
    correctOptionId: poll.correctOptionId || null,
    closed: Boolean(poll.closed),
    totalVoters: typeof poll.totalVoters === 'number' ? poll.totalVoters : allVoterIds.size,
  };
}

function formatMessage(m, currentUserId = null) {
  if (!m) return null;
  let senderName = 'Пользователь';
  let senderAvatarUrl = null;
  const sender = db.prepare('SELECT displayName, username, avatarUrl FROM users WHERE id = ?').get(m.senderId);
  if (sender) {
    senderName = sender.displayName || sender.username || 'Пользователь';
    senderAvatarUrl = sender.avatarUrl || null;
  }

  let rawAttachments = [];
  let images = [];
  let videos = [];
  let files = [];
  let voice = m.voice || null;
  let reactions = [];
  let myReactions = [];
  let envelopes = [];
  let poll = null;

  try { rawAttachments = JSON.parse(m.attachments || '[]'); } catch (_) {}
  try { images = JSON.parse(m.images || '[]'); } catch (_) {}
  try { videos = JSON.parse(m.videos || '[]'); } catch (_) {}
  try { files = JSON.parse(m.files || '[]'); } catch (_) {}
  try { reactions = JSON.parse(m.reactions || '[]'); } catch (_) {}
  try { envelopes = JSON.parse(m.envelopes || '[]'); } catch (_) {}
  try { if (m.poll) poll = JSON.parse(m.poll); } catch (_) {}

  // Construct standard attachments array
  const attachments = [];
  if (Array.isArray(rawAttachments) && rawAttachments.length > 0) {
    for (const att of rawAttachments) {
      const storageKey = normalizeStorageKey(att.storageKey || att.url);
      attachments.push({
        kind: att.kind || 'file',
        storageKey,
        mime: att.mime || 'application/octet-stream',
        meta: att.meta || { filename: att.filename || 'file', size: att.size || 0 },
        size: att.size || (att.meta ? att.meta.size : 0) || 0,
      });
    }
  } else {
    // Fallback: build from legacy images, videos, voice, files
    for (const img of images) {
      const storageKey = normalizeStorageKey(img);
      attachments.push({
        kind: 'image',
        storageKey,
        mime: 'image/jpeg',
        meta: { filename: (typeof img === 'object' && img.filename) || 'part0.jpg', size: (typeof img === 'object' && img.size) || 0 },
        size: (typeof img === 'object' && img.size) || 0,
      });
    }
    for (const vid of videos) {
      const storageKey = normalizeStorageKey(vid);
      attachments.push({
        kind: 'video',
        storageKey,
        mime: 'video/mp4',
        meta: { filename: (typeof vid === 'object' && vid.filename) || 'part0.mp4', size: (typeof vid === 'object' && vid.size) || 0 },
        size: (typeof vid === 'object' && vid.size) || 0,
      });
    }
    if (voice) {
      const storageKey = normalizeStorageKey(voice);
      attachments.push({
        kind: 'audio',
        storageKey,
        mime: 'audio/mp4',
        meta: { filename: 'part0.m4a', size: 0 },
        size: 0,
      });
    }
    for (const f of files) {
      const storageKey = normalizeStorageKey(f);
      const isMusic = Boolean((typeof f === 'object' && f.isMusic) || (f.mime && f.mime.startsWith('audio/')));
      attachments.push({
        kind: isMusic ? 'audio' : 'file',
        storageKey,
        mime: (typeof f === 'object' && f.mime) || (isMusic ? 'audio/mpeg' : 'application/octet-stream'),
        meta: { filename: (typeof f === 'object' && f.filename) || (isMusic ? 'track.mp3' : 'file'), size: (typeof f === 'object' && f.size) || 0 },
        size: (typeof f === 'object' && f.size) || 0,
      });
    }
  }

  // Populate client convenience fields
  const imageKeys = attachments.filter(a => a.kind === 'image').map(a => a.storageKey);
  const videoKeys = attachments.filter(a => a.kind === 'video').map(a => a.storageKey);
  const voiceAtt = attachments.find(a => a.kind === 'audio' && (!a.meta?.filename || /^part\d*\.m4a$/i.test(a.meta.filename)));
  const voiceKey = voiceAtt ? voiceAtt.storageKey : (voice ? normalizeStorageKey(voice) : null);

  let body = m.body || '';
  if ((body === 'Голосовое сообщение' || body === 'Медиафайл') && (attachments.length > 0 || poll)) {
    body = '';
  }

  // Android APK expects reactions to be a JSONObject mapping emoji -> string[] of userIds
  const reactionsMap = {};
  if (Array.isArray(reactions)) {
    for (const r of reactions) {
      if (r && r.emoji) {
        const users = Array.isArray(r.users) ? r.users : [];
        if (users.length > 0) {
          reactionsMap[r.emoji] = users;
          if (currentUserId && users.includes(currentUserId)) {
            myReactions.push(r.emoji);
          }
        }
      }
    }
  } else if (reactions && typeof reactions === 'object' && reactions !== null) {
    for (const [emoji, users] of Object.entries(reactions)) {
      if (Array.isArray(users) && users.length > 0) {
        reactionsMap[emoji] = users;
        if (currentUserId && users.includes(currentUserId)) {
          myReactions.push(emoji);
        }
      }
    }
  }

  // Chat type
  let chatType = 'dm';
  try {
    const cRow = db.prepare('SELECT type FROM chats WHERE id = ?').get(m.chatId);
    if (cRow && cRow.type) chatType = cRow.type;
  } catch (_) {}

  // Reply / quote details
  let replyTo = null;
  let replyToName = null;
  let replyToBody = null;
  if (m.replyToId) {
    try {
      const parentMsg = db.prepare('SELECT * FROM messages WHERE id = ?').get(m.replyToId);
      if (parentMsg) {
        const parentSender = db.prepare('SELECT displayName, username FROM users WHERE id = ?').get(parentMsg.senderId);
        replyToName = parentSender ? (parentSender.displayName || parentSender.username) : 'Пользователь';
        replyToBody = parentMsg.body || '';
        replyTo = {
          id: parentMsg.id,
          chatId: parentMsg.chatId,
          senderId: parentMsg.senderId,
          senderName: replyToName,
          body: replyToBody,
        };
      }
    } catch (_) {}
  }

  return {
    id: m.id,
    chatId: m.chatId,
    chatType,
    senderId: m.senderId,
    senderName,
    senderAvatarUrl,
    body,
    time: m.createdAt,
    createdAt: m.createdAt,
    mine: currentUserId ? m.senderId === currentUserId : false,
    seq: m.seq,
    views: m.views || 0,
    viewCount: m.views || 0,
    isSystem: Boolean(m.isSystem),
    silent: Boolean(m.silent),
    edited: Boolean(m.edited),
    editedAt: m.edited ? (m.updatedAt || m.createdAt) : null,
    deletedAt: null,
    replyToId: m.replyToId || null,
    replyToName,
    replyToBody,
    replyTo,
    attachments,
    images: imageKeys,
    videos: videoKeys,
    files,
    voice: voiceKey,
    reactions: reactionsMap,
    myReactions,
    spoiler: Boolean(m.spoiler),
    isSticker: Boolean(m.isSticker),
    giftId: m.giftId || null,
    giftPrice: m.giftPrice || null,
    giftCaption: m.giftCaption || null,
    giftRevealed: Boolean(m.giftRevealed),
    locked: false,
    envelopes,
    senderDeviceId: m.senderDeviceId || null,
    commentCount: (() => {
      try {
        const cRow = db.prepare('SELECT COUNT(*) AS c FROM comments WHERE messageId = ?').get(m.id);
        return cRow && cRow.c > 0 ? cRow.c : null;
      } catch (_) { return null; }
    })(),
    poll: formatPoll(poll, currentUserId),
  };
}


// ==================== AUTH ROUTES ====================

// 1. Request email verification code
app.post('/auth/email/request-code', codeRequestLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ error: 'Укажите корректный email' });
  }

  const cleanEmail = email.trim().toLowerCase();
  const code = Math.floor(100000 + crypto.randomInt(0, 900000)).toString();
  const regToken = crypto.randomBytes(24).toString('hex');
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO email_codes (email, code, registrationToken, createdAt)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(email) DO UPDATE SET code = excluded.code, registrationToken = excluded.registrationToken, createdAt = excluded.createdAt
  `).run(cleanEmail, code, regToken, now);

  const sent = await sendVerificationCode(cleanEmail, code, 'Регистрация в SlimChat: проверочный код');
  if (!sent) {
    return res.status(500).json({ error: 'Не удалось отправить email. Проверьте адрес почты.' });
  }

  console.log(`[AUTH] Verification code sent to ${cleanEmail}`);
  res.json({ status: 'ok', message: 'Код подтверждения отправлен на вашу почту' });
});

// 2. Confirm email code
app.post('/auth/email/confirm-code', authLimiter, (req, res) => {
  const { email, code } = req.body || {};
  if (!email || !code) return res.status(400).json({ error: 'Email и код обязательны' });
  const cleanEmail = email.trim().toLowerCase();
  const row = db.prepare('SELECT * FROM email_codes WHERE email = ?').get(cleanEmail);
  if (!row || row.code !== String(code).trim()) {
    return res.status(400).json({ error: 'Неверный проверочный код' });
  }

  const createdTime = new Date(row.createdAt).getTime();
  if (Date.now() - createdTime > 10 * 60 * 1000) {
    db.prepare('DELETE FROM email_codes WHERE email = ?').run(cleanEmail);
    return res.status(400).json({ error: 'Срок действия кода истёк. Запросите новый.' });
  }

  res.json({ registrationToken: row.registrationToken });
});

// 3. Register user
app.post('/auth/register', authLimiter, (req, res) => {
  const { registrationToken, displayName, password, platform, username: customUsername } = req.body;

  let email = null;
  if (registrationToken) {
    const emailRow = db.prepare('SELECT email FROM email_codes WHERE registrationToken = ?').get(registrationToken);
    if (emailRow) {
      email = emailRow.email;
    }
  }

  if (!email) {
    return res.status(400).json({ error: 'Требуется подтверждение email перед регистрацией' });
  }

  // Prevent duplicate email registrations
  const existingEmail = db.prepare('SELECT id FROM users WHERE LOWER(email) = ?').get(email.toLowerCase());
  if (existingEmail) {
    return res.status(400).json({ error: 'Пользователь с таким email уже зарегистрирован' });
  }

  const userId = crypto.randomUUID();
  let username = customUsername ? customUsername.trim().toLowerCase().replace(/[^a-z0-9_]/g, '') : `user_${Date.now().toString().slice(-6)}`;
  if (!username) username = `user_${Date.now().toString().slice(-6)}`;

  const now = new Date().toISOString();
  const hashedPassword = (password && typeof password === 'string' && password.length >= 4)
    ? hashPassword(password)
    : hashPassword(crypto.randomBytes(16).toString('hex'));

  try {
    db.prepare(`
      INSERT INTO users (id, username, displayName, password, email, createdAt)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(userId, username, displayName || username, hashedPassword, email, now);
  } catch (e) {
    username = `${username}_${Math.floor(1000 + Math.random() * 9000)}`;
    try {
      db.prepare(`
        INSERT INTO users (id, username, displayName, password, email, createdAt)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(userId, username, displayName || username, hashedPassword, email, now);
    } catch (_) {
      return res.status(400).json({ error: 'Не удалось создать аккаунт. Попробуйте другое имя.' });
    }
  }

  // Delete registration token after user is successfully created
  if (registrationToken) {
    try {
      db.prepare('DELETE FROM email_codes WHERE registrationToken = ?').run(registrationToken);
    } catch (_) {}
  }

  const accessToken = crypto.randomBytes(32).toString('hex');
  const refreshToken = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO tokens (token, userId, type, createdAt) VALUES (?, ?, ?, ?)').run(accessToken, userId, 'access', now);
  db.prepare('INSERT INTO tokens (token, userId, type, createdAt) VALUES (?, ?, ?, ?)').run(refreshToken, userId, 'refresh', now);

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  const recoveryCode = crypto.randomBytes(8).toString('hex').match(/.{1,4}/g).join('-');
  res.json({
    accessToken,
    refreshToken,
    user: formatUser(user, userId),
    recoveryCode,
  });
});

// 4. Login user
app.post('/auth/login', authLimiter, (req, res) => {
  const { username, password, platform, loginToken } = req.body;
  if (!username || typeof username !== 'string' || !username.trim()) {
    return res.status(400).json({ error: 'Укажите логин или email' });
  }
  if (!password || typeof password !== 'string') {
    return res.status(400).json({ error: 'Введите пароль или код' });
  }

  const cleanUsername = username.trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?').get(cleanUsername, cleanUsername);
  if (!user) {
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }

  const inputSecret = password.trim();
  let verified = false;

  // 1. Check permanent password
  if (user.password && verifyPassword(inputSecret, user.password)) {
    verified = true;
  }

  // 2. Check active login code in auth_codes (for username or email)
  if (!verified) {
    const codeRow = db.prepare(`
      SELECT * FROM auth_codes 
      WHERE (LOWER(target) = ? OR LOWER(target) = ?) AND type = 'login' AND code = ?
    `).get(cleanUsername, (user.email || '').toLowerCase(), inputSecret);

    if (codeRow) {
      const createdTime = new Date(codeRow.createdAt).getTime();
      if (Date.now() - createdTime <= 15 * 60 * 1000) {
        verified = true;
        try {
          db.prepare('DELETE FROM auth_codes WHERE (LOWER(target) = ? OR LOWER(target) = ?) AND type = \'login\'')
            .run(cleanUsername, (user.email || '').toLowerCase());
        } catch (_) {}
      }
    }
  }

  // 3. Check active email code in email_codes
  if (!verified && user.email) {
    const emailCodeRow = db.prepare(`
      SELECT * FROM email_codes WHERE LOWER(email) = ? AND code = ?
    `).get(user.email.toLowerCase(), inputSecret);

    if (emailCodeRow) {
      const createdTime = new Date(emailCodeRow.createdAt).getTime();
      if (Date.now() - createdTime <= 15 * 60 * 1000) {
        verified = true;
        try {
          db.prepare('DELETE FROM email_codes WHERE LOWER(email) = ?').run(user.email.toLowerCase());
        } catch (_) {}
      }
    }
  }

  if (!verified) {
    return res.status(401).json({ error: 'Неверный пароль или код' });
  }

  // If password was stored as plain text, migrate it to bcrypt
  if (user.password && !user.password.startsWith('$2') && verifyPassword(inputSecret, user.password)) {
    try {
      db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashPassword(inputSecret), user.id);
    } catch (_) {}
  }

  const now = new Date().toISOString();
  const accessToken = crypto.randomBytes(32).toString('hex');
  const refreshToken = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO tokens (token, userId, type, createdAt) VALUES (?, ?, ?, ?)').run(accessToken, user.id, 'access', now);
  db.prepare('INSERT INTO tokens (token, userId, type, createdAt) VALUES (?, ?, ?, ?)').run(refreshToken, user.id, 'refresh', now);

  res.json({
    accessToken,
    refreshToken,
    user: formatUser(user, user.id),
  });
});

// 5. Refresh token
app.post('/auth/refresh', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });
  const row = db.prepare('SELECT userId FROM tokens WHERE token = ? AND type = ?').get(refreshToken, 'refresh');
  if (!row) return res.status(401).json({ error: 'Invalid refresh token' });

  const now = new Date().toISOString();
  const newAccessToken = crypto.randomBytes(32).toString('hex');
  const newRefreshToken = crypto.randomBytes(32).toString('hex');
  db.prepare('DELETE FROM tokens WHERE token = ?').run(refreshToken);
  db.prepare('INSERT INTO tokens (token, userId, type, createdAt) VALUES (?, ?, ?, ?)').run(newAccessToken, row.userId, 'access', now);
  db.prepare('INSERT INTO tokens (token, userId, type, createdAt) VALUES (?, ?, ?, ?)').run(newRefreshToken, row.userId, 'refresh', now);

  res.json({
    accessToken: newAccessToken,
    refreshToken: newRefreshToken,
  });
});

// App update config for APK in-app update prompt
let appUpdateConfig = {
  enabled: true,
  latestVersionCode: 298, // Код версии 14.81 в APK (обновлено)
  forceAll: false,
  title: 'Доступно обновление',
  message: 'Вышла новая версия приложения SlimChat You! Нажмите «Обновить АПК», чтобы загрузить обновление.',
  target: 'Обновить АПК',
  url: 'https://jxiwm.btxc.indevs.in/app.apk'
};

// 6. Current user info
app.get('/auth/me', authRequired, (req, res) => {
  const resp = { user: formatUser(req.user, req.user.id) };
  if (appUpdateConfig && appUpdateConfig.enabled) {
    const clientVer = parseInt(req.headers['x-slim-version'] || '0', 10);
    const needsUpdate = appUpdateConfig.forceAll || (clientVer > 0 && clientVer < appUpdateConfig.latestVersionCode);
    if (needsUpdate) {
      resp.update = {
        title: appUpdateConfig.title,
        message: appUpdateConfig.message,
        target: appUpdateConfig.target,
        url: appUpdateConfig.url,
      };
    }
  }
  res.json(resp);
});

app.get('/admin/update-prompt', (req, res) => {
  res.json(appUpdateConfig);
});

app.post('/admin/update-prompt', authRequired, (req, res) => {
  const { enabled, latestVersionCode, forceAll, title, message, target, url } = req.body;
  if (enabled !== undefined) appUpdateConfig.enabled = Boolean(enabled);
  if (latestVersionCode !== undefined) appUpdateConfig.latestVersionCode = Number(latestVersionCode);
  if (forceAll !== undefined) appUpdateConfig.forceAll = Boolean(forceAll);
  if (title) appUpdateConfig.title = title;
  if (message) appUpdateConfig.message = message;
  if (target) appUpdateConfig.target = target;
  if (url) appUpdateConfig.url = url;
  res.json({ status: 'ok', config: appUpdateConfig });
});

// 7. Update username
app.post('/auth/username', authRequired, (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username required' });
  const cleanUsername = username.trim().toLowerCase().replace(/[^a-z0-9_]/g, '');
  if (cleanUsername.length < 3) return res.status(400).json({ error: 'Минимум 3 символа' });
  try {
    db.prepare('UPDATE users SET username = ? WHERE id = ?').run(cleanUsername, req.user.id);
    res.json({ status: 'ok' });
  } catch (e) {
    res.status(400).json({ error: 'Username already taken' });
  }
});

// 8. Delete account
app.delete('/auth/account', authRequired, (req, res) => {
  db.prepare('DELETE FROM users WHERE id = ?').run(req.user.id);
  db.prepare('DELETE FROM tokens WHERE userId = ?').run(req.user.id);
  res.json({ status: 'ok' });
});

// 9. Devices
app.get('/auth/devices', authRequired, (req, res) => {
  let devices = db.prepare('SELECT * FROM devices WHERE userId = ?').all(req.user.id);
  if (devices.length === 0) {
    const defaultDev = {
      id: 'dev_' + req.user.id.slice(0, 8),
      userId: req.user.id,
      name: 'Android Phone',
      platform: 'Android',
      lastActive: new Date().toISOString(),
      loginIp: req.ip || '127.0.0.1',
      isCurrent: 1,
    };
    try {
      db.prepare('INSERT OR IGNORE INTO devices (id, userId, name, platform, lastActive, loginIp, isCurrent) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run(defaultDev.id, defaultDev.userId, defaultDev.name, defaultDev.platform, defaultDev.lastActive, defaultDev.loginIp, defaultDev.isCurrent);
      devices = [defaultDev];
    } catch (_) {}
  }
  res.json({
    devices: devices.map((d, i) => ({
      id: d.id,
      platform: d.platform || d.name || 'Android',
      lastSeenAt: d.lastActive || new Date().toISOString(),
      loginIp: d.loginIp || '127.0.0.1',
      isCurrent: d.isCurrent === 1 || i === 0,
    })),
  });
});

app.delete('/auth/devices', authRequired, (req, res) => {
  db.prepare('DELETE FROM devices WHERE userId = ? AND isCurrent != 1').run(req.user.id);
  res.json({ status: 'ok' });
});

app.delete('/auth/devices/:id', authRequired, (req, res) => {
  db.prepare('DELETE FROM devices WHERE userId = ? AND id = ?').run(req.user.id, req.params.id);
  res.json({ status: 'ok' });
});

// 10. QR Auth
app.get('/auth/qr/:token', (req, res) => {
  const token = req.params.token;
  let qr = db.prepare('SELECT * FROM qr_logins WHERE token = ?').get(token);
  if (!qr) {
    try {
      db.prepare('INSERT OR IGNORE INTO qr_logins (token, status, browser, ip, createdAt) VALUES (?, ?, ?, ?, datetime(\'now\'))')
        .run(token, 'pending', 'Web Browser', req.ip || '127.0.0.1');
    } catch (_) {}
    qr = { token, status: 'pending', browser: 'Web Browser', ip: req.ip || '127.0.0.1' };
  }
  res.json({
    browser: qr.browser || 'Web Browser',
    ip: qr.ip || '127.0.0.1',
    status: qr.status,
    token: qr.token,
    userId: qr.userId || null,
  });
});

app.post('/auth/qr/approve', authRequired, (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token required' });
  db.prepare(`
    INSERT INTO qr_logins (token, userId, status, browser, ip, createdAt)
    VALUES (?, ?, 'approved', 'Web Browser', ?, datetime('now'))
    ON CONFLICT(token) DO UPDATE SET userId = excluded.userId, status = 'approved'
  `).run(token, req.user.id, req.ip || '127.0.0.1');
  res.json({ status: 'ok' });
});

app.post('/auth/password/reset-request', codeRequestLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Укажите email' });
  const cleanEmail = email.trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE LOWER(email) = ?').get(cleanEmail);
  if (!user) {
    return res.status(404).json({ error: 'Пользователь с таким email не найден' });
  }
  const code = Math.floor(100000 + crypto.randomInt(0, 900000)).toString();
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO auth_codes (target, code, type, createdAt)
    VALUES (?, ?, 'password_reset', ?)
    ON CONFLICT(target) DO UPDATE SET code = excluded.code, type = excluded.type, createdAt = excluded.createdAt
  `).run(cleanEmail, code, now);

  const sent = await sendVerificationCode(cleanEmail, code, 'Сброс пароля в SlimChat');
  if (!sent) {
    return res.status(500).json({ error: 'Не удалось отправить email со сбросом пароля' });
  }
  res.json({ status: 'ok', message: 'Код сброса отправлен на вашу почту' });
});

// Request password reset code
app.post('/auth/password/request-code', codeRequestLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Укажите email' });
  const cleanEmail = email.trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE LOWER(email) = ?').get(cleanEmail);
  if (!user) {
    return res.status(404).json({ error: 'Пользователь с таким email не найден' });
  }
  const code = Math.floor(100000 + crypto.randomInt(0, 900000)).toString();
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO auth_codes (target, code, type, createdAt)
    VALUES (?, ?, 'password_reset', ?)
    ON CONFLICT(target) DO UPDATE SET code = excluded.code, type = excluded.type, createdAt = excluded.createdAt
  `).run(cleanEmail, code, now);

  const sent = await sendVerificationCode(cleanEmail, code, 'Сброс пароля в SlimChat');
  if (!sent) {
    return res.status(500).json({ error: 'Не удалось отправить email с кодом сброса' });
  }
  res.json({ status: 'ok', message: 'Код отправлен на ваш email' });
});

// Check password reset code
app.post('/auth/password/check-code', authLimiter, (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ error: 'Email и код обязательны' });
  const target = email.trim().toLowerCase();
  const row = db.prepare('SELECT * FROM auth_codes WHERE target = ? AND type = ?').get(target, 'password_reset');
  if (!row || row.code !== String(code).trim()) {
    return res.status(400).json({ error: 'Неверный код' });
  }
  const createdTime = new Date(row.createdAt).getTime();
  if (Date.now() - createdTime > 10 * 60 * 1000) {
    db.prepare('DELETE FROM auth_codes WHERE target = ? AND type = ?').run(target, 'password_reset');
    return res.status(400).json({ error: 'Срок действия кода истёк' });
  }
  const resetToken = crypto.randomBytes(32).toString('hex');
  db.prepare('UPDATE auth_codes SET resetToken = ? WHERE target = ?').run(resetToken, target);
  res.json({ status: 'ok', resetToken });
});

// Reset password with code and log in
app.post('/auth/password/reset-with-code-email', authLimiter, (req, res) => {
  const { email, code, password } = req.body;
  if (!email || !code || !password) return res.status(400).json({ error: 'Email, код и новый пароль обязательны' });
  if (password.length < 4) return res.status(400).json({ error: 'Пароль должен быть минимум 4 символа' });
  const target = email.trim().toLowerCase();
  const row = db.prepare('SELECT * FROM auth_codes WHERE target = ? AND type = ?').get(target, 'password_reset');
  if (!row || row.code !== String(code).trim()) {
    return res.status(400).json({ error: 'Неверный проверочный код' });
  }
  const createdTime = new Date(row.createdAt).getTime();
  if (Date.now() - createdTime > 10 * 60 * 1000) {
    db.prepare('DELETE FROM auth_codes WHERE target = ? AND type = ?').run(target, 'password_reset');
    return res.status(400).json({ error: 'Срок действия кода истёк' });
  }

  let user = db.prepare('SELECT * FROM users WHERE LOWER(email) = ? OR LOWER(username) = ?').get(target, target);
  if (!user) {
    return res.status(404).json({ error: 'Пользователь не найден' });
  }

  const hashedPassword = hashPassword(password);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashedPassword, user.id);
  db.prepare('DELETE FROM auth_codes WHERE target = ? AND type = ?').run(target, 'password_reset');

  const now = new Date().toISOString();
  const accessToken = crypto.randomBytes(32).toString('hex');
  const refreshToken = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO tokens (token, userId, type, createdAt) VALUES (?, ?, ?, ?)').run(accessToken, user.id, 'access', now);
  db.prepare('INSERT INTO tokens (token, userId, type, createdAt) VALUES (?, ?, ?, ?)').run(refreshToken, user.id, 'refresh', now);

  res.json({
    accessToken,
    refreshToken,
    user: formatUser(user, user.id),
  });
});

// Change password for authorized user
app.post('/auth/password/change', authRequired, (req, res) => {
  const { newPassword, currentPassword, oldPassword } = req.body;
  if (!newPassword || newPassword.length < 4) return res.status(400).json({ error: 'Новый пароль должен содержать минимум 4 символа' });
  const checkOld = currentPassword || oldPassword;
  if (!checkOld) {
    return res.status(400).json({ error: 'Введите текущий пароль' });
  }
  if (!verifyPassword(checkOld, req.user.password)) {
    return res.status(400).json({ error: 'Неверный текущий пароль' });
  }
  const hashedPassword = hashPassword(newPassword);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashedPassword, req.user.id);
  res.json({ status: 'ok' });
});

// Remove password for authorized user
app.post('/auth/password/remove', authRequired, (req, res) => {
  const { password } = req.body;
  if (!password || !verifyPassword(password, req.user.password)) {
    return res.status(400).json({ error: 'Неверный пароль' });
  }
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run('', req.user.id);
  res.json({ status: 'ok' });
});

// Login via code: request code
app.post('/auth/login/request-code', codeRequestLimiter, async (req, res) => {
  const { username, email } = req.body;
  const raw = (username || email || '').trim().replace(/^@/, '');
  if (!raw) return res.status(400).json({ error: 'Укажите логин или email' });

  let targetEmail = raw.includes('@') ? raw.toLowerCase() : null;
  if (!targetEmail) {
    const u = db.prepare('SELECT email FROM users WHERE LOWER(username) = ?').get(raw.toLowerCase());
    if (u && u.email && u.email.includes('@') && !u.email.endsWith('@slimchat.local')) {
      targetEmail = u.email;
    }
  }

  if (!targetEmail) {
    return res.status(400).json({ error: 'Для данного пользователя не привязана электронная почта' });
  }

  const code = Math.floor(100000 + crypto.randomInt(0, 900000)).toString();
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO auth_codes (target, code, type, createdAt)
    VALUES (?, ?, 'login', ?)
    ON CONFLICT(target) DO UPDATE SET code = excluded.code, type = excluded.type, createdAt = excluded.createdAt
  `).run(raw.toLowerCase(), code, now);

  const sent = await sendVerificationCode(targetEmail, code, 'Вход в SlimChat: проверочный код');
  if (!sent) {
    return res.status(500).json({ error: 'Не удалось отправить проверочный email' });
  }

  res.json({ status: 'ok', message: `Код отправлен на почту ${targetEmail}` });
});

// Login via code: confirm code
app.post('/auth/login/confirm-code', authLimiter, (req, res) => {
  const { username, email, code } = req.body;
  const raw = (username || email || '').trim().replace(/^@/, '');
  if (!raw || !code) return res.status(400).json({ error: 'Укажите логин и проверочный код' });

  let user = db.prepare('SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?').get(raw.toLowerCase(), raw.toLowerCase());
  if (!user) {
    return res.status(404).json({ error: 'Пользователь не найден' });
  }

  const cleanInput = String(code).trim();
  let verified = false;

  const row = db.prepare(`
    SELECT * FROM auth_codes 
    WHERE (LOWER(target) = ? OR LOWER(target) = ?) AND type = 'login' AND code = ?
  `).get(raw.toLowerCase(), (user.email || '').toLowerCase(), cleanInput);

  if (row) {
    const createdTime = new Date(row.createdAt).getTime();
    if (Date.now() - createdTime <= 15 * 60 * 1000) {
      verified = true;
      try {
        db.prepare('DELETE FROM auth_codes WHERE (LOWER(target) = ? OR LOWER(target) = ?) AND type = \'login\'')
          .run(raw.toLowerCase(), (user.email || '').toLowerCase());
      } catch (_) {}
    }
  }

  if (!verified && user.email) {
    const emailRow = db.prepare('SELECT * FROM email_codes WHERE LOWER(email) = ? AND code = ?').get(user.email.toLowerCase(), cleanInput);
    if (emailRow) {
      const createdTime = new Date(emailRow.createdAt).getTime();
      if (Date.now() - createdTime <= 15 * 60 * 1000) {
        verified = true;
        try {
          db.prepare('DELETE FROM email_codes WHERE LOWER(email) = ?').run(user.email.toLowerCase());
        } catch (_) {}
      }
    }
  }

  if (!verified) {
    return res.status(400).json({ error: 'Неверный или просроченный проверочный код' });
  }

  const now = new Date().toISOString();
  const accessToken = crypto.randomBytes(32).toString('hex');
  const refreshToken = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO tokens (token, userId, type, createdAt) VALUES (?, ?, ?, ?)').run(accessToken, user.id, 'access', now);
  db.prepare('INSERT INTO tokens (token, userId, type, createdAt) VALUES (?, ?, ?, ?)').run(refreshToken, user.id, 'refresh', now);

  res.json({
    accessToken,
    refreshToken,
    user: formatUser(user, user.id),
  });
});

// Logout
app.post('/auth/logout', (req, res) => {
  const { refreshToken } = req.body || {};
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (refreshToken) {
    db.prepare('DELETE FROM tokens WHERE token = ?').run(refreshToken);
  }
  if (token) {
    db.prepare('DELETE FROM tokens WHERE token = ?').run(token);
  }
  res.json({ status: 'ok' });
});

// Referral / Invites API
app.all('/auth/invites', authRequired, (req, res) => {
  const user = req.user;
  const code = user.username || user.id.slice(0, 8);
  try {
    db.prepare("UPDATE users SET referralCode = ? WHERE id = ? AND (referralCode IS NULL OR referralCode = '')").run(code, user.id);
  } catch (_) {}
  const fullUrl = `https://slimchat.me/i/${code}`;
  const invitedUsers = db.prepare('SELECT id, username, displayName, avatarUrl, createdAt FROM users WHERE invitedBy = ?').all(code);
  res.json({
    code,
    url: fullUrl,
    invites: invitedUsers.map(formatUser),
  });
});

// Coins API
app.get('/coins', authRequired, (req, res) => {
  const user = db.prepare('SELECT coins FROM users WHERE id = ?').get(req.user.id);
  const coins = user && typeof user.coins === 'number' ? user.coins : 1000;
  res.json({
    coins,
    balance: coins,
    status: 'ok',
  });
});

// ==================== PROFILE ROUTES ====================

app.patch('/profile', authRequired, (req, res) => {
  const { displayName, bio, gender, birthday, profileMusicTitle, profileMusicUrl } = req.body;
  db.prepare(`
    UPDATE users SET
      displayName = COALESCE(?, displayName),
      bio = COALESCE(?, bio),
      gender = COALESCE(?, gender),
      birthday = COALESCE(?, birthday),
      profileMusicTitle = COALESCE(?, profileMusicTitle),
      profileMusicUrl = COALESCE(?, profileMusicUrl)
    WHERE id = ?
  `).run(
    displayName ?? null,
    bio ?? null,
    gender ?? null,
    birthday ?? null,
    profileMusicTitle ?? null,
    profileMusicUrl ?? null,
    req.user.id
  );

  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  res.json({ user: formatUser(updated) });
});

app.post('/profile/avatar', authRequired, upload.any(), (req, res) => {
  const file = req.file || (req.files && req.files[0]);
  if (!file) return res.status(400).json({ error: 'File required' });
  const avatarUrl = `${getBaseUrl(req)}/uploads/${file.filename}`;
  db.prepare('UPDATE users SET avatarUrl = ? WHERE id = ?').run(avatarUrl, req.user.id);
  const avatarId = crypto.randomUUID();
  try {
    db.prepare('INSERT INTO user_avatars (id, userId, url, createdAt) VALUES (?, ?, ?, datetime(\'now\'))')
      .run(avatarId, req.user.id, avatarUrl);
  } catch (_) {}
  res.json({ avatarUrl, url: avatarUrl, status: 'ok' });
});

app.get('/profile/avatars', authRequired, (req, res) => {
  const rows = db.prepare('SELECT url FROM user_avatars WHERE userId = ? ORDER BY createdAt DESC').all(req.user.id);
  const urls = rows.map(r => r.url);
  if (req.user.avatarUrl && !urls.includes(req.user.avatarUrl)) {
    urls.unshift(req.user.avatarUrl);
  }
  res.json({ avatars: urls });
});

app.delete('/profile/avatars', authRequired, (req, res) => {
  db.prepare('UPDATE users SET avatarUrl = NULL WHERE id = ?').run(req.user.id);
  res.json({ status: 'ok' });
});

app.post('/profile/avatars/remove', authRequired, (req, res) => {
  const { url } = req.body;
  if (url) {
    db.prepare('DELETE FROM user_avatars WHERE userId = ? AND url = ?').run(req.user.id, url);
    if (req.user.avatarUrl === url) {
      const nextAvatar = db.prepare('SELECT url FROM user_avatars WHERE userId = ? ORDER BY createdAt DESC LIMIT 1').get(req.user.id);
      const newUrl = nextAvatar ? nextAvatar.url : null;
      db.prepare('UPDATE users SET avatarUrl = ? WHERE id = ?').run(newUrl, req.user.id);
    }
  } else {
    db.prepare('UPDATE users SET avatarUrl = NULL WHERE id = ?').run(req.user.id);
  }
  res.json({ status: 'ok' });
});

// ==================== USERS & CONTACTS ====================

app.get('/users/search', authRequired, (req, res) => {
  const query = req.query.q || '';
  const rows = db.prepare(`
    SELECT * FROM users
    WHERE id != ? AND (username LIKE ? OR displayName LIKE ?)
    LIMIT 20
  `).all(req.user.id, `%${query}%`, `%${query}%`);
  res.json({ users: rows.map(u => formatUser(u, req.user.id)) });
});

app.get('/users/:id', authRequired, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user: formatUser(user, req.user.id) });
});

app.post('/admin/verify', authRequired, (req, res) => {
  const { userId, username, chatId, verified = true } = req.body;
  const isV = verified ? 1 : 0;
  if (userId) {
    db.prepare('UPDATE users SET verified = ? WHERE id = ?').run(isV, userId);
    return res.json({ status: 'ok', userId, verified: Boolean(isV) });
  }
  if (username) {
    const cleanUsername = username.replace(/^@/, '').trim().toLowerCase();
    db.prepare('UPDATE users SET verified = ? WHERE LOWER(username) = ?').run(isV, cleanUsername);
    return res.json({ status: 'ok', username: cleanUsername, verified: Boolean(isV) });
  }
  if (chatId) {
    db.prepare('UPDATE chats SET verified = ? WHERE id = ?').run(isV, chatId);
    return res.json({ status: 'ok', chatId, verified: Boolean(isV) });
  }
  res.status(400).json({ error: 'userId, username or chatId required' });
});

app.post('/users/:id/verify', authRequired, (req, res) => {
  const isV = req.body.verified !== undefined ? (req.body.verified ? 1 : 0) : 1;
  db.prepare('UPDATE users SET verified = ? WHERE id = ?').run(isV, req.params.id);
  res.json({ status: 'ok', userId: req.params.id, verified: Boolean(isV) });
});

app.get('/users/:id/avatars', authRequired, (req, res) => {
  const targetUser = db.prepare('SELECT avatarUrl FROM users WHERE id = ?').get(req.params.id);
  const rows = db.prepare('SELECT url FROM user_avatars WHERE userId = ? ORDER BY createdAt DESC').all(req.params.id);
  const urls = rows.map(r => r.url);
  if (targetUser && targetUser.avatarUrl && !urls.includes(targetUser.avatarUrl)) {
    urls.unshift(targetUser.avatarUrl);
  }
  res.json({ avatars: urls });
});

app.get('/users/:id/common-groups', authRequired, (req, res) => {
  const targetId = req.params.id;
  const rows = db.prepare(`
    SELECT c.id, c.title, c.avatarUrl, c.type FROM chats c
    JOIN chat_members cm1 ON c.id = cm1.chatId
    JOIN chat_members cm2 ON c.id = cm2.chatId
    WHERE cm1.userId = ? AND cm2.userId = ? AND c.type != 'dm'
  `).all(req.user.id, targetId);
  const groups = rows.map(r => ({
    id: r.id,
    title: r.title || 'Группа',
    avatarUrl: r.avatarUrl || null,
    type: r.type || 'group',
  }));
  res.json({ groups, items: groups });
});

app.post('/contacts/match', authRequired, (req, res) => {
  const phones = req.body.phones || req.body.contacts || [];
  if (!Array.isArray(phones) || phones.length === 0) {
    return res.json({ users: [] });
  }
  const cleanPhones = phones.map(p => typeof p === 'string' ? p.replace(/[^\d+]/g, '') : '').filter(Boolean);
  if (cleanPhones.length === 0) {
    return res.json({ users: [] });
  }
  const placeholders = cleanPhones.map(() => '?').join(',');
  const matched = db.prepare(`SELECT * FROM users WHERE phone IN (${placeholders})`).all(...cleanPhones);
  res.json({
    users: matched.map(u => ({
      id: u.id,
      displayName: u.displayName || u.username || 'Без имени',
      username: u.username || '',
      avatarUrl: u.avatarUrl || null,
      phone: u.phone || '',
    })),
  });
});

app.put('/contacts', authRequired, (req, res) => {
  const ids = req.body && req.body.ids ? req.body.ids : [];
  res.json({ success: true, count: Array.isArray(ids) ? ids.length : 0 });
});

app.get('/contacts', authRequired, (req, res) => {
  res.json({ contacts: [], users: [] });
});

app.get('/privacy', authRequired, (req, res) => {
  let p = db.prepare('SELECT * FROM privacy_settings WHERE userId = ?').get(req.user.id);
  if (!p) {
    try {
      db.prepare(`
        INSERT OR IGNORE INTO privacy_settings (userId, lastSeen, phone, photo, messages, bio, groupInvites)
        VALUES (?, 'everybody', 'contacts', 'everybody', 'everybody', 'everybody', 'everybody')
      `).run(req.user.id);
    } catch (_) {}
    p = {
      lastSeen: 'everybody',
      phone: 'contacts',
      photo: 'everybody',
      messages: 'everybody',
      bio: 'everybody',
      groupInvites: 'everybody',
    };
  }
  res.json({
    privacy: {
      lastSeen: p.lastSeen || 'everybody',
      phone: p.phone || 'contacts',
      photo: p.photo || 'everybody',
      messages: p.messages || 'everybody',
      bio: p.bio || 'everybody',
      groupInvites: p.groupInvites || 'everybody',
    },
  });
});

app.patch('/privacy', authRequired, (req, res) => {
  const { lastSeen, phone, photo, messages, bio, groupInvites } = req.body;
  db.prepare(`
    INSERT INTO privacy_settings (userId, lastSeen, phone, photo, messages, bio, groupInvites)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(userId) DO UPDATE SET
      lastSeen = COALESCE(?, lastSeen),
      phone = COALESCE(?, phone),
      photo = COALESCE(?, photo),
      messages = COALESCE(?, messages),
      bio = COALESCE(?, bio),
      groupInvites = COALESCE(?, groupInvites)
  `).run(
    req.user.id,
    lastSeen || 'everybody',
    phone || 'contacts',
    photo || 'everybody',
    messages || 'everybody',
    bio || 'everybody',
    groupInvites || 'everybody',
    lastSeen ?? null,
    phone ?? null,
    photo ?? null,
    messages ?? null,
    bio ?? null,
    groupInvites ?? null
  );
  const p = db.prepare('SELECT * FROM privacy_settings WHERE userId = ?').get(req.user.id);
  res.json({
    status: 'ok',
    privacy: {
      lastSeen: p.lastSeen || 'everybody',
      phone: p.phone || 'contacts',
      photo: p.photo || 'everybody',
      messages: p.messages || 'everybody',
      bio: p.bio || 'everybody',
      groupInvites: p.groupInvites || 'everybody',
    },
  });
});

app.get('/blocked', authRequired, (req, res) => {
  const rows = db.prepare(`
    SELECT u.* FROM blocked_users b
    JOIN users u ON b.blockedId = u.id
    WHERE b.userId = ?
  `).all(req.user.id);
  res.json({ users: rows.map(formatUser) });
});

app.post('/blocked/:id', authRequired, (req, res) => {
  db.prepare('INSERT OR IGNORE INTO blocked_users (userId, blockedId) VALUES (?, ?)').run(req.user.id, req.params.id);
  res.json({ status: 'ok' });
});

app.delete('/blocked/:id', authRequired, (req, res) => {
  db.prepare('DELETE FROM blocked_users WHERE userId = ? AND blockedId = ?').run(req.user.id, req.params.id);
  res.json({ status: 'ok' });
});

// ==================== STORIES ====================

// GET /stories
app.get('/stories', authRequired, (req, res) => {
  const currentUserId = req.user.id;

  // Fetch active stories (within last 24h, or non-expired, or fallback to recent)
  let storiesRows = [];
  try {
    storiesRows = db.prepare(`
      SELECT * FROM stories
      WHERE createdAt >= datetime('now', '-24 hours') OR (expiresAt IS NOT NULL AND expiresAt >= datetime('now'))
      ORDER BY createdAt ASC
    `).all();
  } catch (_) {}

  if (!storiesRows || storiesRows.length === 0) {
    try {
      storiesRows = db.prepare('SELECT * FROM stories ORDER BY createdAt DESC LIMIT 50').all();
    } catch (_) {}
  }

  // Group stories by author (userId)
  const storiesByUser = new Map();
  for (const s of storiesRows) {
    if (!storiesByUser.has(s.userId)) {
      storiesByUser.set(s.userId, []);
    }
    storiesByUser.get(s.userId).push(s);
  }

  // Ensure current user is in authors map
  if (!storiesByUser.has(currentUserId)) {
    storiesByUser.set(currentUserId, []);
  }

  const authors = [];
  const allStories = [];

  for (const [userId, userStories] of storiesByUser.entries()) {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) continue;

    const isMine = userId === currentUserId;
    let hasNew = false;

    const formattedStories = userStories.map(s => {
      let isViewed = isMine;
      if (!isMine) {
        const viewRow = db.prepare('SELECT 1 FROM story_views WHERE storyId = ? AND userId = ?').get(s.id, currentUserId);
        isViewed = Boolean(viewRow);
      }
      if (!isViewed) hasNew = true;

      let viewsCount = 0;
      try {
        const vr = db.prepare('SELECT COUNT(*) AS c FROM story_views WHERE storyId = ?').get(s.id);
        viewsCount = vr ? vr.c : 0;
      } catch (_) {}

      const mediaUrl = s.mediaUrl
        ? (s.mediaUrl.startsWith('http') ? s.mediaUrl : `${getBaseUrl(req)}${s.mediaUrl}`)
        : '';

      const formatted = {
        id: s.id,
        mediaUrl: mediaUrl || '',
        caption: s.caption || '',
        text: s.text || '',
        background: s.background || 0,
        font: s.font || 0,
        createdAt: s.createdAt,
        viewed: isViewed,
        views: viewsCount,
      };

      allStories.push({
        ...formatted,
        userId: s.userId,
        user: formatUser(user),
      });

      return formatted;
    });

    if (formattedStories.length > 0) {
      authors.push({
        user: formatUser(user),
        mine: isMine,
        hasNew: isMine ? false : hasNew,
        stories: formattedStories,
      });
    }
  }

  // Stable sorting: current user first, then deterministically by userId so index never shifts
  authors.sort((a, b) => {
    if (a.mine) return -1;
    if (b.mine) return 1;
    return String(a.user?.id || '').localeCompare(String(b.user?.id || ''));
  });

  res.json({
    authors,
    stories: allStories,
  });
});

// POST /stories (multipart/form-data or application/json)
app.post('/stories', authRequired, upload.single('file'), (req, res) => {
  const storyId = crypto.randomUUID();
  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  let mediaUrl = null;
  if (req.file) {
    mediaUrl = '/uploads/' + req.file.filename;
  } else if (req.body && req.body.mediaUrl) {
    mediaUrl = normalizeStorageKey(req.body.mediaUrl);
  }

  const caption = (req.body && req.body.caption) || null;
  const text = (req.body && req.body.text) || null;
  const background = parseInt((req.body && req.body.background), 10) || 0;
  const font = parseInt((req.body && req.body.font), 10) || 0;

  db.prepare(`
    INSERT INTO stories (id, userId, mediaUrl, caption, text, background, font, createdAt, expiresAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(storyId, req.user.id, mediaUrl, caption, text, background, font, now, expiresAt);

  const fullMediaUrl = mediaUrl ? `${getBaseUrl(req)}${mediaUrl}` : '';

  const createdStory = {
    id: storyId,
    mediaUrl: fullMediaUrl,
    caption: caption || '',
    text: text || '',
    background,
    font,
    createdAt: now,
    viewed: true,
    views: 0,
  };

  res.json({
    status: 'ok',
    story: createdStory,
    id: storyId,
    mediaUrl: fullMediaUrl,
  });
});

// DELETE /stories/:id
app.delete('/stories/:id', authRequired, (req, res) => {
  const story = db.prepare('SELECT userId FROM stories WHERE id = ?').get(req.params.id);
  if (!story) return res.status(404).json({ error: 'Story not found' });
  if (story.userId !== req.user.id) {
    return res.status(403).json({ error: 'Вы можете удалять только свои истории' });
  }
  db.prepare('DELETE FROM stories WHERE id = ? AND userId = ?').run(req.params.id, req.user.id);
  db.prepare('DELETE FROM story_views WHERE storyId = ?').run(req.params.id);
  res.json({ status: 'ok' });
});

// POST /stories/:id/view
app.post('/stories/:id/view', authRequired, (req, res) => {
  db.prepare(`
    INSERT INTO story_views (storyId, userId, viewedAt)
    VALUES (?, ?, datetime('now'))
    ON CONFLICT(storyId, userId) DO UPDATE SET viewedAt = datetime('now')
  `).run(req.params.id, req.user.id);
  res.json({ status: 'ok' });
});

// GET /stories/:id/viewers
app.get('/stories/:id/viewers', authRequired, (req, res) => {
  const rows = db.prepare(`
    SELECT u.*, v.viewedAt FROM story_views v
    JOIN users u ON v.userId = u.id
    WHERE v.storyId = ?
    ORDER BY v.viewedAt DESC
  `).all(req.params.id);

  res.json({
    viewers: rows.map(formatUser),
  });
});

// ==================== CHAT ROUTES ====================

function ensureSavedChat(userId) {
  if (!userId) return null;
  const existing = db.prepare(`
    SELECT c.id FROM chats c
    JOIN chat_members cm ON c.id = cm.chatId
    WHERE cm.userId = ? AND c.type = 'dm' AND c.title = 'saved'
  `).get(userId);

  if (existing) return existing.id;

  const chatId = 'saved_' + userId;
  const now = new Date().toISOString();
  db.prepare(`
    INSERT OR IGNORE INTO chats (id, type, title, isPublic, createdAt)
    VALUES (?, 'dm', 'saved', 0, ?)
  `).run(chatId, now);

  db.prepare(`
    INSERT OR IGNORE INTO chat_members (chatId, userId, role, canWrite, pinned)
    VALUES (?, ?, 'owner', 1, 0)
  `).run(chatId, userId);

  return chatId;
}

// Get user's chat list
app.get('/chats', authRequired, (req, res) => {
  ensureSavedChat(req.user.id);

  const myChats = db.prepare(`
    SELECT c.*, cm.role AS myRole, cm.canWrite, cm.lastReadSeq, cm.notifMuted, cm.pinned, cm.archived,
           COALESCE((SELECT MAX(createdAt) FROM messages WHERE chatId = c.id), c.createdAt) AS lastMsgTime
    FROM chats c
    JOIN chat_members cm ON c.id = cm.chatId
    WHERE cm.userId = ?
    ORDER BY cm.pinned DESC, lastMsgTime DESC
  `).all(req.user.id);

  const result = [];
  for (const c of myChats) {
    const isSaved = c.type === 'dm' && c.title === 'saved';

    // Determine peer for DM (only if not saved chat)
    let peer = null;
    if (c.type === 'dm' && !isSaved) {
      const peerMember = db.prepare('SELECT userId FROM chat_members WHERE chatId = ? AND userId != ?').get(c.id, req.user.id);
      if (peerMember) {
        const peerUser = db.prepare('SELECT * FROM users WHERE id = ?').get(peerMember.userId);
        peer = formatUser(peerUser);
      }
    }

    // Last message
    const lastMsg = db.prepare('SELECT * FROM messages WHERE chatId = ? ORDER BY seq DESC LIMIT 1').get(c.id);

    // Count unread
    const lastRead = c.lastReadSeq || 0;
    const unreadCount = db.prepare('SELECT COUNT(*) AS count FROM messages WHERE chatId = ? AND seq > ?').get(c.id, lastRead);

    // Member count
    const memberCountRow = db.prepare('SELECT COUNT(*) AS count FROM chat_members WHERE chatId = ?').get(c.id);

    let displayTitle = c.title;
    if (isSaved) {
      displayTitle = 'saved';
    } else if (c.type === 'dm' && peer) {
      displayTitle = peer.displayName || peer.username;
    }

    result.push({
      id: c.id,
      type: c.type,
      title: displayTitle,
      avatarUrl: isSaved ? null : (c.type === 'dm' && peer ? peer.avatarUrl : c.avatarUrl),
      peer,
      lastMessage: lastMsg ? formatMessage(lastMsg, req.user.id) : null,
      unread: unreadCount ? unreadCount.count : 0,
      isChannel: c.type === 'channel',
      notifMuted: Boolean(c.notifMuted),
      lastReadSeq: c.lastReadSeq || 0,
      myRole: isSaved ? 'owner' : (c.myRole || 'member'),
      canWrite: true,
      pinned: Boolean(c.pinned),
      archived: Boolean(c.archived),
      memberCount: isSaved ? 1 : (memberCountRow ? memberCountRow.count : 1),
      verified: Boolean(c.verified || (peer && peer.verified)),
      isVerified: Boolean(c.verified || (peer && peer.verified)),
    });
  }

  res.json({ chats: result });
});

// Create Chat (generic)
app.post('/chats', authRequired, (req, res) => {
  const { type, title, memberIds, userId, description, isPublic, pinChannelPosts } = req.body;
  if (type === 'saved' || userId === req.user.id) {
    const savedChatId = ensureSavedChat(req.user.id);
    const chatRow = db.prepare('SELECT * FROM chats WHERE id = ?').get(savedChatId);
    return res.json({ id: savedChatId, chatId: savedChatId, chat: chatRow });
  }

  if (type === 'dm' || userId) {
    const targetId = userId || (Array.isArray(memberIds) ? memberIds[0] : null);
    if (!targetId) return res.status(400).json({ error: 'Target userId required' });
    if (targetId === req.user.id) {
      const savedChatId = ensureSavedChat(req.user.id);
      const chatRow = db.prepare('SELECT * FROM chats WHERE id = ?').get(savedChatId);
      return res.json({ id: savedChatId, chatId: savedChatId, chat: chatRow });
    }
    const existing = db.prepare(`
      SELECT c.id FROM chats c
      JOIN chat_members cm1 ON c.id = cm1.chatId AND cm1.userId = ?
      JOIN chat_members cm2 ON c.id = cm2.chatId AND cm2.userId = ?
      WHERE c.type = 'dm'
    `).get(req.user.id, targetId);
    if (existing) {
      const chatRow = db.prepare('SELECT * FROM chats WHERE id = ?').get(existing.id);
      return res.json({ id: existing.id, chatId: existing.id, chat: chatRow });
    }
    const chatId = crypto.randomUUID();
    const now = new Date().toISOString();
    db.prepare(`INSERT INTO chats (id, type, createdAt) VALUES (?, 'dm', ?)`).run(chatId, now);
    db.prepare(`INSERT INTO chat_members (chatId, userId, role) VALUES (?, ?, 'member')`).run(chatId, req.user.id);
    db.prepare(`INSERT INTO chat_members (chatId, userId, role) VALUES (?, ?, 'member')`).run(chatId, targetId);
    const chatRow = db.prepare('SELECT * FROM chats WHERE id = ?').get(chatId);
    return res.json({ id: chatId, chatId, chat: chatRow });
  }

  if (type === 'channel') {
    const chatId = crypto.randomUUID();
    const inviteCode = crypto.randomBytes(6).toString('hex');
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO chats (id, type, title, description, isPublic, pinChannelPosts, inviteCode, createdAt)
      VALUES (?, 'channel', ?, ?, ?, ?, ?, ?)
    `).run(chatId, title || 'Новый канал', description || '', isPublic ? 1 : 0, pinChannelPosts !== undefined ? (pinChannelPosts ? 1 : 0) : 1, inviteCode, now);
    db.prepare(`INSERT INTO chat_members (chatId, userId, role) VALUES (?, ?, 'owner')`).run(chatId, req.user.id);
    const chatRow = db.prepare('SELECT * FROM chats WHERE id = ?').get(chatId);
    return res.json({ id: chatId, chatId, chat: chatRow });
  }

  // Group by default
  const chatId = crypto.randomUUID();
  const inviteCode = crypto.randomBytes(6).toString('hex');
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO chats (id, type, title, inviteCode, createdAt)
    VALUES (?, 'group', ?, ?, ?)
  `).run(chatId, title || 'Новая группа', inviteCode, now);
  db.prepare(`INSERT INTO chat_members (chatId, userId, role) VALUES (?, ?, 'owner')`).run(chatId, req.user.id);
  if (Array.isArray(memberIds)) {
    for (const uid of memberIds) {
      if (uid && uid !== req.user.id) {
        db.prepare(`INSERT OR IGNORE INTO chat_members (chatId, userId, role) VALUES (?, ?, 'member')`).run(chatId, uid);
      }
    }
  }
  const chatRow = db.prepare('SELECT * FROM chats WHERE id = ?').get(chatId);
  return res.json({ id: chatId, chatId, chat: chatRow });
});

// Create DM chat
app.post('/chats/dm', authRequired, (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'Target userId required' });
  if (userId === req.user.id) {
    const savedChatId = ensureSavedChat(req.user.id);
    const chatRow = db.prepare('SELECT * FROM chats WHERE id = ?').get(savedChatId);
    return res.json({ id: savedChatId, chatId: savedChatId, chat: chatRow });
  }

  // Check if DM already exists
  const existing = db.prepare(`
    SELECT c.id FROM chats c
    JOIN chat_members cm1 ON c.id = cm1.chatId AND cm1.userId = ?
    JOIN chat_members cm2 ON c.id = cm2.chatId AND cm2.userId = ?
    WHERE c.type = 'dm'
  `).get(req.user.id, userId);

  if (existing) {
    const chatRow = db.prepare('SELECT * FROM chats WHERE id = ?').get(existing.id);
    return res.json({ id: existing.id, chatId: existing.id, chat: chatRow });
  }

  const chatId = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare(`INSERT INTO chats (id, type, createdAt) VALUES (?, 'dm', ?)`).run(chatId, now);
  db.prepare(`INSERT INTO chat_members (chatId, userId, role) VALUES (?, ?, 'member')`).run(chatId, req.user.id);
  db.prepare(`INSERT INTO chat_members (chatId, userId, role) VALUES (?, ?, 'member')`).run(chatId, userId);

  const chatRow = db.prepare('SELECT * FROM chats WHERE id = ?').get(chatId);
  res.json({ id: chatId, chatId, chat: chatRow });
});

// Create Group chat
app.post('/chats/group', authRequired, (req, res) => {
  const { title, memberIds } = req.body;
  const chatId = crypto.randomUUID();
  const inviteCode = crypto.randomBytes(6).toString('hex');
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO chats (id, type, title, inviteCode, createdAt)
    VALUES (?, 'group', ?, ?, ?)
  `).run(chatId, title || 'Новая группа', inviteCode, now);

  db.prepare(`INSERT INTO chat_members (chatId, userId, role) VALUES (?, ?, 'owner')`).run(chatId, req.user.id);

  if (Array.isArray(memberIds)) {
    for (const uid of memberIds) {
      if (uid && uid !== req.user.id) {
        db.prepare(`INSERT OR IGNORE INTO chat_members (chatId, userId, role) VALUES (?, ?, 'member')`).run(chatId, uid);
      }
    }
  }

  const chatRow = db.prepare('SELECT * FROM chats WHERE id = ?').get(chatId);
  res.json({ id: chatId, chatId, chat: chatRow });
});

// Create Channel
app.post('/chats/channel', authRequired, (req, res) => {
  const { title, description, isPublic, pinChannelPosts } = req.body;
  const chatId = crypto.randomUUID();
  const inviteCode = crypto.randomBytes(6).toString('hex');
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO chats (id, type, title, description, isPublic, pinChannelPosts, inviteCode, createdAt)
    VALUES (?, 'channel', ?, ?, ?, ?, ?, ?)
  `).run(
    chatId,
    title || 'Новый канал',
    description || '',
    isPublic ? 1 : 0,
    pinChannelPosts !== undefined ? (pinChannelPosts ? 1 : 0) : 1,
    inviteCode,
    now
  );

  db.prepare(`INSERT INTO chat_members (chatId, userId, role) VALUES (?, ?, 'owner')`).run(chatId, req.user.id);

  const chatRow = db.prepare('SELECT * FROM chats WHERE id = ?').get(chatId);
  res.json({ id: chatId, chatId, chat: chatRow });
});

// Get Messages
app.get('/chats/:id/messages', authRequired, (req, res) => {
  const chatId = req.params.id;
  const chat = db.prepare('SELECT * FROM chats WHERE id = ?').get(chatId);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });

  const cm = getChatMember(chatId, req.user.id);
  if (!cm && !chat.isPublic) {
    return res.status(403).json({ error: 'Вы не являетесь участником этого чата' });
  }

  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 100);

  const rows = db.prepare(`
    SELECT * FROM messages
    WHERE chatId = ?
    ORDER BY seq DESC
    LIMIT ?
  `).all(chatId, limit);

  // Return chronologically
  rows.reverse();
  res.json({ messages: rows.map(m => formatMessage(m, req.user.id)) });
});

// Search messages in a chat
app.get('/chats/:id/messages/search', authRequired, (req, res) => {
  const chatId = req.params.id;
  const chat = db.prepare('SELECT * FROM chats WHERE id = ?').get(chatId);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });

  const cm = getChatMember(chatId, req.user.id);
  if (!cm && !chat.isPublic) {
    return res.status(403).json({ error: 'Вы не являетесь участником этого чата' });
  }

  const query = (req.query.q || '').trim();
  if (!query) {
    return res.json({ messages: [], items: [] });
  }

  const limit = Math.min(parseInt(req.query.limit, 10) || 60, 100);
  const rows = db.prepare(`
    SELECT * FROM messages
    WHERE chatId = ? AND (body LIKE ? OR mediaCaption LIKE ?)
    ORDER BY seq DESC
    LIMIT ?
  `).all(chatId, `%${query}%`, `%${query}%`, limit);

  const formatted = rows.map(m => formatMessage(m, req.user.id));
  res.json({ messages: formatted, items: formatted });
});

// Get messages around a specific message (for search results and jump-to-reply)
app.get('/chats/:id/messages/around/:msgId', authRequired, (req, res) => {
  const chatId = req.params.id;
  const chat = db.prepare('SELECT * FROM chats WHERE id = ?').get(chatId);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });

  const cm = getChatMember(chatId, req.user.id);
  if (!cm && !chat.isPublic) {
    return res.status(403).json({ error: 'Вы не являетесь участником этого чата' });
  }

  const targetMsg = db.prepare('SELECT * FROM messages WHERE id = ? AND chatId = ?').get(req.params.msgId, chatId);
  if (!targetMsg) {
    return res.json({ messages: [] });
  }

  const before = Math.min(parseInt(req.query.before, 10) || 40, 100);
  const after = Math.min(parseInt(req.query.after, 10) || 20, 100);

  const beforeRows = db.prepare(`
    SELECT * FROM messages
    WHERE chatId = ? AND seq <= ?
    ORDER BY seq DESC
    LIMIT ?
  `).all(chatId, targetMsg.seq, before + 1);

  const afterRows = db.prepare(`
    SELECT * FROM messages
    WHERE chatId = ? AND seq > ?
    ORDER BY seq ASC
    LIMIT ?
  `).all(chatId, targetMsg.seq, after);

  beforeRows.reverse();
  const allRows = [...beforeRows, ...afterRows];
  res.json({ messages: allRows.map(m => formatMessage(m, req.user.id)) });
});

app.get('/messages/around/:msgId', authRequired, (req, res) => {
  const targetMsg = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.msgId);
  if (!targetMsg) return res.json({ messages: [] });

  const chatId = targetMsg.chatId;
  const chat = db.prepare('SELECT * FROM chats WHERE id = ?').get(chatId);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });

  const cm = getChatMember(chatId, req.user.id);
  if (!cm && !chat.isPublic) {
    return res.status(403).json({ error: 'Вы не являетесь участником этого чата' });
  }

  const before = Math.min(parseInt(req.query.before, 10) || 40, 100);
  const after = Math.min(parseInt(req.query.after, 10) || 20, 100);

  const beforeRows = db.prepare(`
    SELECT * FROM messages
    WHERE chatId = ? AND seq <= ?
    ORDER BY seq DESC
    LIMIT ?
  `).all(chatId, targetMsg.seq, before + 1);

  const afterRows = db.prepare(`
    SELECT * FROM messages
    WHERE chatId = ? AND seq > ?
    ORDER BY seq ASC
    LIMIT ?
  `).all(chatId, targetMsg.seq, after);

  beforeRows.reverse();
  const allRows = [...beforeRows, ...afterRows];
  res.json({ messages: allRows.map(m => formatMessage(m, req.user.id)) });
});

// Send Message
app.post('/chats/:id/messages', authRequired, (req, res) => {
  const chatId = req.params.id;
  const chat = db.prepare('SELECT * FROM chats WHERE id = ?').get(chatId);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });

  let cm = getChatMember(chatId, req.user.id);
  if (!cm) {
    return res.status(403).json({ error: 'Вы не состоите в этом чате' });
  }

  // Check mute
  if (cm.mutedUntil && new Date(cm.mutedUntil) > new Date()) {
    return res.status(403).json({ error: 'Вы замьючены в этом чате' });
  }

  // Check channel write permission
  if (chat.type === 'channel' && cm.role !== 'owner' && cm.role !== 'admin') {
    return res.status(403).json({ error: 'В канале могут писать только администраторы' });
  }

  // Check group write permission
  if (chat.type === 'group' && chat.memberCanSendMessages === 0 && cm.role !== 'owner' && cm.role !== 'admin') {
    return res.status(403).json({ error: 'Отправка сообщений ограничена администратором' });
  }

  // Check blocked in DM
  if (chat.type === 'dm') {
    const peer = db.prepare('SELECT userId FROM chat_members WHERE chatId = ? AND userId != ?').get(chatId, req.user.id);
    if (peer && isUserBlockedBy(req.user.id, peer.userId)) {
      return res.status(403).json({ error: 'Вы заблокированы этим пользователем' });
    }
  }

  const { body, silent, replyToId, attachments, images, files, videos, voice } = req.body;

  // Compute next sequence number
  const maxSeqRow = db.prepare('SELECT MAX(seq) AS maxSeq FROM messages WHERE chatId = ?').get(chatId);
  const nextSeq = (maxSeqRow && maxSeqRow.maxSeq ? maxSeqRow.maxSeq : 0) + 1;

  const msgId = crypto.randomUUID();
  const now = new Date().toISOString();

  let cleanBody = body || '';
  const trimmedLower = cleanBody.trim().toLowerCase();
  let isCallCommand = false;
  if (trimmedLower === '/call' || trimmedLower === '/звонок' || trimmedLower === '!call' || trimmedLower === 'call' || trimmedLower === 'звонок') {
    cleanBody = `📞 Аудиозвонок 1-на-1\nНажмите для звонка:\nhttps://jxiwm.btxc.indevs.in/call/chat/${chatId}`;
    isCallCommand = true;
  } else if (cleanBody.includes('/join/') && !cleanBody.includes('Перейти')) {
    cleanBody = cleanBody.trim() + '\n\nПерейти';
  }

  db.prepare(`
    INSERT INTO messages (id, chatId, senderId, body, seq, silent, replyToId, attachments, images, files, videos, voice, createdAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    msgId,
    chatId,
    req.user.id,
    cleanBody,
    nextSeq,
    silent ? 1 : 0,
    replyToId || null,
    attachments ? JSON.stringify(attachments) : '[]',
    images ? JSON.stringify(images) : '[]',
    files ? JSON.stringify(files) : '[]',
    videos ? JSON.stringify(videos) : '[]',
    voice || null,
    now
  );

  // Update sender lastReadSeq
  db.prepare('UPDATE chat_members SET lastReadSeq = ? WHERE chatId = ? AND userId = ?').run(nextSeq, chatId, req.user.id);

  const saved = db.prepare('SELECT * FROM messages WHERE id = ?').get(msgId);
  const formatted = formatMessage(saved, req.user.id);

  // Broadcast to all chat members via WebSocket!
  broadcastMessageUpdate(chatId, saved);

  if (isCallCommand) {
    const chat = db.prepare('SELECT type FROM chats WHERE id = ?').get(chatId);
    if (chat && (chat.type === 'dm' || chat.type === 'direct')) {
      const partner = db.prepare('SELECT userId FROM chat_members WHERE chatId = ? AND userId != ?').get(chatId, req.user.id);
      if (partner) {
        sendToUser(partner.userId, {
          type: 'call:incoming',
          callId: 'call_' + Date.now(),
          fromUserId: req.user.id,
          callerName: req.user.displayName || req.user.username,
          callerAvatar: req.user.avatar || '',
          sdp: null
        });
      }
    }
  }

  res.json({ ...formatted, message: formatted });
});

// Upload attachments (images, video, voice, files, music)
app.post('/chats/:id/attachments', authRequired, upload.any(), (req, res) => {
  const chatId = req.params.id;
  const chat = db.prepare('SELECT * FROM chats WHERE id = ?').get(chatId);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });

  const cm = getChatMember(chatId, req.user.id);
  if (!cm) {
    return res.status(403).json({ error: 'Вы не состоите в этом чате' });
  }

  if (cm.mutedUntil && new Date(cm.mutedUntil) > new Date()) {
    return res.status(403).json({ error: 'Вы замьючены в этом чате' });
  }

  if (chat.type === 'channel' && cm.role !== 'owner' && cm.role !== 'admin') {
    return res.status(403).json({ error: 'В канале могут публиковать только администраторы' });
  }

  if (chat.type === 'group' && chat.memberCanSendMedia === 0 && cm.role !== 'owner' && cm.role !== 'admin') {
    return res.status(403).json({ error: 'Отправка медиафайлов ограничена администратором' });
  }

  if (chat.type === 'dm') {
    const peer = db.prepare('SELECT userId FROM chat_members WHERE chatId = ? AND userId != ?').get(chatId, req.user.id);
    if (peer && isUserBlockedBy(req.user.id, peer.userId)) {
      return res.status(403).json({ error: 'Вы заблокированы этим пользователем' });
    }
  }

  const files = req.files || [];

  const maxSeqRow = db.prepare('SELECT MAX(seq) AS maxSeq FROM messages WHERE chatId = ?').get(chatId);
  const nextSeq = (maxSeqRow && maxSeqRow.maxSeq ? maxSeqRow.maxSeq : 0) + 1;

  const msgId = req.body.clientMessageId || crypto.randomUUID();
  const now = new Date().toISOString();

  const attachments = [];
  const imageKeys = [];
  const videoKeys = [];
  const fileList = [];
  let voiceKey = null;

  for (let idx = 0; idx < files.length; idx++) {
    const f = files[idx];
    const storageKey = `/uploads/${f.filename}`;
    let kind = 'file';
    let mime = f.mimetype || 'application/octet-stream';
    let originalName = f.originalname || `file_${idx}`;

    if (f.mimetype && f.mimetype.startsWith('image/')) {
      kind = 'image';
      imageKeys.push(storageKey);
    } else if (f.mimetype && f.mimetype.startsWith('video/')) {
      kind = 'video';
      videoKeys.push(storageKey);
    } else if (f.mimetype && f.mimetype.startsWith('audio/')) {
      kind = 'audio';
      // If voice message recorded from app, filename is part0.m4a or null or voice*
      const isVoice = !f.originalname || /^(part\d*|voice.*|blob.*|recording.*|audio\d*)\.\w+$/i.test(f.originalname);
      if (isVoice) {
        mime = 'audio/mp4';
        originalName = `part${idx}.m4a`;
        voiceKey = storageKey;
      } else {
        // Music track
        fileList.push({ url: storageKey, filename: originalName, size: f.size, isMusic: true, mime });
      }
    } else {
      kind = 'file';
      fileList.push({ url: storageKey, filename: originalName, size: f.size, isMusic: false, mime });
    }

    attachments.push({
      kind,
      storageKey,
      mime,
      meta: {
        filename: originalName,
        size: f.size,
      },
      size: f.size,
    });
  }

  const bodyText = req.body.body || '';

  db.prepare(`
    INSERT INTO messages (id, chatId, senderId, body, seq, images, videos, files, voice, attachments, replyToId, spoiler, isSticker, createdAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    msgId,
    chatId,
    req.user.id,
    bodyText,
    nextSeq,
    JSON.stringify(imageKeys),
    JSON.stringify(videoKeys),
    JSON.stringify(fileList),
    voiceKey,
    JSON.stringify(attachments),
    req.body.replyToId || null,
    req.body.spoiler === 'true' || req.body.spoiler === true ? 1 : 0,
    req.body.isSticker === 'true' || req.body.isSticker === true ? 1 : 0,
    now
  );

  // Update sender lastReadSeq
  db.prepare('UPDATE chat_members SET lastReadSeq = ? WHERE chatId = ? AND userId = ?').run(nextSeq, chatId, req.user.id);

  const saved = db.prepare('SELECT * FROM messages WHERE id = ?').get(msgId);
  const formatted = formatMessage(saved, req.user.id);

  broadcastMessageUpdate(chatId, saved);

  res.json({ ...formatted, message: formatted });
});

// Create Poll
app.post('/chats/:id/polls', authRequired, (req, res) => {
  const chatId = req.params.id;
  const { question, options, anonymous, multiple, quiz, correctOption, replyToId, clientMessageId } = req.body;

  const maxSeqRow = db.prepare('SELECT MAX(seq) AS maxSeq FROM messages WHERE chatId = ?').get(chatId);
  const nextSeq = (maxSeqRow && maxSeqRow.maxSeq ? maxSeqRow.maxSeq : 0) + 1;

  const msgId = clientMessageId || crypto.randomUUID();
  const now = new Date().toISOString();

  const optionsList = (Array.isArray(options) ? options : []).map((optText, idx) => ({
    id: `opt_${idx}`,
    text: String(optText),
    votes: 0,
    voterIds: [],
  }));

  const poll = {
    question: question || 'Опрос',
    options: optionsList,
    myVotes: [],
    anonymous: anonymous !== undefined ? Boolean(anonymous) : true,
    multiple: Boolean(multiple),
    quiz: Boolean(quiz),
    correctOptionId: quiz && typeof correctOption === 'number' ? `opt_${correctOption}` : null,
    closed: false,
    totalVoters: 0,
  };

  db.prepare(`
    INSERT INTO messages (id, chatId, senderId, body, seq, replyToId, poll, createdAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(msgId, chatId, req.user.id, '', nextSeq, replyToId || null, JSON.stringify(poll), now);

  // Update sender lastReadSeq
  db.prepare('UPDATE chat_members SET lastReadSeq = ? WHERE chatId = ? AND userId = ?').run(nextSeq, chatId, req.user.id);

  const saved = db.prepare('SELECT * FROM messages WHERE id = ?').get(msgId);
  const formatted = formatMessage(saved, req.user.id);

  broadcastToChat(chatId, {
    type: 'message',
    payload: {
      chatId,
      ...formatted,
    },
  });

  res.json(formatted);
});

// Vote on Poll
app.post('/chats/:id/messages/:msgId/poll/votes', authRequired, (req, res) => {
  const { id: chatId, msgId } = req.params;
  const { optionIds } = req.body;

  const msg = db.prepare('SELECT * FROM messages WHERE id = ? AND chatId = ?').get(msgId, chatId);
  if (!msg || !msg.poll) return res.status(404).json({ error: 'Опрос не найден' });

  let poll;
  try { poll = JSON.parse(msg.poll); } catch (_) { return res.status(400).json({ error: 'Неверный опрос' }); }
  if (poll.closed) return res.status(400).json({ error: 'Опрос завершен' });

  const chosen = Array.isArray(optionIds) ? optionIds : [];

  for (const opt of poll.options) {
    opt.voterIds = (opt.voterIds || []).filter(uid => uid !== req.user.id);
    if (chosen.includes(opt.id)) {
      opt.voterIds.push(req.user.id);
    }
    opt.votes = opt.voterIds.length;
  }

  const allVoterIds = new Set(poll.options.flatMap(o => o.voterIds || []));
  poll.totalVoters = allVoterIds.size;

  db.prepare('UPDATE messages SET poll = ? WHERE id = ?').run(JSON.stringify(poll), msgId);

  // Broadcast poll-changed event to chat
  broadcastToChat(chatId, {
    type: 'poll-changed',
    payload: {
      chatId,
      messageId: msgId,
      poll: formatPoll(poll, null),
    },
  });

  res.json(formatPoll(poll, req.user.id));
});

// Close Poll
app.post('/chats/:id/messages/:msgId/poll/close', authRequired, (req, res) => {
  const { id: chatId, msgId } = req.params;

  const msg = db.prepare('SELECT * FROM messages WHERE id = ? AND chatId = ?').get(msgId, chatId);
  if (!msg || !msg.poll) return res.status(404).json({ error: 'Опрос не найден' });

  const cm = getChatMember(chatId, req.user.id);
  const isAuthor = msg.senderId === req.user.id;
  const isAdmin = cm && (cm.role === 'owner' || cm.role === 'admin');
  if (!isAuthor && !isAdmin) {
    return res.status(403).json({ error: 'Нет прав на закрытие этого опроса' });
  }

  let poll;
  try { poll = JSON.parse(msg.poll); } catch (_) { return res.status(400).json({ error: 'Неверный опрос' }); }
  poll.closed = true;

  db.prepare('UPDATE messages SET poll = ? WHERE id = ?').run(JSON.stringify(poll), msgId);

  broadcastToChat(chatId, {
    type: 'poll-changed',
    payload: {
      chatId,
      messageId: msgId,
      poll: formatPoll(poll, null),
    },
  });

  res.json(formatPoll(poll, req.user.id));
});

// Media tab: photos, videos, files, music, links
app.get('/chats/:id/media', authRequired, (req, res) => {
  const chatId = req.params.id;
  const tab = (req.query.tab || 'media').toLowerCase();
  const limit = Math.min(parseInt(req.query.limit, 10) || 100, 200);

  const rows = db.prepare(`
    SELECT * FROM messages
    WHERE chatId = ?
    ORDER BY seq DESC
    LIMIT ?
  `).all(chatId, limit);

  const items = [];

  for (const m of rows) {
    const formatted = formatMessage(m, req.user.id);
    const atts = formatted.attachments || [];

    if (tab === 'media' || tab === 'медиа') {
      for (const att of atts) {
        if (att.kind === 'image' || att.kind === 'video') {
          items.push({
            messageId: m.id,
            kind: att.kind,
            storageKey: att.storageKey,
            meta: att.meta || {},
            size: att.size || 0,
            body: m.body || '',
          });
        }
      }
    } else if (tab === 'files' || tab === 'файлы') {
      for (const att of atts) {
        if (att.kind === 'file') {
          items.push({
            messageId: m.id,
            kind: 'file',
            storageKey: att.storageKey,
            meta: att.meta || {},
            size: att.size || 0,
            body: m.body || '',
          });
        }
      }
    } else if (tab === 'music' || tab === 'музыка' || tab === 'audio') {
      for (const att of atts) {
        if (att.kind === 'audio') {
          items.push({
            messageId: m.id,
            kind: 'audio',
            storageKey: att.storageKey,
            meta: att.meta || {},
            size: att.size || 0,
            body: m.body || '',
          });
        }
      }
    } else if (tab === 'links' || tab === 'ссылки') {
      if (m.body) {
        const matches = m.body.match(/https?:\/\/[^\s]+/g);
        if (matches) {
          for (const url of matches) {
            items.push({
              messageId: m.id,
              kind: 'link',
              storageKey: '',
              meta: {},
              size: 0,
              body: url,
            });
          }
        }
      }
    } else {
      for (const att of atts) {
        items.push({
          messageId: m.id,
          kind: att.kind,
          storageKey: att.storageKey,
          meta: att.meta || {},
          size: att.size || 0,
          body: m.body || '',
        });
      }
    }
  }

  res.json({ items });
});

// Read messages acknowledgment
app.post('/chats/:id/read', authRequired, (req, res) => {
  const chatId = req.params.id;
  const seq = parseInt(req.body.seq, 10) || 0;

  db.prepare(`
    UPDATE chat_members
    SET lastReadSeq = MAX(lastReadSeq, ?)
    WHERE chatId = ? AND userId = ?
  `).run(seq, chatId, req.user.id);

  broadcastToChat(chatId, {
    type: 'read',
    payload: {
      chatId,
      userId: req.user.id,
      seq,
    },
  });

  res.json({ status: 'ok', seq });
});

// ==================== CHAT SETTINGS & MODERATION ====================

// Chat by public username
app.get('/chats/by-username/:username', optionalAuth, (req, res) => {
  const raw = req.params.username.replace(/^@/, '');
  const chat = db.prepare('SELECT * FROM chats WHERE publicUsername = ? OR inviteCode = ?').get(raw, raw);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });
  const memberCount = db.prepare('SELECT COUNT(*) AS c FROM chat_members WHERE chatId = ?').get(chat.id).c;
  const isMember = req.user ? Boolean(db.prepare('SELECT 1 FROM chat_members WHERE chatId = ? AND userId = ?').get(chat.id, req.user.id)) : false;
  const pending = req.user ? Boolean(db.prepare('SELECT 1 FROM chat_join_requests WHERE chatId = ? AND userId = ?').get(chat.id, req.user.id)) : false;
  res.json({
    id: chat.id,
    title: chat.title || 'Чат',
    publicUsername: chat.publicUsername || raw,
    avatarUrl: chat.avatarUrl || null,
    isChannel: chat.type === 'channel',
    requireApproval: Boolean(chat.requireApproval),
    memberCount,
    isMember,
    pending,
  });
});

// Chat settings
app.get('/chats/:id/settings', authRequired, (req, res) => {
  const chat = db.prepare('SELECT * FROM chats WHERE id = ?').get(req.params.id);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });
  res.json({
    title: chat.title || '',
    description: chat.description || '',
    inviteCode: chat.inviteCode || '',
    isPublic: Boolean(chat.isPublic),
    publicUsername: chat.publicUsername || null,
    requireApproval: Boolean(chat.requireApproval),
    memberCanSendMessages: chat.memberCanSendMessages !== 0,
    memberCanSendMedia: chat.memberCanSendMedia !== 0,
    memberCanAddMembers: chat.memberCanAddMembers !== 0,
    slowModeSeconds: chat.slowModeSeconds || 0,
    historyVisibleToNewMembers: chat.historyVisibleToNewMembers !== 0,
    reactionsEnabled: chat.reactionsEnabled !== 0,
  });
});

// Update chat basic info
const handleChatUpdate = (req, res) => {
  const chat = db.prepare('SELECT * FROM chats WHERE id = ?').get(req.params.id);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });
  const cm = getChatMember(req.params.id, req.user.id);
  if (chat.type !== 'dm' && (!cm || (cm.role !== 'owner' && cm.role !== 'admin'))) {
    return res.status(403).json({ error: 'Только администратор может изменять настройки чата' });
  }

  const { title, description, avatarUrl, publicUsername, isPublic, requireApproval, pinned, notifMuted } = req.body;
  db.prepare(`
    UPDATE chats SET
      title = COALESCE(?, title),
      description = COALESCE(?, description),
      avatarUrl = COALESCE(?, avatarUrl),
      publicUsername = COALESCE(?, publicUsername),
      isPublic = COALESCE(?, isPublic),
      requireApproval = COALESCE(?, requireApproval)
    WHERE id = ?
  `).run(
    title ?? null,
    description ?? null,
    avatarUrl ?? null,
    publicUsername ?? null,
    isPublic !== undefined ? (isPublic ? 1 : 0) : null,
    requireApproval !== undefined ? (requireApproval ? 1 : 0) : null,
    req.params.id
  );
  if (pinned !== undefined) {
    db.prepare('UPDATE chat_members SET pinned = ? WHERE chatId = ? AND userId = ?')
      .run(pinned ? 1 : 0, req.params.id, req.user.id);
  }
  if (notifMuted !== undefined) {
    db.prepare('UPDATE chat_members SET notifMuted = ? WHERE chatId = ? AND userId = ?')
      .run(notifMuted ? 1 : 0, req.params.id, req.user.id);
  }
  const updated = db.prepare('SELECT * FROM chats WHERE id = ?').get(req.params.id);
  broadcastToChat(req.params.id, { type: 'chat_update', payload: updated });
  res.json({ status: 'ok', chat: updated });
};
app.route('/chats/:id')
  .patch(authRequired, handleChatUpdate)
  .put(authRequired, handleChatUpdate);

// Chat state for current user
const handleChatState = (req, res) => {
  const { notifMuted, pinned, archived } = req.body;
  if (notifMuted !== undefined) {
    db.prepare('UPDATE chat_members SET notifMuted = ? WHERE chatId = ? AND userId = ?')
      .run(notifMuted ? 1 : 0, req.params.id, req.user.id);
  }
  if (pinned !== undefined) {
    db.prepare('UPDATE chat_members SET pinned = ? WHERE chatId = ? AND userId = ?')
      .run(pinned ? 1 : 0, req.params.id, req.user.id);
  }
  if (archived !== undefined) {
    db.prepare('UPDATE chat_members SET archived = ? WHERE chatId = ? AND userId = ?')
      .run(archived ? 1 : 0, req.params.id, req.user.id);
  }
  res.json({ status: 'ok' });
};
app.route('/chats/:id/state')
  .patch(authRequired, handleChatState)
  .put(authRequired, handleChatState);

// Chat permissions
const handleChatPermissions = (req, res) => {
  const { memberCanSendMessages, memberCanSendMedia, memberCanAddMembers, slowModeSeconds } = req.body;
  db.prepare(`
    UPDATE chats SET
      memberCanSendMessages = COALESCE(?, memberCanSendMessages),
      memberCanSendMedia = COALESCE(?, memberCanSendMedia),
      memberCanAddMembers = COALESCE(?, memberCanAddMembers),
      slowModeSeconds = COALESCE(?, slowModeSeconds)
    WHERE id = ?
  `).run(
    memberCanSendMessages !== undefined ? (memberCanSendMessages ? 1 : 0) : null,
    memberCanSendMedia !== undefined ? (memberCanSendMedia ? 1 : 0) : null,
    memberCanAddMembers !== undefined ? (memberCanAddMembers ? 1 : 0) : null,
    slowModeSeconds !== undefined ? (Number(slowModeSeconds) || 0) : null,
    req.params.id
  );
  const updated = db.prepare('SELECT * FROM chats WHERE id = ?').get(req.params.id);
  if (updated) broadcastToChat(req.params.id, { type: 'chat_update', payload: updated });
  res.json({ status: 'ok' });
};
app.route('/chats/:id/permissions')
  .patch(authRequired, handleChatPermissions)
  .put(authRequired, handleChatPermissions);

// Chat publicity
const handleChatPublicity = (req, res) => {
  const { isPublic, publicUsername, requireApproval } = req.body;
  db.prepare(`
    UPDATE chats SET
      isPublic = COALESCE(?, isPublic),
      publicUsername = COALESCE(?, publicUsername),
      requireApproval = COALESCE(?, requireApproval)
    WHERE id = ?
  `).run(
    isPublic !== undefined ? (isPublic ? 1 : 0) : null,
    publicUsername !== undefined ? publicUsername : null,
    requireApproval !== undefined ? (requireApproval ? 1 : 0) : null,
    req.params.id
  );
  const updated = db.prepare('SELECT * FROM chats WHERE id = ?').get(req.params.id);
  if (updated) broadcastToChat(req.params.id, { type: 'chat_update', payload: updated });
  res.json({ status: 'ok', chat: updated });
};
app.route('/chats/:id/publicity')
  .patch(authRequired, handleChatPublicity)
  .put(authRequired, handleChatPublicity);

// Chat history visibility & moderation
const handleChatModeration = (req, res) => {
  const { historyVisibleToNewMembers, slowModeSeconds } = req.body;
  if (historyVisibleToNewMembers !== undefined) {
    db.prepare('UPDATE chats SET historyVisibleToNewMembers = ? WHERE id = ?')
      .run(historyVisibleToNewMembers ? 1 : 0, req.params.id);
  }
  if (slowModeSeconds !== undefined) {
    db.prepare('UPDATE chats SET slowModeSeconds = ? WHERE id = ?')
      .run(Number(slowModeSeconds) || 0, req.params.id);
  }
  const updated = db.prepare('SELECT * FROM chats WHERE id = ?').get(req.params.id);
  if (updated) broadcastToChat(req.params.id, { type: 'chat_update', payload: updated });
  res.json({ status: 'ok' });
};
app.route('/chats/:id/moderation')
  .patch(authRequired, handleChatModeration)
  .put(authRequired, handleChatModeration);

// Chat reactions enabled
const handleChatReactions = (req, res) => {
  const enabled = req.body.enabled !== undefined ? req.body.enabled : req.body.reactionsEnabled;
  if (enabled !== undefined) {
    db.prepare('UPDATE chats SET reactionsEnabled = ? WHERE id = ?')
      .run(enabled ? 1 : 0, req.params.id);
  }
  const updated = db.prepare('SELECT * FROM chats WHERE id = ?').get(req.params.id);
  if (updated) broadcastToChat(req.params.id, { type: 'chat_update', payload: updated });
  res.json({ status: 'ok' });
};
app.route('/chats/:id/reactions')
  .patch(authRequired, handleChatReactions)
  .put(authRequired, handleChatReactions);

// Generate or get invite link
app.post('/chats/:id/invite', authRequired, (req, res) => {
  let chat = db.prepare('SELECT inviteCode FROM chats WHERE id = ?').get(req.params.id);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });
  let inviteCode = chat.inviteCode;
  if (!inviteCode) {
    inviteCode = crypto.randomBytes(6).toString('hex');
    db.prepare('UPDATE chats SET inviteCode = ? WHERE id = ?').run(inviteCode, req.params.id);
  }
  res.json({ inviteCode, status: 'ok' });
});

// Chat Bans
app.get('/chats/:id/bans', authRequired, (req, res) => {
  const rows = db.prepare(`
    SELECT u.* FROM chat_bans b
    JOIN users u ON b.userId = u.id
    WHERE b.chatId = ?
  `).all(req.params.id);
  res.json({ banned: rows.map(formatUser), bans: rows.map(formatUser) });
});

app.post('/chats/:id/members/:userId/ban', authRequired, (req, res) => {
  const cm = getChatMember(req.params.id, req.user.id);
  if (!cm || (cm.role !== 'owner' && cm.role !== 'admin')) {
    return res.status(403).json({ error: 'Недостаточно прав для блокировки участников' });
  }
  const targetMember = getChatMember(req.params.id, req.params.userId);
  if (targetMember && targetMember.role === 'owner') {
    return res.status(403).json({ error: 'Нельзя заблокировать создателя чата' });
  }

  db.prepare(`
    INSERT INTO chat_bans (chatId, userId, bannedAt)
    VALUES (?, ?, datetime('now'))
    ON CONFLICT(chatId, userId) DO UPDATE SET bannedAt = datetime('now')
  `).run(req.params.id, req.params.userId);
  db.prepare('DELETE FROM chat_members WHERE chatId = ? AND userId = ?').run(req.params.id, req.params.userId);
  res.json({ status: 'ok' });
});

app.delete('/chats/:id/members/:userId/ban', authRequired, (req, res) => {
  const cm = getChatMember(req.params.id, req.user.id);
  if (!cm || (cm.role !== 'owner' && cm.role !== 'admin')) {
    return res.status(403).json({ error: 'Недостаточно прав для разблокировки' });
  }
  db.prepare('DELETE FROM chat_bans WHERE chatId = ? AND userId = ?').run(req.params.id, req.params.userId);
  res.json({ status: 'ok' });
});

// Chat Mute
app.post('/chats/:id/members/:userId/mute', authRequired, (req, res) => {
  const cm = getChatMember(req.params.id, req.user.id);
  if (!cm || (cm.role !== 'owner' && cm.role !== 'admin')) {
    return res.status(403).json({ error: 'Недостаточно прав для ограничения участников' });
  }
  const targetMember = getChatMember(req.params.id, req.params.userId);
  if (targetMember && targetMember.role === 'owner') {
    return res.status(403).json({ error: 'Нельзя ограничить создателя чата' });
  }

  const until = req.body.until || req.body.mutedUntil || new Date(Date.now() + 86400000).toISOString();
  db.prepare('UPDATE chat_members SET mutedUntil = ? WHERE chatId = ? AND userId = ?')
    .run(until, req.params.id, req.params.userId);
  res.json({ status: 'ok' });
});

app.delete('/chats/:id/members/:userId/mute', authRequired, (req, res) => {
  const cm = getChatMember(req.params.id, req.user.id);
  if (!cm || (cm.role !== 'owner' && cm.role !== 'admin')) {
    return res.status(403).json({ error: 'Недостаточно прав' });
  }
  db.prepare('UPDATE chat_members SET mutedUntil = NULL WHERE chatId = ? AND userId = ?')
    .run(req.params.id, req.params.userId);
  res.json({ status: 'ok' });
});

// Kick member
app.delete('/chats/:id/members/:userId', authRequired, (req, res) => {
  const cm = getChatMember(req.params.id, req.user.id);
  if (!cm || (cm.role !== 'owner' && cm.role !== 'admin')) {
    return res.status(403).json({ error: 'Недостаточно прав для удаления участников' });
  }
  const targetMember = getChatMember(req.params.id, req.params.userId);
  if (targetMember && targetMember.role === 'owner') {
    return res.status(403).json({ error: 'Нельзя исключить создателя чата' });
  }
  db.prepare('DELETE FROM chat_members WHERE chatId = ? AND userId = ?')
    .run(req.params.id, req.params.userId);
  res.json({ status: 'ok' });
});

// Update member role
app.patch('/chats/:id/members/:userId', authRequired, (req, res) => {
  const cm = getChatMember(req.params.id, req.user.id);
  if (!cm || cm.role !== 'owner') {
    return res.status(403).json({ error: 'Только владелец чата может назначать роли' });
  }
  const { role } = req.body;
  if (role) {
    db.prepare('UPDATE chat_members SET role = ? WHERE chatId = ? AND userId = ?')
      .run(role, req.params.id, req.params.userId);
  }
  res.json({ status: 'ok' });
});

// Join requests
app.get('/chats/:id/join-requests', authRequired, (req, res) => {
  const cm = getChatMember(req.params.id, req.user.id);
  if (!cm || (cm.role !== 'owner' && cm.role !== 'admin')) {
    return res.status(403).json({ error: 'Недостаточно прав' });
  }
  const rows = db.prepare(`
    SELECT u.* FROM chat_join_requests r
    JOIN users u ON r.userId = u.id
    WHERE r.chatId = ?
  `).all(req.params.id);
  res.json({ requests: rows.map(u => formatUser(u, req.user.id)) });
});

const handleApproveJoinRequest = (req, res) => {
  const chatId = req.params.id;
  const uid = req.params.uid;
  const cm = getChatMember(chatId, req.user.id);
  if (!cm || (cm.role !== 'owner' && cm.role !== 'admin')) {
    return res.status(403).json({ error: 'Недостаточно прав' });
  }
  db.prepare('INSERT OR IGNORE INTO chat_members (chatId, userId, role) VALUES (?, ?, ?)')
    .run(chatId, uid, 'member');
  db.prepare('DELETE FROM chat_join_requests WHERE chatId = ? AND userId = ?')
    .run(chatId, uid);
  broadcastToChat(chatId, {
    type: 'chat_member_joined',
    payload: { chatId, userId: uid }
  });
  res.json({ status: 'ok' });
};

const handleRejectJoinRequest = (req, res) => {
  const chatId = req.params.id;
  const uid = req.params.uid;
  const cm = getChatMember(chatId, req.user.id);
  if (!cm || (cm.role !== 'owner' && cm.role !== 'admin')) {
    return res.status(403).json({ error: 'Недостаточно прав' });
  }
  db.prepare('DELETE FROM chat_join_requests WHERE chatId = ? AND userId = ?')
    .run(chatId, uid);
  res.json({ status: 'ok' });
};

app.route('/chats/:id/join-requests/:uid/approve')
  .post(authRequired, handleApproveJoinRequest)
  .put(authRequired, handleApproveJoinRequest)
  .patch(authRequired, handleApproveJoinRequest);

app.route('/chats/:id/join-requests/:uid/reject')
  .post(authRequired, handleRejectJoinRequest)
  .put(authRequired, handleRejectJoinRequest)
  .patch(authRequired, handleRejectJoinRequest);

// ==================== MESSAGES, REACTIONS, PINS, COMMENTS ====================

// Edit message
app.patch('/chats/:id/messages/:msgId', authRequired, (req, res) => {
  const { body } = req.body;
  if (body === undefined) return res.status(400).json({ error: 'Body required' });

  const msg = db.prepare('SELECT * FROM messages WHERE id = ? AND chatId = ?').get(req.params.msgId, req.params.id);
  if (!msg) return res.status(404).json({ error: 'Message not found' });
  if (msg.senderId !== req.user.id) {
    return res.status(403).json({ error: 'Вы можете редактировать только свои сообщения' });
  }

  db.prepare('UPDATE messages SET body = ?, edited = 1 WHERE id = ? AND chatId = ?')
    .run(body, req.params.msgId, req.params.id);
  const updatedMsg = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.msgId);
  if (updatedMsg) {
    const formatted = formatMessage(updatedMsg, req.user.id);
    broadcastMessageUpdate(req.params.id, updatedMsg, { isEdit: true });
    return res.json({ status: 'ok', message: formatted });
  }
  res.status(404).json({ error: 'Message not found' });
});

// Reactions
const handleMessageReaction = (req, res) => {
  const { emoji, action, replaceOthers } = req.body;
  if (!emoji) return res.status(400).json({ error: 'Emoji required' });
  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.msgId);
  if (!msg) return res.status(404).json({ error: 'Message not found' });

  // Parse existing reactions into dictionary { [emoji]: string[] }
  let reactionsMap = {};
  try {
    const parsed = JSON.parse(msg.reactions || '{}');
    if (Array.isArray(parsed)) {
      for (const r of parsed) {
        if (r && r.emoji && Array.isArray(r.users)) {
          reactionsMap[r.emoji] = r.users;
        }
      }
    } else if (parsed && typeof parsed === 'object' && parsed !== null) {
      for (const [k, v] of Object.entries(parsed)) {
        if (Array.isArray(v)) reactionsMap[k] = v;
      }
    }
  } catch (_) {}

  if (replaceOthers) {
    for (const [k, users] of Object.entries(reactionsMap)) {
      if (k !== emoji) {
        reactionsMap[k] = users.filter(u => u !== req.user.id);
        if (reactionsMap[k].length === 0) delete reactionsMap[k];
      }
    }
  }

  // Toggle user's reaction, or explicit add/remove
  const userList = reactionsMap[emoji] ? [...reactionsMap[emoji]] : [];
  const idx = userList.indexOf(req.user.id);
  if (action === 'add') {
    if (idx === -1) userList.push(req.user.id);
  } else if (action === 'remove') {
    if (idx >= 0) userList.splice(idx, 1);
  } else {
    // Default: toggle
    if (idx >= 0) {
      userList.splice(idx, 1);
    } else {
      userList.push(req.user.id);
    }
  }

  if (userList.length > 0) {
    reactionsMap[emoji] = userList;
  } else {
    delete reactionsMap[emoji];
  }

  db.prepare('UPDATE messages SET reactions = ? WHERE id = ?').run(JSON.stringify(reactionsMap), req.params.msgId);
  const updated = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.msgId);
  const formatted = formatMessage(updated, req.user.id);

  // Broadcast WebSocket update tailored to each user
  broadcastMessageUpdate(msg.chatId, updated, { isReaction: true });

  // Also broadcast reaction event for other listeners
  broadcastToChat(msg.chatId, {
    type: 'reaction',
    payload: {
      messageId: msg.id,
      chatId: msg.chatId,
      reactions: reactionsMap,
      message: formatted,
    },
  });

  res.json({ status: 'ok', reactions: reactionsMap, message: formatted });
};

app.route('/chats/:id/messages/:msgId/reactions')
  .post(authRequired, handleMessageReaction)
  .put(authRequired, handleMessageReaction);

app.route('/chats/:id/messages/:msgId/reaction')
  .post(authRequired, handleMessageReaction)
  .put(authRequired, handleMessageReaction);

app.route('/messages/:msgId/reactions')
  .post(authRequired, handleMessageReaction)
  .put(authRequired, handleMessageReaction);

app.route('/messages/:msgId/reaction')
  .post(authRequired, handleMessageReaction)
  .put(authRequired, handleMessageReaction);

// Unpin specific message
app.delete('/chats/:id/pin/:msgId', authRequired, (req, res) => {
  const chat = db.prepare('SELECT pinnedMessageId FROM chats WHERE id = ?').get(req.params.id);
  if (chat && chat.pinnedMessageId === req.params.msgId) {
    db.prepare('UPDATE chats SET pinnedMessageId = NULL WHERE id = ?').run(req.params.id);
    broadcastToChat(req.params.id, { type: 'unpin', payload: { chatId: req.params.id, messageId: req.params.msgId } });
  }
  res.json({ status: 'ok' });
});

// Comments on posts/messages
app.get('/chats/:id/messages/:msgId/comments', authRequired, (req, res) => {
  const rows = db.prepare(`
    SELECT c.*, u.displayName, u.username, u.avatarUrl FROM comments c
    LEFT JOIN users u ON c.userId = u.id
    WHERE c.messageId = ?
    ORDER BY c.createdAt ASC
  `).all(req.params.msgId);

  const commentsList = rows.map(r => ({
    id: r.id,
    messageId: r.messageId,
    chatId: r.chatId,
    userId: r.userId,
    authorName: r.displayName || r.username || 'Пользователь',
    avatarUrl: r.avatarUrl || null,
    body: r.body,
    createdAt: r.createdAt,
    time: r.createdAt,
  }));

  res.json({
    comments: commentsList,
    items: commentsList,
    total: commentsList.length,
  });
});

app.post('/chats/:id/messages/:msgId/comments', authRequired, (req, res) => {
  const { body } = req.body;
  if (!body) return res.status(400).json({ error: 'Body required' });
  const commentId = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare('INSERT INTO comments (id, messageId, chatId, userId, body, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
    .run(commentId, req.params.msgId, req.params.id, req.user.id, body, now);

  const newComment = {
    id: commentId,
    messageId: req.params.msgId,
    chatId: req.params.id,
    userId: req.user.id,
    authorName: req.user.displayName || req.user.username || 'Пользователь',
    avatarUrl: req.user.avatarUrl || null,
    body,
    createdAt: now,
    time: now,
  };

  broadcastToChat(req.params.id, {
    type: 'comment',
    payload: newComment,
  });

  res.json({ status: 'ok', comment: newComment });
});

// Chat Avatar upload
app.post('/chats/:id/avatar', authRequired, upload.any(), (req, res) => {
  const chat = db.prepare('SELECT * FROM chats WHERE id = ?').get(req.params.id);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });
  const cm = getChatMember(req.params.id, req.user.id);
  if (chat.type !== 'dm' && (!cm || (cm.role !== 'owner' && cm.role !== 'admin'))) {
    return res.status(403).json({ error: 'Только администратор может изменять аватар чата' });
  }
  const file = req.file || (req.files && req.files[0]);
  if (!file) return res.status(400).json({ error: 'File required' });
  const avatarUrl = `${getBaseUrl(req)}/uploads/${file.filename}`;
  db.prepare('UPDATE chats SET avatarUrl = ? WHERE id = ?').run(avatarUrl, req.params.id);
  res.json({ avatarUrl, url: avatarUrl, status: 'ok' });
});

// Delete message
app.delete('/chats/:id/messages/:msgId', authRequired, (req, res) => {
  const msg = db.prepare('SELECT * FROM messages WHERE id = ? AND chatId = ?').get(req.params.msgId, req.params.id);
  if (!msg) return res.json({ status: 'ok' });
  const cm = getChatMember(req.params.id, req.user.id);
  const isAuthor = msg.senderId === req.user.id;
  const isAdmin = cm && (cm.role === 'owner' || cm.role === 'admin');
  if (!isAuthor && !isAdmin) {
    return res.status(403).json({ error: 'Нет прав на удаление этого сообщения' });
  }
  db.prepare('DELETE FROM messages WHERE id = ? AND chatId = ?').run(req.params.msgId, req.params.id);
  broadcastToChat(req.params.id, {
    type: 'message_deleted',
    payload: { chatId: req.params.id, messageId: req.params.msgId }
  });
  res.json({ status: 'ok' });
});

// Increment views
app.post('/chats/:id/messages/:msgId/view', authRequired, (req, res) => {
  db.prepare('UPDATE messages SET views = views + 1 WHERE id = ?').run(req.params.msgId);
  const msg = db.prepare('SELECT views FROM messages WHERE id = ?').get(req.params.msgId);
  res.json({ viewCount: msg ? msg.views : 1 });
});

// Pin/Unpin message
app.patch('/chats/:id/pin', authRequired, (req, res) => {
  const chat = db.prepare('SELECT * FROM chats WHERE id = ?').get(req.params.id);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });
  const cm = getChatMember(req.params.id, req.user.id);
  if (chat.type !== 'dm' && (!cm || (cm.role !== 'owner' && cm.role !== 'admin'))) {
    return res.status(403).json({ error: 'Только администратор может закреплять сообщения' });
  }
  const messageId = req.body.messageId || req.body.id || null;
  db.prepare('UPDATE chats SET pinnedMessageId = ? WHERE id = ?').run(messageId, req.params.id);
  res.json({ status: 'ok' });
});

// Pins list
app.get('/chats/:id/pins', authRequired, (req, res) => {
  const chat = db.prepare('SELECT pinnedMessageId FROM chats WHERE id = ?').get(req.params.id);
  if (chat && chat.pinnedMessageId) {
    const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(chat.pinnedMessageId);
    if (msg) {
      return res.json({
        pins: [{
          id: msg.id,
          body: msg.body || '',
          senderId: msg.senderId,
          ...formatMessage(msg, req.user.id),
        }],
      });
    }
  }
  res.json({ pins: [] });
});

// Chat members
app.get('/chats/:id/members', authRequired, (req, res) => {
  const chat = db.prepare('SELECT isPublic FROM chats WHERE id = ?').get(req.params.id);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });
  const cm = getChatMember(req.params.id, req.user.id);
  if (!cm && !chat.isPublic) {
    return res.status(403).json({ error: 'Доступ запрещён' });
  }
  const rows = db.prepare(`
    SELECT u.*, cm.role, cm.mutedUntil, cm.lastReadSeq FROM chat_members cm
    JOIN users u ON cm.userId = u.id
    WHERE cm.chatId = ?
  `).all(req.params.id);
  res.json({
    total: rows.length,
    members: rows.map(r => ({
      ...formatUser(r, req.user.id),
      role: r.role || 'member',
      mutedUntil: r.mutedUntil || null,
      lastReadSeq: r.lastReadSeq || 0,
    })),
  });
});

app.post('/chats/:id/members', authRequired, (req, res) => {
  const chat = db.prepare('SELECT * FROM chats WHERE id = ?').get(req.params.id);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });
  const cm = getChatMember(req.params.id, req.user.id);
  if (chat.type !== 'dm' && (!cm || (cm.role !== 'owner' && cm.role !== 'admin' && chat.memberCanAddMembers === 0))) {
    return res.status(403).json({ error: 'Добавление участников ограничено администратором' });
  }
  const { userId } = req.body;
  if (userId) {
    db.prepare('INSERT OR IGNORE INTO chat_members (chatId, userId, role) VALUES (?, ?, ?)')
      .run(req.params.id, userId, 'member');
    const joinedUser = db.prepare('SELECT id, username, displayName FROM users WHERE id = ?').get(userId);
    broadcastToChat(req.params.id, {
      type: 'chat_member_joined',
      payload: {
        chatId: req.params.id,
        userId,
        user: joinedUser ? { id: joinedUser.id, username: joinedUser.username, displayName: joinedUser.displayName || joinedUser.username } : null
      }
    });
  }
  res.json({ status: 'ok' });
});

app.post('/chats/:id/leave', authRequired, (req, res) => {
  db.prepare('DELETE FROM chat_members WHERE chatId = ? AND userId = ?').run(req.params.id, req.user.id);
  res.json({ status: 'ok' });
});

app.post('/chats/:id/clear', authRequired, (req, res) => {
  const chat = db.prepare('SELECT * FROM chats WHERE id = ?').get(req.params.id);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });
  const cm = getChatMember(req.params.id, req.user.id);
  if (!cm || (chat.type !== 'dm' && cm.role !== 'owner' && cm.role !== 'admin')) {
    return res.status(403).json({ error: 'Недостаточно прав для очистки истории чата' });
  }
  db.prepare('DELETE FROM messages WHERE chatId = ?').run(req.params.id);
  res.json({ status: 'ok' });
});

app.delete('/chats/:id', authRequired, (req, res) => {
  const chat = db.prepare('SELECT * FROM chats WHERE id = ?').get(req.params.id);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });
  const cm = getChatMember(req.params.id, req.user.id);
  if (chat.type === 'dm') {
    if (!cm) return res.status(403).json({ error: 'Доступ запрещён' });
  } else {
    if (!cm || cm.role !== 'owner') {
      return res.status(403).json({ error: 'Только создатель может удалить группу или канал' });
    }
  }
  db.prepare('DELETE FROM chats WHERE id = ?').run(req.params.id);
  db.prepare('DELETE FROM chat_members WHERE chatId = ?').run(req.params.id);
  db.prepare('DELETE FROM messages WHERE chatId = ?').run(req.params.id);
  res.json({ status: 'ok' });
});

// Invite & Preview & Join
app.get('/chats/invite/:code', optionalAuth, (req, res) => {
  const chat = db.prepare('SELECT * FROM chats WHERE inviteCode = ?').get(req.params.code);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });
  const memberCount = db.prepare('SELECT COUNT(*) AS c FROM chat_members WHERE chatId = ?').get(chat.id).c;
  const isMember = req.user ? Boolean(db.prepare('SELECT 1 FROM chat_members WHERE chatId = ? AND userId = ?').get(chat.id, req.user.id)) : false;
  const pending = req.user ? Boolean(db.prepare('SELECT 1 FROM chat_join_requests WHERE chatId = ? AND userId = ?').get(chat.id, req.user.id)) : false;
  res.json({
    id: chat.id,
    title: chat.title || 'Чат',
    avatarUrl: chat.avatarUrl || null,
    isChannel: chat.type === 'channel',
    requireApproval: Boolean(chat.requireApproval),
    memberCount,
    isMember,
    pending,
  });
});

app.get('/chats/preview/:code', optionalAuth, (req, res) => {
  const chat = db.prepare('SELECT * FROM chats WHERE inviteCode = ?').get(req.params.code);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });
  const memberCount = db.prepare('SELECT COUNT(*) AS c FROM chat_members WHERE chatId = ?').get(chat.id).c;
  const isMember = req.user ? Boolean(db.prepare('SELECT 1 FROM chat_members WHERE chatId = ? AND userId = ?').get(chat.id, req.user.id)) : false;
  const pending = req.user ? Boolean(db.prepare('SELECT 1 FROM chat_join_requests WHERE chatId = ? AND userId = ?').get(chat.id, req.user.id)) : false;
  res.json({
    id: chat.id,
    title: chat.title || 'Чат',
    avatarUrl: chat.avatarUrl || null,
    isChannel: chat.type === 'channel',
    requireApproval: Boolean(chat.requireApproval),
    memberCount,
    isMember,
    pending,
  });
});

// Get single chat details
app.get('/chats/:id', optionalAuth, (req, res) => {
  const c = db.prepare('SELECT * FROM chats WHERE id = ?').get(req.params.id);
  if (!c) return res.status(404).json({ error: 'Chat not found' });

  let cm = null;
  if (req.user) {
    cm = db.prepare('SELECT role AS myRole, canWrite, lastReadSeq, notifMuted, pinned, archived FROM chat_members WHERE chatId = ? AND userId = ?')
      .get(c.id, req.user.id);
  }

  let peer = null;
  if (c.type === 'dm' && req.user) {
    const peerMember = db.prepare('SELECT userId FROM chat_members WHERE chatId = ? AND userId != ?').get(c.id, req.user.id);
    if (peerMember) {
      const peerUser = db.prepare('SELECT * FROM users WHERE id = ?').get(peerMember.userId);
      peer = formatUser(peerUser);
    }
  }

  const lastMsg = db.prepare('SELECT * FROM messages WHERE chatId = ? ORDER BY seq DESC LIMIT 1').get(c.id);
  const lastRead = cm?.lastReadSeq || 0;
  const unreadCount = req.user ? db.prepare('SELECT COUNT(*) AS count FROM messages WHERE chatId = ? AND seq > ?').get(c.id, lastRead) : null;
  const memberCountRow = db.prepare('SELECT COUNT(*) AS count FROM chat_members WHERE chatId = ?').get(c.id);
  const isPending = req.user ? Boolean(db.prepare('SELECT 1 FROM chat_join_requests WHERE chatId = ? AND userId = ?').get(c.id, req.user.id)) : false;

  const formatted = {
    id: c.id,
    type: c.type,
    title: c.type === 'dm' && peer ? peer.displayName : (c.title || 'Чат'),
    avatarUrl: c.type === 'dm' && peer ? peer.avatarUrl : c.avatarUrl,
    description: c.description || '',
    publicUsername: c.publicUsername || null,
    inviteCode: c.inviteCode || '',
    isPublic: Boolean(c.isPublic),
    requireApproval: Boolean(c.requireApproval),
    peer,
    lastMessage: lastMsg && req.user ? formatMessage(lastMsg, req.user.id) : null,
    unread: unreadCount ? unreadCount.count : 0,
    isChannel: c.type === 'channel',
    notifMuted: Boolean(cm?.notifMuted),
    lastReadSeq: cm?.lastReadSeq || 0,
    myRole: cm?.myRole || (c.type === 'dm' ? 'member' : null),
    canWrite: cm ? Boolean(cm.canWrite) : true,
    pinned: Boolean(cm?.pinned),
    archived: Boolean(cm?.archived),
    memberCount: memberCountRow ? memberCountRow.count : 1,
    isMember: Boolean(cm),
    pending: isPending,
    verified: Boolean(c.verified || (peer && peer.verified)),
    isVerified: Boolean(c.verified || (peer && peer.verified)),
  };

  res.json({
    ...formatted,
    chat: formatted,
  });
});

app.post('/chats/join-by-code', authRequired, (req, res) => {
  const { code } = req.body;
  const chat = db.prepare('SELECT * FROM chats WHERE inviteCode = ?').get(code);
  if (!chat) return res.status(404).json({ error: 'Ссылка недействительна' });

  if (chat.requireApproval) {
    db.prepare(`
      INSERT INTO chat_join_requests (chatId, userId, createdAt)
      VALUES (?, ?, datetime('now'))
      ON CONFLICT(chatId, userId) DO UPDATE SET createdAt = datetime('now')
    `).run(chat.id, req.user.id);
    return res.json({ status: 'pending', pending: true, chatId: chat.id });
  }

  db.prepare('INSERT OR IGNORE INTO chat_members (chatId, userId, role) VALUES (?, ?, ?)').run(chat.id, req.user.id, 'member');
  const joinedUserCode = db.prepare('SELECT id, username, displayName FROM users WHERE id = ?').get(req.user.id);
  broadcastToChat(chat.id, {
    type: 'chat_member_joined',
    payload: {
      chatId: chat.id,
      userId: req.user.id,
      user: joinedUserCode ? { id: joinedUserCode.id, username: joinedUserCode.username, displayName: joinedUserCode.displayName || joinedUserCode.username } : null
    }
  });
  res.json({ status: 'joined', pending: false, chatId: chat.id });
});

app.post('/chats/:id/join', authRequired, (req, res) => {
  const chat = db.prepare('SELECT * FROM chats WHERE id = ?').get(req.params.id);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });

  if (chat.requireApproval) {
    db.prepare(`
      INSERT INTO chat_join_requests (chatId, userId, createdAt)
      VALUES (?, ?, datetime('now'))
      ON CONFLICT(chatId, userId) DO UPDATE SET createdAt = datetime('now')
    `).run(chat.id, req.user.id);
    return res.json({ status: 'pending', pending: true });
  }

  db.prepare('INSERT OR IGNORE INTO chat_members (chatId, userId, role) VALUES (?, ?, ?)').run(req.params.id, req.user.id, 'member');
  const joinedUserDirect = db.prepare('SELECT id, username, displayName FROM users WHERE id = ?').get(req.user.id);
  broadcastToChat(req.params.id, {
    type: 'chat_member_joined',
    payload: {
      chatId: req.params.id,
      userId: req.user.id,
      user: joinedUserDirect ? { id: joinedUserDirect.id, username: joinedUserDirect.username, displayName: joinedUserDirect.displayName || joinedUserDirect.username } : null
    }
  });
  res.json({ status: 'joined', pending: false });
});

// ==================== SCHEDULED MESSAGES ====================

app.get('/scheduled', authRequired, (req, res) => {
  const rows = db.prepare('SELECT * FROM scheduled_messages WHERE userId = ? ORDER BY sendAt ASC').all(req.user.id);
  res.json(rows.map(r => {
    let attachments = [];
    try { attachments = JSON.parse(r.attachments || '[]'); } catch (_) {}
    return {
      id: r.id,
      chatId: r.chatId,
      body: r.body || '',
      sendAt: r.sendAt,
      attachments,
    };
  }));
});

app.post('/chats/:id/scheduled', authRequired, (req, res) => {
  const { body, sendAt } = req.body;
  const id = crypto.randomUUID();
  const finalSendAt = sendAt || new Date(Date.now() + 3600000).toISOString();
  db.prepare('INSERT INTO scheduled_messages (id, chatId, userId, body, sendAt, attachments, createdAt) VALUES (?, ?, ?, ?, ?, ?, datetime(\'now\'))')
    .run(id, req.params.id, req.user.id, body || '', finalSendAt, '[]');
  res.json({ status: 'ok', id, sendAt: finalSendAt });
});

app.post('/chats/:id/scheduled/attachments', authRequired, upload.any(), (req, res) => {
  const id = crypto.randomUUID();
  const sendAt = req.body.sendAt || new Date(Date.now() + 3600000).toISOString();
  const body = req.body.body || req.body.caption || '';
  const attachments = [];

  for (const file of (req.files || [])) {
    const storageKey = `/uploads/${file.filename}`;
    const isImage = file.mimetype.startsWith('image/');
    const isVideo = file.mimetype.startsWith('video/');
    const isAudio = file.mimetype.startsWith('audio/') || file.originalname.endsWith('.m4a');
    let kind = 'file';
    if (isImage) kind = 'image';
    else if (isVideo) kind = 'video';
    else if (isAudio) kind = 'audio';

    attachments.push({
      kind,
      storageKey,
      mime: file.mimetype,
      meta: { filename: file.originalname, size: file.size },
      size: file.size,
    });
  }

  db.prepare('INSERT INTO scheduled_messages (id, chatId, userId, body, sendAt, attachments, createdAt) VALUES (?, ?, ?, ?, ?, ?, datetime(\'now\'))')
    .run(id, req.params.id, req.user.id, body, sendAt, JSON.stringify(attachments));

  res.json({ status: 'ok', id, sendAt, attachments });
});

app.delete('/scheduled/:id', authRequired, (req, res) => {
  db.prepare('DELETE FROM scheduled_messages WHERE id = ? AND userId = ?').run(req.params.id, req.user.id);
  res.json({ status: 'ok' });
});

// Coins
app.get('/coins', authRequired, (req, res) => {
  res.json({ coins: req.user.coins || 1000 });
});

// ==================== STICKER PACKS ====================

app.get('/sticker-packs', authRequired, (req, res) => {
  const rows = db.prepare('SELECT * FROM sticker_packs').all();
  res.json(rows.map(r => {
    let items = [];
    try { items = JSON.parse(r.items || '[]'); } catch (_) {}
    return {
      id: r.id,
      name: r.name || 'Набор',
      avatarUrl: r.avatarUrl || (items.length > 0 ? items[0].storageKey : null),
      items,
    };
  }));
});

app.post('/sticker-packs', authRequired, (req, res) => {
  const { name } = req.body;
  const id = crypto.randomUUID();
  db.prepare('INSERT INTO sticker_packs (id, userId, name, items, createdAt) VALUES (?, ?, ?, ?, datetime(\'now\'))')
    .run(id, req.user.id, name || 'Новый набор', '[]');
  res.json({ id, name: name || 'Новый набор', status: 'ok' });
});

app.delete('/sticker-packs/:id', authRequired, (req, res) => {
  db.prepare('DELETE FROM sticker_packs WHERE id = ? AND userId = ?').run(req.params.id, req.user.id);
  res.json({ status: 'ok' });
});

app.post('/sticker-packs/:id/items', authRequired, upload.any(), (req, res) => {
  const file = req.file || (req.files && req.files[0]);
  if (!file) return res.status(400).json({ error: 'File required' });
  const storageKey = `/uploads/${file.filename}`;
  const pack = db.prepare('SELECT * FROM sticker_packs WHERE id = ?').get(req.params.id);
  if (!pack) return res.status(404).json({ error: 'Sticker pack not found' });

  let items = [];
  try { items = JSON.parse(pack.items || '[]'); } catch (_) {}
  const newItem = {
    storageKey,
    mime: file.mimetype || 'image/png',
  };
  items.push(newItem);

  const avatarUrl = pack.avatarUrl || storageKey;
  db.prepare('UPDATE sticker_packs SET items = ?, avatarUrl = ? WHERE id = ?')
    .run(JSON.stringify(items), avatarUrl, req.params.id);

  res.json({ status: 'ok', storageKey, avatarUrl });
});

// ==================== E2EE KEYS ====================

app.put('/e2ee/keys', authRequired, (req, res) => {
  const { deviceId, identityKey, signedPrekey, oneTimePrekeys } = req.body;
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO e2ee_keys (userId, deviceId, identityKey, signedPrekey, oneTimePrekeys, updatedAt)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(userId, deviceId) DO UPDATE SET
      identityKey = excluded.identityKey,
      signedPrekey = excluded.signedPrekey,
      oneTimePrekeys = excluded.oneTimePrekeys,
      updatedAt = excluded.updatedAt
  `).run(
    req.user.id,
    deviceId || 'default',
    identityKey || '',
    JSON.stringify(signedPrekey || {}),
    JSON.stringify(oneTimePrekeys || []),
    now
  );
  res.json({ status: 'ok' });
});

app.get('/e2ee/keys/bundle/:userId', authRequired, (req, res) => {
  const targetId = req.params.userId;
  const keys = db.prepare('SELECT * FROM e2ee_keys WHERE userId = ? ORDER BY updatedAt DESC LIMIT 1').get(targetId);
  if (!keys) {
    return res.json({
      deviceId: 'dev_' + targetId.slice(0, 8),
      identityKey: 'idk_' + targetId,
      signingIdentityKey: 'sidk_' + targetId,
      signedPrekeyId: 1,
      signedPrekey: 'spk_' + targetId,
      signedPrekeySignature: 'sig_' + targetId,
      oneTimePrekey: { keyId: 1, publicKey: 'otpk_' + targetId },
    });
  }

  let signedPrekey = keys.signedPrekey;
  let signedPrekeyId = 1;
  let signedPrekeySignature = 'sig_' + targetId;
  let signingIdentityKey = keys.identityKey || 'sidk_' + targetId;

  if (typeof signedPrekey === 'string' && signedPrekey.startsWith('{')) {
    try {
      const parsed = JSON.parse(signedPrekey);
      signedPrekeyId = parsed.keyId || parsed.id || 1;
      signedPrekey = parsed.publicKey || parsed.key || signedPrekey;
      signedPrekeySignature = parsed.signature || signedPrekeySignature;
      signingIdentityKey = parsed.signingIdentityKey || signingIdentityKey;
    } catch (_) {}
  }

  let oneTimePrekeys = [];
  try { oneTimePrekeys = JSON.parse(keys.oneTimePrekeys || '[]'); } catch (_) {}
  const otp = oneTimePrekeys.pop() || null;
  if (otp) {
    db.prepare('UPDATE e2ee_keys SET oneTimePrekeys = ? WHERE userId = ? AND deviceId = ?')
      .run(JSON.stringify(oneTimePrekeys), targetId, keys.deviceId);
  }

  res.json({
    deviceId: keys.deviceId || 'default',
    identityKey: keys.identityKey || 'idk',
    signingIdentityKey,
    signedPrekeyId,
    signedPrekey: typeof signedPrekey === 'string' ? signedPrekey : JSON.stringify(signedPrekey),
    signedPrekeySignature,
    oneTimePrekey: otp ? (typeof otp === 'object' ? otp : { keyId: 1, publicKey: otp }) : null,
  });
});

app.get('/e2ee/keys/bundles/:targetId', authRequired, (req, res) => {
  const targetId = req.params.targetId;
  let memberIds = [targetId];
  const members = db.prepare('SELECT userId FROM chat_members WHERE chatId = ?').all(targetId);
  if (members.length > 0) {
    memberIds = members.map(m => m.userId);
  }

  const bundles = [];
  for (const uid of memberIds) {
    const keys = db.prepare('SELECT * FROM e2ee_keys WHERE userId = ? LIMIT 1').get(uid);
    if (keys) {
      let spk = keys.signedPrekey;
      let spkId = 1;
      let sig = 'sig_' + uid;
      if (typeof spk === 'string' && spk.startsWith('{')) {
        try {
          const parsed = JSON.parse(spk);
          spkId = parsed.keyId || 1;
          spk = parsed.publicKey || spk;
          sig = parsed.signature || sig;
        } catch (_) {}
      }
      bundles.push({
        deviceId: keys.deviceId || 'default',
        identityKey: keys.identityKey || 'idk',
        signingIdentityKey: keys.identityKey || 'idk',
        signedPrekeyId: spkId,
        signedPrekey: typeof spk === 'string' ? spk : JSON.stringify(spk),
        signedPrekeySignature: sig,
      });
    }
  }
  res.json({ bundles });
});

app.get('/e2ee/keys/status/:userId', authRequired, (req, res) => {
  const exists = db.prepare('SELECT COUNT(*) AS c FROM e2ee_keys WHERE userId = ?').get(req.params.userId);
  const count = exists ? exists.c : 0;
  res.json({ hasKeys: count > 0, deviceCount: Math.max(1, count) });
});

app.get('/e2ee/keys/one-time-prekeys/count', authRequired, (req, res) => {
  const deviceId = req.query.deviceId;
  let count = 50;
  const row = db.prepare('SELECT oneTimePrekeys FROM e2ee_keys WHERE userId = ?' + (deviceId ? ' AND deviceId = ?' : '')).get(...(deviceId ? [req.user.id, deviceId] : [req.user.id]));
  if (row) {
    try { count = JSON.parse(row.oneTimePrekeys || '[]').length; } catch (_) {}
  }
  res.json({ count, remaining: count });
});

app.post('/e2ee/keys/one-time-prekeys', authRequired, (req, res) => {
  const { oneTimePrekeys, deviceId } = req.body;
  if (Array.isArray(oneTimePrekeys)) {
    const targetDev = deviceId || 'default';
    const row = db.prepare('SELECT oneTimePrekeys FROM e2ee_keys WHERE userId = ? AND deviceId = ?').get(req.user.id, targetDev);
    let existing = [];
    if (row) {
      try { existing = JSON.parse(row.oneTimePrekeys || '[]'); } catch (_) {}
    }
    const combined = existing.concat(oneTimePrekeys);
    db.prepare(`
      INSERT INTO e2ee_keys (userId, deviceId, identityKey, signedPrekey, oneTimePrekeys, updatedAt)
      VALUES (?, ?, '', '', ?, datetime('now'))
      ON CONFLICT(userId, deviceId) DO UPDATE SET
        oneTimePrekeys = excluded.oneTimePrekeys,
        updatedAt = datetime('now')
    `).run(req.user.id, targetDev, JSON.stringify(combined));
  }
  res.json({ status: 'ok' });
});

// Scheduled messages background runner
setInterval(() => {
  try {
    const now = new Date().toISOString();
    const ready = db.prepare('SELECT * FROM scheduled_messages WHERE sendAt <= ?').all(now);
    for (const item of ready) {
      const msgId = crypto.randomUUID();
      const lastMsg = db.prepare('SELECT MAX(seq) AS maxSeq FROM messages WHERE chatId = ?').get(item.chatId);
      const seq = (lastMsg && lastMsg.maxSeq ? lastMsg.maxSeq : 0) + 1;

      db.prepare(`
        INSERT INTO messages (id, chatId, senderId, body, seq, attachments, createdAt)
        VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
      `).run(msgId, item.chatId, item.userId, item.body, seq, item.attachments || '[]');

      db.prepare('DELETE FROM scheduled_messages WHERE id = ?').run(item.id);

      const newMsg = db.prepare('SELECT * FROM messages WHERE id = ?').get(msgId);
      broadcastToChat(item.chatId, {
        type: 'message',
        payload: formatMessage(newMsg, null),
      });
    }
  } catch (e) {
    console.error('Scheduled messages runner error:', e);
  }
}, 5000);

// Healthcheck
app.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

// Digital Asset Links for Android App Links verification
app.get('/.well-known/assetlinks.json', (req, res) => {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.json([
    {
      relation: ['delegate_permission/common.handle_all_urls'],
      target: {
        namespace: 'android_app',
        package_name: 'com.example.slimchatyou',
        sha256_cert_fingerprints: [
          '5E:A1:C6:D9:C9:F8:B8:FA:0D:01:A0:59:96:91:CF:FC:68:FA:26:CB:38:AB:D4:F6:68:0B:FF:E2:6D:54:6B:6D'
        ]
      }
    }
  ]);
});

// Download APK
app.get('/download', (req, res) => {
  const appApk = '/root/slimchat-backend/app.apk';
  if (fs.existsSync(appApk)) {
    return res.download(appApk, 'SlimChat You v13.75.apk');
  }
  const v1375 = '/root/slimchat-backend/slimchat_13_75.apk';
  if (fs.existsSync(v1375)) {
    return res.download(v1375, 'SlimChat You v13.75.apk');
  }
  res.status(404).send('APK file not found on server');
});

app.get('/app.apk', (req, res) => {
  res.download('/root/slimchat-backend/app.apk', 'app.apk');
});

app.get('/slimchat_13_75.apk', (req, res) => {
  res.download('/root/slimchat-backend/slimchat_13_75.apk', 'slimchat_13_75.apk');
});

// Download Decompiled Sources ZIP
app.get('/download-sources', (req, res) => {
  const zipPath = '/root/slimchat-apk-sources.zip';
  if (fs.existsSync(zipPath)) {
    res.download(zipPath, 'slimchat-apk-sources.zip');
  } else {
    res.status(404).send('Sources zip not found');
  }
});

// Download Clean Original-style Android Project ZIP
app.get('/download-project', (req, res) => {
  const zipPath = '/root/SlimChat-Android.zip';
  if (fs.existsSync(zipPath)) {
    res.download(zipPath, 'SlimChat-Android.zip');
  } else {
    res.status(404).send('Project zip not found');
  }
});

// Crash reports endpoint (from new Android client)
app.post('/crash-reports', (req, res) => {
  const text = req.body?.text || (typeof req.body === 'string' ? req.body : JSON.stringify(req.body));
  console.log('[CRASH-REPORT]', text);
  res.json({ success: true, status: 'ok' });
});

// Helper functions for landing preview page
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function pluralizeRussian(n, one, two, five) {
  n = Math.abs(n) % 100;
  const n1 = n % 10;
  if (n > 10 && n < 20) return five;
  if (n1 > 1 && n1 < 5) return two;
  if (n1 === 1) return one;
  return five;
}

function renderChatInvitePage(chat, fullUrl, rawTarget, isUsername = false, inviteUser = null) {
  const isUserInvite = Boolean(inviteUser);
  const isFound = Boolean(chat || inviteUser);
  let title = 'Чат не найден';
  let typeLabel = 'Чат';
  let description = 'Данная ссылка для приглашения недействительна или была удалена.';
  let avatarUrl = null;
  let pathPart = isUsername ? `g/${encodeURIComponent(rawTarget)}` : `join/${encodeURIComponent(rawTarget)}`;
  let memberLabel = '';

  if (isUserInvite) {
    title = inviteUser.displayName || (inviteUser.username ? `@${inviteUser.username}` : 'Пользователь SlimChat');
    typeLabel = 'Приглашение';
    description = `Пользователь ${title} приглашает вас в SlimChat Messenger.`;
    avatarUrl = inviteUser.avatarUrl || null;
    pathPart = `i/${encodeURIComponent(rawTarget)}`;
  } else if (chat) {
    title = chat.title || (isUsername ? `@${rawTarget}` : 'Чат');
    const isChannel = chat.type === 'channel';
    typeLabel = isChannel ? 'Канал' : (chat?.type === 'group' ? 'Группа' : 'Чат');
    description = chat.description || '';
    avatarUrl = chat.avatarUrl || null;
    pathPart = isUsername ? `g/${encodeURIComponent(rawTarget)}` : `join/${encodeURIComponent(rawTarget)}`;

    let memberCount = 0;
    const row = db.prepare('SELECT COUNT(*) AS c FROM chat_members WHERE chatId = ?').get(chat.id);
    memberCount = row ? row.c : 0;
    memberLabel = isChannel 
      ? `${memberCount} ${pluralizeRussian(memberCount, 'подписчик', 'подписчика', 'подписчиков')}`
      : `${memberCount} ${pluralizeRussian(memberCount, 'участник', 'участника', 'участников')}`;
  }

  const firstLetter = escapeHtml(title.trim().charAt(0).toUpperCase() || 'S');
  const intentUrl = `intent://jxiwm.btxc.indevs.in/${pathPart}#Intent;scheme=https;package=com.example.slimchatyou;action=android.intent.action.VIEW;category=android.intent.category.BROWSABLE;end;`;

  return `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>${escapeHtml(title)} — SlimChat</title>
  
  <meta property="og:type" content="website">
  <meta property="og:site_name" content="SlimChat">
  <meta property="og:title" content="${escapeHtml(title)}">
  <meta property="og:description" content="${escapeHtml(description || (isFound ? `${typeLabel} • ${memberLabel}` : 'Ссылка недействительна'))}">
  ${avatarUrl ? `<meta property="og:image" content="${escapeHtml(avatarUrl)}">` : ''}
  <meta property="og:url" content="${escapeHtml(fullUrl)}">
  <meta name="theme-color" content="#2481cc">

  <style>
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      -webkit-tap-highlight-color: transparent;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: #0e1621;
      color: #f5f5f5;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 24px 16px;
    }
    .card {
      background: #17212b;
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 24px;
      box-shadow: 0 16px 40px rgba(0, 0, 0, 0.5);
      width: 100%;
      max-width: 420px;
      padding: 36px 24px 28px;
      text-align: center;
      display: flex;
      flex-direction: column;
      align-items: center;
    }
    .avatar-wrap {
      width: 108px;
      height: 108px;
      border-radius: 50%;
      margin-bottom: 18px;
      overflow: hidden;
      display: flex;
      align-items: center;
      justify-content: center;
      background: linear-gradient(135deg, #2481cc, #52a9e8);
      box-shadow: 0 8px 24px rgba(36, 129, 204, 0.35);
    }
    .avatar-img {
      width: 100%;
      height: 100%;
      object-fit: cover;
    }
    .avatar-letter {
      font-size: 46px;
      font-weight: 700;
      color: #ffffff;
      text-transform: uppercase;
      user-select: none;
    }
    .title {
      font-size: 24px;
      font-weight: 700;
      line-height: 1.25;
      color: #ffffff;
      margin-bottom: 6px;
      word-break: break-word;
    }
    .subtitle {
      font-size: 14px;
      color: #798b9c;
      font-weight: 500;
      margin-bottom: 16px;
    }
    .badge {
      display: inline-block;
      padding: 4px 12px;
      background: rgba(36, 129, 204, 0.18);
      color: #52a9e8;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 600;
      margin-bottom: 12px;
      letter-spacing: 0.2px;
    }
    .desc {
      font-size: 15px;
      line-height: 1.45;
      color: #c4d3e0;
      margin-bottom: 24px;
      white-space: pre-wrap;
      word-break: break-word;
      max-width: 100%;
    }
    .actions {
      width: 100%;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .btn {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      width: 100%;
      padding: 14px 20px;
      font-size: 16px;
      font-weight: 600;
      border-radius: 14px;
      text-decoration: none;
      transition: transform 0.15s ease, filter 0.15s ease;
      cursor: pointer;
      border: none;
    }
    .btn:active {
      transform: scale(0.98);
    }
    .btn-primary {
      background: #2481cc;
      color: #ffffff;
      box-shadow: 0 4px 16px rgba(36, 129, 204, 0.35);
    }
    .btn-primary:hover {
      filter: brightness(1.08);
    }
    .btn-secondary {
      background: rgba(255, 255, 255, 0.08);
      color: #8bb5db;
    }
    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.12);
      color: #ffffff;
    }
    .hint {
      margin-top: 18px;
      font-size: 12px;
      color: #5c6c7c;
      line-height: 1.4;
    }
    .brand {
      margin-top: 24px;
      font-size: 13px;
      color: #5c6c7c;
      display: flex;
      align-items: center;
      gap: 6px;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="avatar-wrap">
      ${avatarUrl 
        ? `<img class="avatar-img" src="${escapeHtml(avatarUrl)}" alt="Avatar">`
        : `<span class="avatar-letter">${firstLetter}</span>`
      }
    </div>
    
    ${isFound ? '<div class="badge">' + escapeHtml(typeLabel) + '</div>' : ''}
    <h1 class="title">${escapeHtml(title)}</h1>
    ${isFound ? '<div class="subtitle">' + escapeHtml(memberLabel) + '</div>' : ''}
    
    <div class="desc">${escapeHtml(description)}</div>
    
    <div class="actions">
      ${isFound ? `
        <a id="openAppBtn" href="${escapeHtml(intentUrl)}" class="btn btn-primary">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 14.5v-9l6 4.5-6 4.5z"/></svg>
          Перейти
        </a>
      ` : ''}
      <a href="/download" class="btn btn-secondary">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96zM17 13l-5 5-5-5h3V9h4v4h3z"/></svg>
        Скачать SlimChat (APK)
      </a>
    </div>

    ${isFound ? `
      <div class="hint">
        Если приложение установлено, оно откроется автоматически.<br>
        Если этого не произошло, нажмите «Перейти».
      </div>
    ` : ''}
  </div>

  <div class="brand">
    <span>SlimChat Messenger</span>
  </div>

  ${isFound ? `
  <script>
    (function() {
      var isAndroid = /Android/i.test(navigator.userAgent);
      if (isAndroid) {
        setTimeout(function() {
          window.location.href = ${JSON.stringify(intentUrl)};
        }, 350);
      }
    })();
  </script>
  ` : ''}
</body>
</html>`;
}

// Deep links web landing pages
app.get('/join/:code', (req, res) => {
  const code = req.params.code;
  const chat = db.prepare('SELECT * FROM chats WHERE inviteCode = ?').get(code);
  const fullUrl = `https://jxiwm.btxc.indevs.in/join/${code}`;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(renderChatInvitePage(chat, fullUrl, code, false));
});

app.get('/g/:username', (req, res) => {
  const raw = req.params.username.replace(/^@/, '');
  const chat = db.prepare('SELECT * FROM chats WHERE publicUsername = ? OR inviteCode = ?').get(raw, raw);
  const fullUrl = `https://jxiwm.btxc.indevs.in/g/${raw}`;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(renderChatInvitePage(chat, fullUrl, raw, true));
});

app.get('/i/:code', (req, res) => {
  const code = req.params.code;
  const user = db.prepare('SELECT * FROM users WHERE referralCode = ? OR username = ?').get(code, code);
  const fullUrl = `https://jxiwm.btxc.indevs.in/i/${code}`;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(renderChatInvitePage(null, fullUrl, code, false, user));
});

// ==================== 1-ON-1 CALLS ROUTES ====================

app.get('/calls/check/:userId', (req, res) => {
  const targetUserId = req.params.userId;
  const online = isUserOnline(targetUserId);
  const busy = userCallMap.has(targetUserId);
  const targetUser = db.prepare('SELECT id, username, displayName, avatarUrl FROM users WHERE id = ?').get(targetUserId);
  if (!targetUser) return res.status(404).json({ error: 'User not found' });
  res.json({
    userId: targetUserId,
    online,
    busy,
    user: {
      ...targetUser,
      avatar: targetUser.avatarUrl
    }
  });
});

app.get('/calls/peer-for-chat/:chatId', (req, res) => {
  let token = req.headers['authorization'];
  if (token && token.startsWith('Bearer ')) {
    token = token.slice(7);
  } else if (req.query && req.query.token) {
    token = req.query.token;
  }
  let userId = null;
  if (token) {
    const tokenRow = db.prepare('SELECT userId FROM tokens WHERE token = ? AND type = ?').get(token, 'access');
    if (tokenRow) userId = tokenRow.userId;
  }

  const chatId = req.params.chatId;
  let otherMember = null;
  if (userId) {
    otherMember = db.prepare('SELECT userId FROM chat_members WHERE chatId = ? AND userId != ?').get(chatId, userId);
  }
  if (!otherMember) {
    otherMember = db.prepare('SELECT userId FROM chat_members WHERE chatId = ? LIMIT 1').get(chatId);
  }
  if (!otherMember) return res.status(404).json({ error: 'Chat has no members' });
  const targetUser = db.prepare('SELECT id, username, displayName, avatarUrl FROM users WHERE id = ?').get(otherMember.userId);
  if (!targetUser) return res.status(404).json({ error: 'User not found' });
  res.json({
    peerId: otherMember.userId,
    peerName: targetUser.displayName || targetUser.username || 'Собеседник',
    peerAvatar: targetUser.avatarUrl || ''
  });
});

app.get('/calls/active', authRequired, (req, res) => {
  const activeCallId = userCallMap.get(req.user.id);
  if (!activeCallId) return res.json({ active: false });
  const call = activeCalls.get(activeCallId);
  res.json({ active: true, callId: activeCallId, status: call ? call.status : 'unknown' });
});

app.get('/calls/session/:callId', (req, res) => {
  const callId = req.params.callId;
  const call = activeCalls.get(callId);
  if (!call) return res.status(404).json({ error: 'Call session not found' });
  res.json({
    callId,
    callerId: call.callerId,
    calleeId: call.calleeId,
    status: call.status,
    offerSdp: call.offerSdp || null
  });
});

app.post('/calls/reject/:callId', express.json(), (req, res) => {
  const callId = req.params.callId;
  const call = activeCalls.get(callId);
  if (call) {
    if (call.timeoutTimer) clearTimeout(call.timeoutTimer);
    activeCalls.delete(callId);
    userCallMap.delete(call.callerId);
    userCallMap.delete(call.calleeId);
    const peerId = (call.callerId === (req.body && req.body.userId)) ? call.calleeId : call.callerId;
    sendToUser(peerId, {
      type: 'call:rejected',
      callId,
      fromUserId: (req.body && req.body.userId) || '',
      reason: (req.body && req.body.reason) || 'declined'
    });
  }
  res.json({ success: true });
});

app.post('/calls/end/:callId', express.json(), (req, res) => {
  const callId = req.params.callId;
  const call = activeCalls.get(callId);
  if (call) {
    if (call.timeoutTimer) clearTimeout(call.timeoutTimer);
    activeCalls.delete(callId);
    userCallMap.delete(call.callerId);
    userCallMap.delete(call.calleeId);
    const peerId = (call.callerId === (req.body && req.body.userId)) ? call.calleeId : call.callerId;
    sendToUser(peerId, {
      type: 'call:ended',
      callId,
      fromUserId: (req.body && req.body.userId) || ''
    });
  }
  res.json({ success: true });
});

app.get('/call.html', (req, res) => {
  const callHtmlPath = path.join(__dirname, 'call.html');
  if (fs.existsSync(callHtmlPath)) {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.sendFile(callHtmlPath);
  }
  res.status(404).send('call.html not found');
});

// Browser fallback redirect for /call/chat/:chatId, /call/:userId, /call/:callId
app.get(['/call/chat/:chatId', '/call/user/:userId', '/call/:callId'], (req, res) => {
  const callHtmlPath = path.join(__dirname, 'call.html');
  if (fs.existsSync(callHtmlPath) && req.headers.accept && req.headers.accept.includes('text/html')) {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.sendFile(callHtmlPath);
  }
  const fullUrl = `https://jxiwm.btxc.indevs.in${req.originalUrl}`;
  const cleanHost = fullUrl.replace('https://', '').replace('http://', '');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SlimChat Звонок</title>
  <style>
    body { background: #222224; color: #fff; font-family: sans-serif; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0; text-align: center; padding: 20px; box-sizing: border-box; }
    .btn { display: inline-block; margin-top: 24px; padding: 14px 28px; background: #22c55e; color: #fff; text-decoration: none; border-radius: 30px; font-weight: bold; font-size: 16px; box-shadow: 0 4px 15px rgba(34,197,94,0.4); }
  </style>
  <script>
    window.location.href = "intent://${cleanHost}#Intent;scheme=https;package=com.example.slimchatyou;end";
  </script>
</head>
<body>
  <div style="font-size: 48px; margin-bottom: 12px;">📞</div>
  <h2 style="margin: 0 0 8px 0;">Аудиозвонок SlimChat</h2>
  <p style="color: #94a3b8; margin: 0;">Переход в приложение SlimChat...</p>
  <a class="btn" href="${fullUrl}">Открыть в SlimChat</a>
</body>
</html>`);
});

// ==================== WEB FRONTEND & EXTENDED APIS ====================

// QR Authentication endpoints for Web Client
app.post('/auth/qr/start', (req, res) => {
  const token = crypto.randomUUID();
  try {
    db.prepare(`
      INSERT INTO qr_logins (token, status, browser, ip, createdAt)
      VALUES (?, 'pending', 'Web Browser', ?, datetime('now'))
    `).run(token, req.ip || '127.0.0.1');
  } catch (_) {}
  res.json({ token, expiresIn: 120 });
});

app.post('/auth/qr/wait', (req, res) => {
  const { token, platform } = req.body;
  if (!token) return res.status(400).json({ error: 'Token required' });
  const qr = db.prepare('SELECT * FROM qr_logins WHERE token = ?').get(token);
  if (!qr) return res.json({ status: 'expired' });

  const createdTime = new Date(qr.createdAt).getTime();
  if (Date.now() - createdTime > 120000) {
    return res.json({ status: 'expired' });
  }

  if (qr.status === 'approved' && qr.userId) {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(qr.userId);
    if (!user) return res.json({ status: 'expired' });
    const now = new Date().toISOString();
    const accessToken = crypto.randomBytes(32).toString('hex');
    const refreshToken = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO tokens (token, userId, type, createdAt) VALUES (?, ?, ?, ?)').run(accessToken, user.id, 'access', now);
    db.prepare('INSERT INTO tokens (token, userId, type, createdAt) VALUES (?, ?, ?, ?)').run(refreshToken, user.id, 'refresh', now);
    return res.json({
      status: 'approved',
      accessToken,
      refreshToken,
      user: formatUser(user, user.id)
    });
  }

  res.json({ status: 'pending' });
});

// Email Change endpoints
app.post('/auth/email/change/request-code', authRequired, (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Укажите корректный email' });
  }
  const existing = db.prepare('SELECT id FROM users WHERE LOWER(email) = ? AND id != ?').get(email, req.user.id);
  if (existing) {
    return res.status(400).json({ error: 'Этот email уже используется другим аккаунтом' });
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
  db.prepare(`
    INSERT INTO auth_codes (email, code, expiresAt, type)
    VALUES (?, ?, ?, 'email_change')
  `).run(email, code, expiresAt);

  console.log(`[Email Change] Code for ${email}: ${code}`);
  sendVerificationEmail(email, code).catch(e => console.error('[Mailer] Error:', e));
  res.json({ success: true });
});

app.post('/auth/email/change/confirm-code', authRequired, (req, res) => {
  const { email, code } = req.body;
  const cleanEmail = (email || '').trim().toLowerCase();
  const cleanCode = (code || '').trim();

  const codeRow = db.prepare(`
    SELECT * FROM auth_codes
    WHERE LOWER(email) = ? AND code = ? AND type = 'email_change' AND expiresAt > datetime('now')
    ORDER BY id DESC LIMIT 1
  `).get(cleanEmail, cleanCode);

  if (!codeRow) {
    return res.status(400).json({ error: 'Неверный или просроченный код' });
  }

  db.prepare('UPDATE users SET email = ? WHERE id = ?').run(cleanEmail, req.user.id);
  db.prepare('DELETE FROM auth_codes WHERE LOWER(email) = ?').run(cleanEmail);
  res.json({ success: true });
});

// Client system endpoints
app.get('/maintenance', (req, res) => {
  res.json({ enabled: false });
});

app.post('/auth/lock', (req, res) => {
  res.json({ success: true });
});

app.post('/auth/switch', authRequired, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({
    user: formatUser(user, user.id)
  });
});

app.get('/push/key', (req, res) => {
  res.json({ publicKey: null });
});

app.post('/push/subscribe', (req, res) => {
  res.json({ success: true });
});

// Static APK downloads
app.get(['/app.apk', '/you/app.apk', '/slimchat_14_81.apk', '/slimchat_13_86.apk', '/slimchat_13_75.apk'], (req, res) => {
  const apkPath = path.join(__dirname, 'app.apk');
  if (fs.existsSync(apkPath)) {
    return res.download(apkPath, 'app.apk');
  }
  res.status(404).json({ error: 'APK file not found' });
});

// Web Frontend Static Hosting
const PUBLIC_DIR = path.join(__dirname, 'public');
if (fs.existsSync(PUBLIC_DIR)) {
  app.use('/app', express.static(path.join(PUBLIC_DIR, 'app')));
  app.use('/you', express.static(path.join(PUBLIC_DIR, 'you')));
  app.use(express.static(PUBLIC_DIR));

  app.get(/^\/app(\/.*)?$/, (req, res, next) => {
    if (req.path.includes('.')) return next();
    res.sendFile(path.join(PUBLIC_DIR, 'app', 'index.html'));
  });

  app.get(/^\/you(\/.*)?$/, (req, res, next) => {
    if (req.path.includes('.')) return next();
    res.sendFile(path.join(PUBLIC_DIR, 'you', 'home', 'index.html'));
  });

  app.get('/', (req, res) => {
    res.redirect('/app/');
  });
}



// Ensure necessary database tables and columns exist for new features
function initNewFeaturesDb() {
  try {
    db.prepare('CREATE TABLE IF NOT EXISTS user_invites (id TEXT PRIMARY KEY, userId TEXT, code TEXT UNIQUE, createdAt TEXT)').run();
    db.prepare('CREATE TABLE IF NOT EXISTS spam_reports (id TEXT PRIMARY KEY, chatId TEXT, reporterId TEXT, createdAt TEXT)').run();
    db.prepare('CREATE TABLE IF NOT EXISTS hidden_spam_bars (userId TEXT, chatId TEXT, PRIMARY KEY(userId, chatId))').run();
    db.prepare('CREATE TABLE IF NOT EXISTS user_pin_orders (userId TEXT PRIMARY KEY, chatIds TEXT)').run();
    db.prepare('CREATE TABLE IF NOT EXISTS chat_mentions_read (chatId TEXT, userId TEXT, lastReadSeq INTEGER, PRIMARY KEY(chatId, userId))').run();
    db.prepare('CREATE TABLE IF NOT EXISTS feed_reports (id TEXT PRIMARY KEY, chatId TEXT, messageId TEXT, userId TEXT, createdAt TEXT)').run();
    db.prepare('CREATE TABLE IF NOT EXISTS user_sticker_packs (userId TEXT, packId TEXT, PRIMARY KEY(userId, packId))').run();
    db.prepare('CREATE TABLE IF NOT EXISTS user_sticker_prefs (userId TEXT PRIMARY KEY, recent TEXT, favorite TEXT)').run();
    db.prepare('CREATE TABLE IF NOT EXISTS localizations (id TEXT PRIMARY KEY, name TEXT, baseLang TEXT, overrides TEXT, authorId TEXT, createdAt TEXT)').run();
    try { db.prepare('ALTER TABLE chats ADD COLUMN inFeed INTEGER DEFAULT 0').run(); } catch (_) {}
    try { db.prepare('ALTER TABLE chats ADD COLUMN topics TEXT').run(); } catch (_) {}
    try { db.prepare('ALTER TABLE chats ADD COLUMN discussionId TEXT').run(); } catch (_) {}
    try { db.prepare('ALTER TABLE sticker_packs ADD COLUMN archived INTEGER DEFAULT 0').run(); } catch (_) {}
    try { db.prepare('ALTER TABLE messages ADD COLUMN forwardedFrom TEXT').run(); } catch (_) {}
  } catch (err) {
    console.error('[DB Init] Error ensuring new schema tables/columns:', err);
  }
}
initNewFeaturesDb();

// --- Auth & Invites ---
app.post('/auth/invites', authRequired, (req, res) => {
  const code = crypto.randomBytes(4).toString('hex');
  try {
    db.prepare('INSERT OR REPLACE INTO user_invites (id, userId, code, createdAt) VALUES (?, ?, ?, datetime("now"))')
      .run(crypto.randomUUID(), req.user.id, code);
  } catch (_) {}
  res.json({ code });
});

// --- Chat Actions: Invite, Spam Bar, Discussion, Feed, Topics, Pin Order ---
app.delete('/chats/:id/invite', authRequired, (req, res) => {
  const chat = db.prepare('SELECT * FROM chats WHERE id = ?').get(req.params.id);
  if (!chat) return res.status(404).json({ error: 'Чат не найден' });
  const cm = getChatMember(req.params.id, req.user.id);
  if (!cm || (cm.role !== 'owner' && cm.role !== 'admin')) {
    return res.status(403).json({ error: 'Нет прав' });
  }
  const newCode = crypto.randomBytes(6).toString('hex');
  db.prepare('UPDATE chats SET inviteCode = ? WHERE id = ?').run(newCode, req.params.id);
  res.json({ status: 'ok', inviteCode: newCode });
});

app.post('/chats/:id/report-spam', authRequired, (req, res) => {
  const { leave } = req.body;
  try {
    db.prepare('INSERT INTO spam_reports (id, chatId, reporterId, createdAt) VALUES (?, ?, ?, datetime("now"))')
      .run(crypto.randomUUID(), req.params.id, req.user.id);
  } catch (_) {}
  if (leave) {
    db.prepare('DELETE FROM chat_members WHERE chatId = ? AND userId = ?').run(req.params.id, req.user.id);
    broadcastToChat(req.params.id, {
      type: 'member-left',
      payload: { chatId: req.params.id, userId: req.user.id }
    });
  }
  res.json({ status: 'ok' });
});

app.post('/chats/:id/spam-bar/hide', authRequired, (req, res) => {
  try {
    db.prepare('INSERT OR REPLACE INTO hidden_spam_bars (userId, chatId) VALUES (?, ?)').run(req.user.id, req.params.id);
  } catch (_) {}
  res.json({ status: 'ok' });
});

app.post('/chats/:id/discussion', authRequired, (req, res) => {
  const channel = db.prepare('SELECT * FROM chats WHERE id = ?').get(req.params.id);
  if (!channel) return res.status(404).json({ error: 'Канал не найден' });
  const cm = getChatMember(req.params.id, req.user.id);
  if (!cm || (cm.role !== 'owner' && cm.role !== 'admin')) {
    return res.status(403).json({ error: 'Нет прав' });
  }
  const discussionId = 'chat_' + Date.now() + '_' + crypto.randomBytes(3).toString('hex');
  const title = (channel.name || 'Обсуждение') + ' (Чат)';
  db.prepare(`
    INSERT INTO chats (id, name, type, isPublic, inviteCode, ownerId, createdAt, description)
    VALUES (?, ?, 'group', 0, ?, ?, datetime('now'), ?)
  `).run(discussionId, title, crypto.randomBytes(6).toString('hex'), req.user.id, 'Группа для комментариев канала');
  db.prepare(`
    INSERT INTO chat_members (chatId, userId, role, joinedAt)
    VALUES (?, ?, 'owner', datetime('now'))
  `).run(discussionId, req.user.id);
  db.prepare('UPDATE chats SET discussionId = ? WHERE id = ?').run(discussionId, req.params.id);
  const newChat = db.prepare('SELECT * FROM chats WHERE id = ?').get(discussionId);
  res.json({ status: 'ok', discussionId, chat: formatChat(newChat, req.user.id) });
});

app.patch('/chats/:id/discussion', authRequired, (req, res) => {
  const { groupChatId } = req.body;
  const cm = getChatMember(req.params.id, req.user.id);
  if (!cm || (cm.role !== 'owner' && cm.role !== 'admin')) {
    return res.status(403).json({ error: 'Нет прав' });
  }
  db.prepare('UPDATE chats SET discussionId = ? WHERE id = ?').run(groupChatId || null, req.params.id);
  res.json({ status: 'ok', discussionId: groupChatId || null });
});

app.put('/chats/:id/feed', authRequired, (req, res) => {
  const cm = getChatMember(req.params.id, req.user.id);
  if (!cm || (cm.role !== 'owner' && cm.role !== 'admin')) {
    return res.status(403).json({ error: 'Нет прав' });
  }
  const inFeed = req.body.inFeed ? 1 : 0;
  db.prepare('UPDATE chats SET inFeed = ? WHERE id = ?').run(inFeed, req.params.id);
  res.json({ status: 'ok', inFeed: Boolean(inFeed) });
});

app.put('/chats/:id/topics', authRequired, (req, res) => {
  const { topics } = req.body;
  db.prepare('UPDATE chats SET topics = ? WHERE id = ?').run(JSON.stringify(topics || []), req.params.id);
  res.json({ status: 'ok', topics: topics || [] });
});

app.put('/chats/pin-order', authRequired, (req, res) => {
  const { chatIds } = req.body;
  try {
    db.prepare('INSERT OR REPLACE INTO user_pin_orders (userId, chatIds) VALUES (?, ?)').run(req.user.id, JSON.stringify(chatIds || []));
  } catch (_) {}
  res.json({ status: 'ok', chatIds: chatIds || [] });
});

// --- Forwarding & Stickers ---
app.post('/chats/:id/forward', authRequired, (req, res) => {
  const targetChatId = req.params.id;
  const cm = getChatMember(targetChatId, req.user.id);
  if (!cm) return res.status(403).json({ error: 'Вы не участник чата' });

  const { fromChatId, messageIds } = req.body;
  if (!messageIds || !Array.isArray(messageIds) || messageIds.length === 0) {
    return res.status(400).json({ error: 'Нет сообщений для пересылки' });
  }

  const fromChat = db.prepare('SELECT * FROM chats WHERE id = ?').get(fromChatId);
  const fromChatName = fromChat ? fromChat.name : 'Чат';

  const placeholders = messageIds.map(() => '?').join(',');
  const sourceMessages = db.prepare(`SELECT * FROM messages WHERE id IN (${placeholders}) ORDER BY seq ASC`).all(...messageIds);

  const forwardedList = [];
  for (const src of sourceMessages) {
    const newMsgId = 'msg_' + Date.now() + '_' + crypto.randomBytes(3).toString('hex');
    const seqRow = db.prepare('SELECT MAX(seq) as maxSeq FROM messages WHERE chatId = ?').get(targetChatId);
    const newSeq = (seqRow && seqRow.maxSeq ? seqRow.maxSeq : 0) + 1;
    const fwdMeta = JSON.stringify({
      name: fromChatName,
      chatId: fromChatId,
    });

    db.prepare(`
      INSERT INTO messages (id, chatId, senderId, body, createdAt, seq, attachments, forwardedFrom)
      VALUES (?, ?, ?, ?, datetime('now'), ?, ?, ?)
    `).run(newMsgId, targetChatId, req.user.id, src.body || '', newSeq, src.attachments || '[]', fwdMeta);

    const inserted = db.prepare('SELECT * FROM messages WHERE id = ?').get(newMsgId);
    const formatted = formatMessage(inserted, req.user.id);
    forwardedList.push(formatted);

    broadcastToChat(targetChatId, {
      type: 'message',
      payload: {
        chatId: targetChatId,
        ...formatted
      }
    });
  }

  res.json({ status: 'ok', messages: forwardedList });
});

app.post('/chats/:id/stickers', authRequired, (req, res) => {
  const chatId = req.params.id;
  const cm = getChatMember(chatId, req.user.id);
  if (!cm) return res.status(403).json({ error: 'Вы не участник чата' });

  const { storageKey, replyToId, clientMessageId } = req.body;
  if (!storageKey) return res.status(400).json({ error: 'Отсутствует storageKey' });

  const msgId = clientMessageId || ('msg_' + Date.now() + '_' + crypto.randomBytes(3).toString('hex'));
  const seqRow = db.prepare('SELECT MAX(seq) as maxSeq FROM messages WHERE chatId = ?').get(chatId);
  const newSeq = (seqRow && seqRow.maxSeq ? seqRow.maxSeq : 0) + 1;

  const attachments = JSON.stringify([
    {
      kind: 'image',
      storageKey,
      meta: { isSticker: true }
    }
  ]);

  db.prepare(`
    INSERT INTO messages (id, chatId, senderId, body, createdAt, seq, attachments, replyToId)
    VALUES (?, ?, ?, ?, datetime('now'), ?, ?, ?)
  `).run(msgId, chatId, req.user.id, '', newSeq, attachments, replyToId || null);

  const inserted = db.prepare('SELECT * FROM messages WHERE id = ?').get(msgId);
  const formatted = formatMessage(inserted, req.user.id);

  broadcastToChat(chatId, {
    type: 'message',
    payload: {
      chatId,
      ...formatted
    }
  });

  res.json({ status: 'ok', message: formatted });
});

// --- Voice Recognition ---
app.post('/chats/:id/messages/:msgId/recognize', authRequired, (req, res) => {
  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.msgId);
  if (!msg) return res.status(404).json({ error: 'Сообщение не найдено' });

  let text = 'Голосовое сообщение распознано';
  try {
    const atts = JSON.parse(msg.attachments || '[]');
    const audio = atts.find(a => a.kind === 'audio');
    if (audio && audio.meta && audio.meta.recognized) {
      text = audio.meta.recognized;
    } else if (audio) {
      if (!audio.meta) audio.meta = {};
      audio.meta.recognized = text;
      db.prepare('UPDATE messages SET attachments = ? WHERE id = ?').run(JSON.stringify(atts), req.params.msgId);
    }
  } catch (_) {}

  res.json({ text });
});

// --- Mentions & Commands ---
app.get('/chats/:id/mentions', authRequired, (req, res) => {
  const user = req.user;
  const username = user.username ? ('@' + user.username) : null;
  const rows = db.prepare(`
    SELECT id FROM messages
    WHERE chatId = ? AND (body LIKE ? OR body LIKE '%@all%' OR body LIKE '%@everyone%')
    ORDER BY seq DESC LIMIT 50
  `).all(req.params.id, username ? ('%' + username + '%') : '%@never%');
  res.json({ mentions: rows.map(r => r.id) });
});

app.post('/chats/:id/mentions/read', authRequired, (req, res) => {
  const chatId = req.params.id;
  try {
    db.prepare('INSERT OR REPLACE INTO chat_mentions_read (chatId, userId, lastReadSeq) VALUES (?, ?, (SELECT COALESCE(MAX(seq), 0) FROM messages WHERE chatId = ?))')
      .run(chatId, req.user.id, chatId);
  } catch (_) {}
  broadcastMentionsRead(chatId, req.user.id, 0);
  res.json({ status: 'ok', unreadMentions: 0 });
});

app.get('/chats/:id/commands', authRequired, (req, res) => {
  res.json({
    commands: [
      { name: 'help', description: 'Показать справку', usage: '/help' },
      { name: 'info', description: 'Информация о чате', usage: '/info' },
      { name: 'shrug', description: '¯\\_(ツ)_/¯', usage: '/shrug' },
      { name: 'tableflip', description: '(╯°□°)╯︵ ┻━┻', usage: '/tableflip' },
    ]
  });
});

app.post('/chats/:id/commands/run', authRequired, (req, res) => {
  const { text } = req.body;
  const cmd = (text || '').trim();
  let responseText = 'Команда выполнена';
  if (cmd === '/help') responseText = 'Доступные команды: /help, /info, /shrug, /tableflip';
  else if (cmd === '/shrug') responseText = '¯\\_(ツ)_/¯';
  else if (cmd === '/tableflip') responseText = '(╯°□°)╯︵ ┻━┻';
  else if (cmd === '/info') {
    const chat = db.prepare('SELECT * FROM chats WHERE id = ?').get(req.params.id);
    responseText = chat ? ('Чат: ' + chat.name + ' (' + chat.type + ')') : 'Информация недоступна';
  }
  res.json({ text: responseText });
});

// --- Public Feed & Recommendations ---
app.get(['/feed', '/feed/recommended'], optionalAuth, (req, res) => {
  const channels = db.prepare(`
    SELECT * FROM chats WHERE type = 'channel' AND (isPublic = 1 OR inFeed = 1) LIMIT 20
  `).all();

  const channelMap = channels.map(c => ({
    id: c.id,
    title: c.name,
    avatarUrl: c.avatarUrl || null,
    username: c.username || null,
    verified: c.verified === 1,
    supporter: c.supporter === 1,
    discussionId: c.discussionId || null,
    reactionsEnabled: c.reactionsEnabled !== 0,
    members: (db.prepare('SELECT COUNT(*) as count FROM chat_members WHERE chatId = ?').get(c.id) || {}).count || 0,
    reason: null,
  }));

  const channelIds = channels.map(c => c.id);
  let posts = [];
  if (channelIds.length > 0) {
    const placeholders = channelIds.map(() => '?').join(',');
    const recentMsgs = db.prepare(`
      SELECT * FROM messages WHERE chatId IN (${placeholders}) ORDER BY createdAt DESC LIMIT 40
    `).all(...channelIds);
    posts = recentMsgs.map(m => formatMessage(m, req.user ? req.user.id : null));
  }

  res.json({
    channels: channelMap,
    posts,
  });
});

app.post('/feed/dismiss', authRequired, (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/feed/report', authRequired, (req, res) => {
  const { chatId, messageId } = req.body;
  try {
    db.prepare('INSERT INTO feed_reports (id, chatId, messageId, userId, createdAt) VALUES (?, ?, ?, ?, datetime("now"))')
      .run(crypto.randomUUID(), chatId, messageId, req.user.id);
  } catch (_) {}
  res.json({ status: 'ok' });
});

// --- Sticker Packs & Preferences Extended ---
app.get('/sticker-packs/archived', authRequired, (req, res) => {
  const rows = db.prepare('SELECT * FROM sticker_packs WHERE archived = 1').all();
  res.json(rows.map(r => ({
    id: r.id,
    name: r.name,
    avatarUrl: r.avatarUrl,
    items: JSON.parse(r.items || '[]'),
    archived: true,
  })));
});

app.put('/sticker-packs/order', authRequired, (req, res) => {
  res.json({ status: 'ok', packIds: req.body.packIds || [] });
});

app.patch('/sticker-packs/:id', authRequired, (req, res) => {
  const { name } = req.body;
  if (name) {
    db.prepare('UPDATE sticker_packs SET name = ? WHERE id = ? AND userId = ?').run(name, req.params.id, req.user.id);
  }
  const pack = db.prepare('SELECT * FROM sticker_packs WHERE id = ?').get(req.params.id);
  res.json({ status: 'ok', pack });
});

app.delete('/sticker-packs/:id/items/:itemId', authRequired, (req, res) => {
  const pack = db.prepare('SELECT * FROM sticker_packs WHERE id = ? AND userId = ?').get(req.params.id, req.user.id);
  if (!pack) return res.status(404).json({ error: 'Пакет не найден' });
  let items = JSON.parse(pack.items || '[]');
  items = items.filter(it => it.id !== req.params.itemId && it.storageKey !== req.params.itemId);
  db.prepare('UPDATE sticker_packs SET items = ? WHERE id = ?').run(JSON.stringify(items), req.params.id);
  res.json({ status: 'ok', items });
});

app.post('/sticker-packs/:id/items/copy', authRequired, (req, res) => {
  res.json({ status: 'ok' });
});

app.put('/sticker-packs/:id/items/order', authRequired, (req, res) => {
  const { itemIds } = req.body;
  const pack = db.prepare('SELECT * FROM sticker_packs WHERE id = ? AND userId = ?').get(req.params.id, req.user.id);
  if (pack && itemIds) {
    let items = JSON.parse(pack.items || '[]');
    items.sort((a, b) => itemIds.indexOf(a.id) - itemIds.indexOf(b.id));
    db.prepare('UPDATE sticker_packs SET items = ? WHERE id = ?').run(JSON.stringify(items), req.params.id);
  }
  res.json({ status: 'ok' });
});

app.post('/sticker-packs/:id/cover', authRequired, (req, res) => {
  const { itemId } = req.body;
  const pack = db.prepare('SELECT * FROM sticker_packs WHERE id = ? AND userId = ?').get(req.params.id, req.user.id);
  if (pack) {
    const items = JSON.parse(pack.items || '[]');
    const it = items.find(i => i.id === itemId);
    if (it) {
      db.prepare('UPDATE sticker_packs SET avatarUrl = ? WHERE id = ?').run(it.storageKey || it.url, req.params.id);
    }
  }
  res.json({ status: 'ok' });
});

app.post('/sticker-packs/:id/archive', authRequired, (req, res) => {
  const archived = req.body.archived ? 1 : 0;
  db.prepare('UPDATE sticker_packs SET archived = ? WHERE id = ? AND userId = ?').run(archived, req.params.id, req.user.id);
  res.json({ status: 'ok', archived: Boolean(archived) });
});

app.post('/sticker-packs/:id/add', authRequired, (req, res) => {
  try {
    db.prepare('INSERT OR REPLACE INTO user_sticker_packs (userId, packId) VALUES (?, ?)').run(req.user.id, req.params.id);
  } catch (_) {}
  res.json({ status: 'ok' });
});

app.delete('/sticker-packs/:id/add', authRequired, (req, res) => {
  try {
    db.prepare('DELETE FROM user_sticker_packs WHERE userId = ? AND packId = ?').run(req.user.id, req.params.id);
  } catch (_) {}
  res.json({ status: 'ok' });
});

app.get('/sticker-packs/link/:code', optionalAuth, (req, res) => {
  const pack = db.prepare('SELECT * FROM sticker_packs WHERE id = ? OR name = ?').get(req.params.code, req.params.code);
  if (!pack) return res.status(404).json({ error: 'Стикерпак не найден' });
  res.json({
    id: pack.id,
    name: pack.name,
    avatarUrl: pack.avatarUrl,
    items: JSON.parse(pack.items || '[]'),
  });
});

app.get('/sticker-packs/:id', optionalAuth, (req, res) => {
  const pack = db.prepare('SELECT * FROM sticker_packs WHERE id = ?').get(req.params.id);
  if (!pack) return res.status(404).json({ error: 'Стикерпак не найден' });
  res.json({
    id: pack.id,
    name: pack.name,
    avatarUrl: pack.avatarUrl,
    items: JSON.parse(pack.items || '[]'),
  });
});

app.get('/sticker-prefs', authRequired, (req, res) => {
  let prefs = { recent: [], favorite: [] };
  try {
    const row = db.prepare('SELECT * FROM user_sticker_prefs WHERE userId = ?').get(req.user.id);
    if (row) {
      prefs.recent = JSON.parse(row.recent || '[]');
      prefs.favorite = JSON.parse(row.favorite || '[]');
    }
  } catch (_) {}
  res.json(prefs);
});

app.put('/sticker-prefs', authRequired, (req, res) => {
  const { recent, favorite } = req.body;
  try {
    db.prepare('INSERT OR REPLACE INTO user_sticker_prefs (userId, recent, favorite) VALUES (?, ?, ?)')
      .run(req.user.id, JSON.stringify(recent || []), JSON.stringify(favorite || []));
  } catch (_) {}
  res.json({ status: 'ok' });
});

// --- Localization (l10n) ---
app.get('/l10n/localizations', optionalAuth, (req, res) => {
  try {
    const rows = db.prepare('SELECT id, name, baseLang, authorId, createdAt FROM localizations ORDER BY createdAt DESC LIMIT 50').all();
    res.json(rows);
  } catch (_) {
    res.json([]);
  }
});

app.get('/l10n/localizations/mine', authRequired, (req, res) => {
  try {
    const rows = db.prepare('SELECT * FROM localizations WHERE authorId = ?').all();
    res.json({ items: rows.map(r => ({ ...r, overrides: JSON.parse(r.overrides || '{}') })) });
  } catch (_) {
    res.json({ items: [] });
  }
});

app.post('/l10n/localizations', authRequired, (req, res) => {
  const { name, baseLang, overrides } = req.body;
  const id = 'l10n_' + Date.now() + '_' + crypto.randomBytes(3).toString('hex');
  try {
    db.prepare('INSERT INTO localizations (id, name, baseLang, overrides, authorId, createdAt) VALUES (?, ?, ?, ?, ?, datetime("now"))')
      .run(id, name || 'Custom Localization', baseLang || 'ru', JSON.stringify(overrides || {}), req.user.id);
  } catch (_) {}
  res.json({ id, name, baseLang, overrides: overrides || {} });
});

app.get('/l10n/localizations/:id', optionalAuth, (req, res) => {
  try {
    const row = db.prepare('SELECT * FROM localizations WHERE id = ?').get(req.params.id);
    if (!row) return res.status(404).json({ error: 'Локализация не найдена' });
    res.json({ ...row, overrides: JSON.parse(row.overrides || '{}') });
  } catch (_) {
    res.status(404).json({ error: 'Локализация не найдена' });
  }
});

app.delete('/l10n/localizations/:id', authRequired, (req, res) => {
  try {
    db.prepare('DELETE FROM localizations WHERE id = ? AND authorId = ?').run(req.params.id, req.user.id);
  } catch (_) {}
  res.json({ status: 'ok' });
});

app.put('/l10n/localizations/:id', authRequired, (req, res) => {
  const { name, baseLang, overrides } = req.body;
  try {
    db.prepare('UPDATE localizations SET name = COALESCE(?, name), baseLang = COALESCE(?, baseLang), overrides = COALESCE(?, overrides) WHERE id = ? AND authorId = ?')
      .run(name || null, baseLang || null, overrides ? JSON.stringify(overrides) : null, req.params.id, req.user.id);
  } catch (_) {}
  res.json({ status: 'ok' });
});

app.post('/l10n/localizations/batch', optionalAuth, (req, res) => {
  const { oids } = req.body;
  if (!oids || !Array.isArray(oids) || oids.length === 0) {
    return res.json({ localizations: [] });
  }
  try {
    const placeholders = oids.map(() => '?').join(',');
    const rows = db.prepare(`SELECT * FROM localizations WHERE id IN (${placeholders})`).all(...oids);
    res.json({ localizations: rows.map(r => ({ ...r, overrides: JSON.parse(r.overrides || '{}') })) });
  } catch (_) {
    res.json({ localizations: [] });
  }
});

app.get('/l10n/pack/:lang', (req, res) => {
  const lang = req.params.lang || 'ru';
  let dict = {};
  try {
    const keysPath = path.join(__dirname, 'jadx_out', 'resources', 'assets', 'lang', 'keys.json');
    if (fs.existsSync(keysPath)) {
      const parsed = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
      if (Array.isArray(parsed)) {
        for (const cat of parsed) {
          if (Array.isArray(cat.keys)) {
            for (const k of cat.keys) dict[k] = k;
          }
        }
      }
    }
  } catch (_) {}
  res.json(dict);
});

app.post('/l10n/translate', (req, res) => {
  const { texts } = req.body;
  const translations = Array.isArray(texts) ? texts : [];
  res.json({ translations });
});


// Fallback 404
app.use((req, res) => {
  console.log(`[404 NOT FOUND] ${req.method} ${req.originalUrl}`);
  res.status(404).json({ error: `Path ${req.originalUrl} not found` });
});

// ==================== HTTP & WEBSOCKET SERVER ====================

const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (request, socket, head) => {
  const urlObj = new URL(request.url, `http://${request.headers.host}`);
  if (urlObj.pathname === '/ws') {
    const token = urlObj.searchParams.get('token');
    if (!token) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }
    const tokenRow = db.prepare('SELECT userId FROM tokens WHERE token = ? AND type = ?').get(token, 'access');
    if (!tokenRow) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }
    const userId = tokenRow.userId;
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request, userId);
    });
  } else {
    socket.destroy();
  }
});

wss.on('connection', (ws, req, userId) => {
  console.log(`[WS] User ${userId} connected.`);
  addClient(userId, ws);

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data.toString());
      console.log(`[WS] From ${userId}:`, msg);

      if (msg.type === 'presence') {
        broadcastPresence(userId, msg.active !== false);
      } else if (msg.type === 'typing') {
        const { chatId, kind } = msg;
        if (chatId) {
          const cm = getChatMember(chatId, userId);
          if (cm) {
            broadcastToChat(chatId, {
              type: 'typing',
              payload: { chatId, userId, kind: kind || 'text' },
            }, userId);
          }
        }
      } else if (msg.type === 'read') {
        const { chatId, seq } = msg;
        if (chatId) {
          const cm = getChatMember(chatId, userId);
          if (cm) {
            db.prepare('UPDATE chat_members SET lastReadSeq = ? WHERE chatId = ? AND userId = ?')
              .run(seq || 0, chatId, userId);
            broadcastToChat(chatId, {
              type: 'read',
              payload: { chatId, userId, seq },
            }, userId);
          }
        }
      } else if (msg.type === 'call:offer' || msg.type === 'call_offer') {
        const { toUserId, sdp, callerName, callerAvatar, callId: reqCallId } = msg;
        const callId = reqCallId || `call_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;

        if (!toUserId) {
          return ws.send(JSON.stringify({ type: 'call:error', error: 'Missing toUserId' }));
        }

        if (!isUserOnline(toUserId)) {
          console.log(`[Call] ${userId} calling ${toUserId}, but callee is offline`);
          return ws.send(JSON.stringify({ type: 'call:unavailable', callId, toUserId, reason: 'offline' }));
        }

        if (userCallMap.has(toUserId) || userCallMap.has(userId)) {
          console.log(`[Call] Busy: ${toUserId} or ${userId} already in call`);
          return ws.send(JSON.stringify({ type: 'call:busy', callId, toUserId }));
        }

        const timeoutTimer = setTimeout(() => {
          const call = activeCalls.get(callId);
          if (call && call.status === 'ringing') {
            console.log(`[Call] Call ${callId} timed out`);
            activeCalls.delete(callId);
            userCallMap.delete(userId);
            userCallMap.delete(toUserId);
            sendToUser(userId, { type: 'call:timeout', callId, toUserId });
            sendToUser(toUserId, { type: 'call:timeout', callId, fromUserId: userId });
          }
        }, 45000);

        activeCalls.set(callId, {
          callerId: userId,
          calleeId: toUserId,
          offerSdp: sdp,
          status: 'ringing',
          timeoutTimer,
          createdAt: Date.now()
        });
        userCallMap.set(userId, callId);
        userCallMap.set(toUserId, callId);

        console.log(`[Call] Call ${callId} initiated by ${userId} to ${toUserId}`);
        ws.send(JSON.stringify({ type: 'call:ringing', callId, toUserId }));

        sendToUser(toUserId, {
          type: 'call:incoming',
          callId,
          fromUserId: userId,
          callerName: callerName || 'Пользователь',
          callerAvatar: callerAvatar || '',
          sdp
        });
      } else if (msg.type === 'call:answer' || msg.type === 'call_answer') {
        const { callId, sdp } = msg;
        const call = activeCalls.get(callId);
        if (call && call.calleeId === userId) {
          if (call.timeoutTimer) clearTimeout(call.timeoutTimer);
          call.status = 'connected';
          call.connectedAt = Date.now();
          console.log(`[Call] Call ${callId} answered by ${userId}`);
          sendToUser(call.callerId, {
            type: 'call:accepted',
            callId,
            fromUserId: userId,
            sdp
          });
        }
      } else if (msg.type === 'call:ice' || msg.type === 'call_ice') {
        const { callId, toUserId, candidate } = msg;
        if (toUserId && candidate) {
          sendToUser(toUserId, {
            type: 'call:ice',
            callId,
            fromUserId: userId,
            candidate
          });
        }
      } else if (msg.type === 'call:reject' || msg.type === 'call_reject') {
        const { callId, reason } = msg;
        const call = activeCalls.get(callId);
        if (call) {
          if (call.timeoutTimer) clearTimeout(call.timeoutTimer);
          activeCalls.delete(callId);
          userCallMap.delete(call.callerId);
          userCallMap.delete(call.calleeId);
          const peerId = (call.callerId === userId) ? call.calleeId : call.callerId;
          console.log(`[Call] Call ${callId} rejected by ${userId}`);
          sendToUser(peerId, {
            type: 'call:rejected',
            callId,
            fromUserId: userId,
            reason: reason || 'declined'
          });
        }
      } else if (msg.type === 'call:end' || msg.type === 'call_end') {
        const currentCallId = msg.callId || userCallMap.get(userId);
        const call = activeCalls.get(currentCallId);
        if (call) {
          if (call.timeoutTimer) clearTimeout(call.timeoutTimer);
          activeCalls.delete(currentCallId);
          userCallMap.delete(call.callerId);
          userCallMap.delete(call.calleeId);
          const peerId = (call.callerId === userId) ? call.calleeId : call.callerId;
          console.log(`[Call] Call ${currentCallId} ended by ${userId}`);
          sendToUser(peerId, {
            type: 'call:ended',
            callId: currentCallId,
            fromUserId: userId
          });
        }
      }
    } catch (e) {
      console.error('[WS] Error processing frame:', e.message);
    }
  });

  ws.on('close', () => {
    console.log(`[WS] User ${userId} disconnected.`);
    const activeCallId = userCallMap.get(userId);
    if (activeCallId) {
      const call = activeCalls.get(activeCallId);
      if (call) {
        if (call.timeoutTimer) clearTimeout(call.timeoutTimer);
        activeCalls.delete(activeCallId);
        userCallMap.delete(call.callerId);
        userCallMap.delete(call.calleeId);
        const peerId = (call.callerId === userId) ? call.calleeId : call.callerId;
        console.log(`[Call] User ${userId} disconnected during call ${activeCallId}`);
        sendToUser(peerId, {
          type: 'call:ended',
          callId: activeCallId,
          fromUserId: userId,
          reason: 'disconnected'
        });
      }
    }
    removeClient(userId, ws);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`=======================================================`);
  console.log(` SlimChat Backend Server running on port ${PORT}`);
  console.log(` HTTP API:   http://0.0.0.0:${PORT}`);
  console.log(` WebSocket:  ws://0.0.0.0:${PORT}/ws?token=...`);
  console.log(` Uploads:    http://0.0.0.0:${PORT}/uploads/`);
  console.log(`=======================================================`);
});


// =============================================================================
// NEW & UPDATED ENDPOINTS ALIGNED WITH SLIMCHAT YOU APK 14.81 (VERSION 298)
// =============================================================================

