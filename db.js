const Database = require('better-sqlite3');
const path = require('node:path');
const fs = require('node:fs');

const dbPath = process.env.DB_PATH || path.join(__dirname, 'slimchat.db');
const db = new Database(dbPath);

db.pragma('journal_mode = WAL');

// Initialize base schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE,
    displayName TEXT,
    password TEXT,
    email TEXT,
    phone TEXT,
    bio TEXT,
    gender TEXT,
    birthday TEXT,
    profileMusicTitle TEXT,
    profileMusicUrl TEXT,
    avatarUrl TEXT,
    verified INTEGER DEFAULT 0,
    referralCode TEXT,
    coins INTEGER DEFAULT 1000,
    createdAt TEXT
  );

  CREATE TABLE IF NOT EXISTS tokens (
    token TEXT PRIMARY KEY,
    userId TEXT,
    type TEXT,
    createdAt TEXT
  );

  CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    userId TEXT,
    name TEXT,
    platform TEXT,
    lastActive TEXT,
    loginIp TEXT,
    isCurrent INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS qr_logins (
    token TEXT PRIMARY KEY,
    status TEXT,
    browser TEXT,
    ip TEXT,
    createdAt TEXT,
    userId TEXT
  );

  CREATE TABLE IF NOT EXISTS auth_codes (
    target TEXT PRIMARY KEY,
    code TEXT,
    type TEXT,
    createdAt TEXT,
    email TEXT,
    expiresAt TEXT
  );

  CREATE TABLE IF NOT EXISTS email_codes (
    email TEXT PRIMARY KEY,
    code TEXT,
    registrationToken TEXT,
    createdAt TEXT
  );

  CREATE TABLE IF NOT EXISTS user_avatars (
    id TEXT PRIMARY KEY,
    userId TEXT,
    url TEXT,
    createdAt TEXT
  );

  CREATE TABLE IF NOT EXISTS privacy_settings (
    userId TEXT PRIMARY KEY,
    lastSeen TEXT DEFAULT 'everybody',
    phone TEXT DEFAULT 'everybody',
    photo TEXT DEFAULT 'everybody',
    messages TEXT DEFAULT 'everybody',
    bio TEXT DEFAULT 'everybody',
    groupInvites TEXT DEFAULT 'everybody'
  );

  CREATE TABLE IF NOT EXISTS blocked_users (
    userId TEXT,
    blockedId TEXT,
    PRIMARY KEY(userId, blockedId)
  );

  CREATE TABLE IF NOT EXISTS stories (
    id TEXT PRIMARY KEY,
    userId TEXT,
    mediaUrl TEXT,
    caption TEXT,
    text TEXT,
    background TEXT,
    font TEXT,
    createdAt TEXT,
    expiresAt TEXT
  );

  CREATE TABLE IF NOT EXISTS story_views (
    storyId TEXT,
    userId TEXT,
    viewedAt TEXT,
    PRIMARY KEY(storyId, userId)
  );

  CREATE TABLE IF NOT EXISTS chats (
    id TEXT PRIMARY KEY,
    type TEXT,
    title TEXT,
    isPublic INTEGER DEFAULT 0,
    createdAt TEXT,
    description TEXT,
    pinChannelPosts INTEGER DEFAULT 0,
    inviteCode TEXT,
    name TEXT,
    ownerId TEXT,
    avatarUrl TEXT,
    publicUsername TEXT,
    requireApproval INTEGER DEFAULT 0,
    memberCanSendMessages INTEGER DEFAULT 1,
    memberCanSendMedia INTEGER DEFAULT 1,
    memberCanAddMembers INTEGER DEFAULT 1,
    slowModeSeconds INTEGER DEFAULT 0,
    historyVisibleToNewMembers INTEGER DEFAULT 1,
    reactionsEnabled INTEGER DEFAULT 1,
    pinnedMessageId TEXT,
    verified INTEGER DEFAULT 0,
    discussionId TEXT,
    inFeed INTEGER DEFAULT 0,
    topics TEXT,
    indevs INTEGER DEFAULT 0,
    supporter INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS chat_members (
    chatId TEXT,
    userId TEXT,
    role TEXT,
    canWrite INTEGER DEFAULT 1,
    pinned INTEGER DEFAULT 0,
    archived INTEGER DEFAULT 0,
    notifMuted INTEGER DEFAULT 0,
    lastReadSeq INTEGER DEFAULT 0,
    mutedUntil TEXT,
    joinedAt TEXT,
    PRIMARY KEY(chatId, userId)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    chatId TEXT,
    senderId TEXT,
    body TEXT,
    seq INTEGER,
    silent INTEGER DEFAULT 0,
    replyToId TEXT,
    attachments TEXT,
    images TEXT,
    files TEXT,
    videos TEXT,
    voice TEXT,
    createdAt TEXT,
    spoiler INTEGER DEFAULT 0,
    isSticker INTEGER DEFAULT 0,
    poll TEXT,
    forwardedFrom TEXT,
    reactions TEXT,
    editedAt TEXT,
    pinSeq INTEGER,
    giftCaption TEXT,
    giftId TEXT,
    giftPrice INTEGER DEFAULT 0,
    giftRevealed INTEGER DEFAULT 0,
    senderDeviceId TEXT,
    envelopes TEXT,
    views INTEGER DEFAULT 0,
    edited INTEGER DEFAULT 0,
    isSystem INTEGER DEFAULT 0,
    updatedAt TEXT
  );

  CREATE TABLE IF NOT EXISTS chat_bans (
    chatId TEXT,
    userId TEXT,
    bannedAt TEXT,
    PRIMARY KEY(chatId, userId)
  );

  CREATE TABLE IF NOT EXISTS comments (
    id TEXT PRIMARY KEY,
    messageId TEXT,
    chatId TEXT,
    userId TEXT,
    body TEXT,
    createdAt TEXT
  );

  CREATE TABLE IF NOT EXISTS chat_join_requests (
    chatId TEXT,
    userId TEXT,
    createdAt TEXT,
    PRIMARY KEY(chatId, userId)
  );

  CREATE TABLE IF NOT EXISTS scheduled_messages (
    id TEXT PRIMARY KEY,
    chatId TEXT,
    userId TEXT,
    body TEXT,
    sendAt TEXT,
    attachments TEXT,
    createdAt TEXT
  );

  CREATE TABLE IF NOT EXISTS sticker_packs (
    id TEXT PRIMARY KEY,
    userId TEXT,
    name TEXT,
    items TEXT,
    createdAt TEXT
  );

  CREATE TABLE IF NOT EXISTS e2ee_keys (
    userId TEXT,
    deviceId TEXT,
    identityKey TEXT,
    signedPrekey TEXT,
    oneTimePrekeys TEXT,
    updatedAt TEXT,
    PRIMARY KEY(userId, deviceId)
  );

  CREATE TABLE IF NOT EXISTS user_invites (
    id TEXT PRIMARY KEY,
    userId TEXT,
    code TEXT UNIQUE,
    createdAt TEXT
  );

  CREATE TABLE IF NOT EXISTS spam_reports (
    id TEXT PRIMARY KEY,
    chatId TEXT,
    reporterId TEXT,
    createdAt TEXT
  );

  CREATE TABLE IF NOT EXISTS hidden_spam_bars (
    userId TEXT,
    chatId TEXT,
    PRIMARY KEY(userId, chatId)
  );

  CREATE TABLE IF NOT EXISTS user_pin_orders (
    userId TEXT PRIMARY KEY,
    chatIds TEXT
  );

  CREATE TABLE IF NOT EXISTS chat_mentions_read (
    chatId TEXT,
    userId TEXT,
    lastReadSeq INTEGER,
    PRIMARY KEY(chatId, userId)
  );

  CREATE TABLE IF NOT EXISTS feed_reports (
    id TEXT PRIMARY KEY,
    chatId TEXT,
    messageId TEXT,
    userId TEXT,
    createdAt TEXT
  );

  CREATE TABLE IF NOT EXISTS user_sticker_packs (
    userId TEXT,
    packId TEXT,
    PRIMARY KEY(userId, packId)
  );

  CREATE TABLE IF NOT EXISTS user_sticker_prefs (
    userId TEXT PRIMARY KEY,
    recent TEXT,
    favorite TEXT
  );

  CREATE TABLE IF NOT EXISTS localizations (
    id TEXT PRIMARY KEY,
    name TEXT,
    baseLang TEXT,
    overrides TEXT,
    authorId TEXT,
    createdAt TEXT
  );
`);

// Safe column migrations for existing databases
const migrations = [
  'ALTER TABLE chat_members ADD COLUMN lastReadSeq INTEGER DEFAULT 0',
  'ALTER TABLE chat_members ADD COLUMN notifMuted INTEGER DEFAULT 0',
  'ALTER TABLE chat_members ADD COLUMN pinned INTEGER DEFAULT 0',
  'ALTER TABLE chat_members ADD COLUMN archived INTEGER DEFAULT 0',
  'ALTER TABLE chat_members ADD COLUMN mutedUntil TEXT',
  'ALTER TABLE chat_members ADD COLUMN canWrite INTEGER DEFAULT 1',
  'ALTER TABLE chats ADD COLUMN inFeed INTEGER DEFAULT 0',
  'ALTER TABLE chats ADD COLUMN topics TEXT',
  'ALTER TABLE chats ADD COLUMN discussionId TEXT',
  'ALTER TABLE chats ADD COLUMN indevs INTEGER DEFAULT 0',
  'ALTER TABLE chats ADD COLUMN supporter INTEGER DEFAULT 0',
  'ALTER TABLE messages ADD COLUMN giftCaption TEXT',
  'ALTER TABLE messages ADD COLUMN giftId TEXT',
  'ALTER TABLE messages ADD COLUMN giftPrice INTEGER DEFAULT 0',
  'ALTER TABLE messages ADD COLUMN giftRevealed INTEGER DEFAULT 0',
  'ALTER TABLE messages ADD COLUMN senderDeviceId TEXT',
  'ALTER TABLE messages ADD COLUMN envelopes TEXT',
  'ALTER TABLE messages ADD COLUMN views INTEGER DEFAULT 0',
  'ALTER TABLE messages ADD COLUMN edited INTEGER DEFAULT 0',
  'ALTER TABLE messages ADD COLUMN isSystem INTEGER DEFAULT 0',
  'ALTER TABLE messages ADD COLUMN updatedAt TEXT',
  'ALTER TABLE messages ADD COLUMN forwardedFrom TEXT',
];

for (const sql of migrations) {
  try {
    db.prepare(sql).run();
  } catch (_) {
    // Column already exists
  }
}

module.exports = db;
