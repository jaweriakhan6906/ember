const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const SECRET = process.env.SECRET || 'ember-dev-secret-change-me';
const MIN = 60e3, HOUR = 36e5;
const LIFE = 24 * HOUR, LIKE = 30 * MIN, COMMENT = 5 * MIN, LEGEND = 72 * HOUR;

const db = new DatabaseSync(path.join(__dirname, 'ember.db'));
db.exec('PRAGMA journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE COLLATE NOCASE, pass TEXT, bio TEXT DEFAULT '', hue INTEGER DEFAULT 20);
CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY, user_id INT, body TEXT, created_at INT, expires_at INT, legend INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY, post_id INT, user_id INT, body TEXT, created_at INT);
CREATE TABLE IF NOT EXISTS likes(user_id INT, post_id INT, PRIMARY KEY(user_id, post_id));
CREATE TABLE IF NOT EXISTS follows(follower_id INT, followee_id INT, PRIMARY KEY(follower_id, followee_id));
`);

// Burn out expired posts (legends, i.e. posts that lived 72h+, are kept forever)
function sweep() {
  const now = Date.now();
  db.prepare('DELETE FROM comments WHERE post_id IN (SELECT id FROM posts WHERE legend=0 AND expires_at<?)').run(now);
  db.prepare('DELETE FROM likes WHERE post_id IN (SELECT id FROM posts WHERE legend=0 AND expires_at<?)').run(now);
  db.prepare('DELETE FROM posts WHERE legend=0 AND expires_at<?').run(now);
}
setInterval(sweep, 60e3);

const SEL = `SELECT p.*, u.username, u.hue,
  (SELECT COUNT(*) FROM likes WHERE post_id=p.id) likes,
  (SELECT COUNT(*) FROM comments WHERE post_id=p.id) comments,
  EXISTS(SELECT 1 FROM likes WHERE post_id=p.id AND user_id=?) liked
  FROM posts p JOIN users u ON u.id=p.user_id`;
const ALIVE = '(p.legend=1 OR p.expires_at>?)';
const getPost = (id, me) => db.prepare(`${SEL} WHERE p.id=?`).get(me, id);

function extend(id, ms) {
  db.prepare('UPDATE posts SET expires_at=expires_at+? WHERE id=?').run(ms, id);
  db.prepare('UPDATE posts SET legend=1 WHERE id=? AND expires_at-created_at>=?').run(id, LEGEND);
}

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const auth = (req, res, next) => {
  try {
    req.uid = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET).id;
    next();
  } catch { res.status(401).json({ error: 'Please log in again.' }); }
};
const token = u => jwt.sign({ id: u.id }, SECRET, { expiresIn: '7d' });
const publicUser = u => ({ id: u.id, username: u.username, bio: u.bio, hue: u.hue });

// ---------- Auth ----------
app.post('/api/register', (req, res) => {
  const { username = '', password = '' } = req.body;
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) return res.status(400).json({ error: 'Username must be 3-20 letters, numbers or underscores.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password needs at least 6 characters.' });
  if (db.prepare('SELECT 1 FROM users WHERE username=?').get(username)) return res.status(400).json({ error: 'That username is taken.' });
  const hue = Math.floor(Math.random() * 360);
  const id = db.prepare('INSERT INTO users(username,pass,hue) VALUES(?,?,?)').run(username, bcrypt.hashSync(password, 10), hue).lastInsertRowid;
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(id);
  res.json({ token: token(u), user: publicUser(u) });
});

app.post('/api/login', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(req.body.username || '');
  if (!u || !bcrypt.compareSync(req.body.password || '', u.pass)) return res.status(400).json({ error: 'Wrong username or password.' });
  res.json({ token: token(u), user: publicUser(u) });
});

app.get('/api/me', auth, (req, res) => res.json(publicUser(db.prepare('SELECT * FROM users WHERE id=?').get(req.uid))));

app.put('/api/me', auth, (req, res) => {
  const bio = String(req.body.bio || '').slice(0, 160);
  const hue = Math.max(0, Math.min(360, parseInt(req.body.hue) || 0));
  db.prepare('UPDATE users SET bio=?, hue=? WHERE id=?').run(bio, hue, req.uid);
  res.json(publicUser(db.prepare('SELECT * FROM users WHERE id=?').get(req.uid)));
});

// ---------- Posts ----------
app.get('/api/feed', auth, (req, res) => {
  sweep();
  const now = Date.now();
  const orbit = req.query.mode === 'orbit';
  const rows = orbit
    ? db.prepare(`${SEL} WHERE ${ALIVE} AND (p.user_id=? OR p.user_id IN (SELECT followee_id FROM follows WHERE follower_id=?)) ORDER BY p.created_at DESC LIMIT 50`).all(req.uid, now, req.uid, req.uid)
    : db.prepare(`${SEL} WHERE ${ALIVE} ORDER BY (p.expires_at + (SELECT COUNT(*) FROM likes WHERE post_id=p.id)*60000) DESC LIMIT 50`).all(req.uid, now);
  res.json(rows);
});

app.post('/api/posts', auth, (req, res) => {
  const body = String(req.body.body || '').trim().slice(0, 280);
  if (!body) return res.status(400).json({ error: 'Write something to ignite.' });
  const now = Date.now();
  const id = db.prepare('INSERT INTO posts(user_id,body,created_at,expires_at) VALUES(?,?,?,?)').run(req.uid, body, now, now + LIFE).lastInsertRowid;
  res.json(getPost(req.uid, id));
});

app.delete('/api/posts/:id', auth, (req, res) => {
  const r = db.prepare('DELETE FROM posts WHERE id=? AND user_id=?').run(req.params.id, req.uid);
  if (!r.changes) return res.status(403).json({ error: 'You can only delete your own posts.' });
  db.prepare('DELETE FROM comments WHERE post_id=?').run(req.params.id);
  db.prepare('DELETE FROM likes WHERE post_id=?').run(req.params.id);
  res.json({ ok: true });
});

app.post('/api/posts/:id/like', auth, (req, res) => {
  const id = +req.params.id;
  const p = db.prepare(`SELECT * FROM posts p WHERE id=? AND ${ALIVE}`).get(id, Date.now());
  if (!p) return res.status(404).json({ error: 'This ember has burned out.' });
  const had = db.prepare('SELECT 1 FROM likes WHERE user_id=? AND post_id=?').get(req.uid, id);
  if (had) { db.prepare('DELETE FROM likes WHERE user_id=? AND post_id=?').run(req.uid, id); if (!p.legend) extend(id, -LIKE); }
  else { db.prepare('INSERT INTO likes VALUES(?,?)').run(req.uid, id); extend(id, LIKE); }
  res.json(getPost(req.uid, id));
});

app.get('/api/posts/:id/comments', auth, (req, res) => {
  res.json(db.prepare(`SELECT c.*, u.username, u.hue FROM comments c JOIN users u ON u.id=c.user_id WHERE post_id=? ORDER BY c.created_at ASC`).all(req.params.id));
});

app.post('/api/posts/:id/comments', auth, (req, res) => {
  const id = +req.params.id;
  const body = String(req.body.body || '').trim().slice(0, 200);
  if (!body) return res.status(400).json({ error: 'Write a comment first.' });
  if (!db.prepare(`SELECT 1 FROM posts p WHERE id=? AND ${ALIVE}`).get(id, Date.now())) return res.status(404).json({ error: 'This ember has burned out.' });
  db.prepare('INSERT INTO comments(post_id,user_id,body,created_at) VALUES(?,?,?,?)').run(id, req.uid, body, Date.now());
  extend(id, COMMENT);
  res.json(getPost(req.uid, id));
});

// ---------- Profiles & follows ----------
app.get('/api/users/:name', auth, (req, res) => {
  sweep();
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(req.params.name);
  if (!u) return res.status(404).json({ error: 'No such user.' });
  const count = (sql) => db.prepare(sql).get(u.id).n;
  res.json({
    ...publicUser(u),
    followers: count('SELECT COUNT(*) n FROM follows WHERE followee_id=?'),
    following: count('SELECT COUNT(*) n FROM follows WHERE follower_id=?'),
    isFollowing: !!db.prepare('SELECT 1 FROM follows WHERE follower_id=? AND followee_id=?').get(req.uid, u.id),
    isMe: u.id === req.uid,
    live: db.prepare(`${SEL} WHERE p.user_id=? AND p.legend=0 AND p.expires_at>? ORDER BY p.created_at DESC`).all(req.uid, u.id, Date.now()),
    hall: db.prepare(`${SEL} WHERE p.user_id=? AND p.legend=1 ORDER BY p.created_at DESC`).all(req.uid, u.id),
  });
});

app.post('/api/users/:name/follow', auth, (req, res) => {
  const u = db.prepare('SELECT id FROM users WHERE username=?').get(req.params.name);
  if (!u || u.id === req.uid) return res.status(400).json({ error: "You can't follow yourself." });
  const had = db.prepare('SELECT 1 FROM follows WHERE follower_id=? AND followee_id=?').get(req.uid, u.id);
  if (had) db.prepare('DELETE FROM follows WHERE follower_id=? AND followee_id=?').run(req.uid, u.id);
  else db.prepare('INSERT INTO follows VALUES(?,?)').run(req.uid, u.id);
  res.json({ isFollowing: !had, followers: db.prepare('SELECT COUNT(*) n FROM follows WHERE followee_id=?').get(u.id).n });
});

app.get('/api/search', auth, (req, res) => {
  res.json(db.prepare('SELECT id,username,bio,hue FROM users WHERE username LIKE ? LIMIT 8').all(`%${req.query.q || ''}%`));
});

app.listen(3000, () => console.log('Ember is burning at http://localhost:3000'));
