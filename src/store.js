// src/store.js
// 데이터 저장 계층 (3-tier 자동 선택).
//
// 우선순위:
//   1) PostgreSQL  — 환경변수 DATABASE_URL 이 있을 때 (외부 DB / 배포용)
//   2) SQLite      — better-sqlite3 가 설치돼 있을 때 (로컬 개발용)
//   3) JSON 파일   — 위 둘 다 안 되면 폴백 (설치 없이 즉시 실행)

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_DIR = path.join(__dirname, '..', 'db');

if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}

let backend = null;

// ===========================================================================
// 1) PostgreSQL 백엔드
// ===========================================================================

export async function buildPgBackend(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            SERIAL PRIMARY KEY,
      username      TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      enc_pubkey    TEXT,
      sig_pubkey    TEXT,
      is_admin      INTEGER NOT NULL DEFAULT 0,
      created_at    TEXT NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id           SERIAL PRIMARY KEY,
      sender_id    INTEGER NOT NULL REFERENCES users(id),
      receiver_id  INTEGER NOT NULL REFERENCES users(id),
      enc_key      TEXT NOT NULL,
      iv           TEXT NOT NULL,
      ciphertext   TEXT NOT NULL,
      signature    TEXT NOT NULL,
      created_at   TEXT NOT NULL
    );
  `);
  // 단체방 테이블
  await pool.query(`
    CREATE TABLE IF NOT EXISTS groups (
      id         SERIAL PRIMARY KEY,
      name       TEXT NOT NULL,
      created_by INTEGER NOT NULL REFERENCES users(id),
      created_at TEXT NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS group_members (
      group_id  INTEGER NOT NULL REFERENCES groups(id),
      user_id   INTEGER NOT NULL REFERENCES users(id),
      PRIMARY KEY (group_id, user_id)
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS group_messages (
      id         SERIAL PRIMARY KEY,
      group_id   INTEGER NOT NULL REFERENCES groups(id),
      sender_id  INTEGER NOT NULL REFERENCES users(id),
      iv         TEXT NOT NULL,
      ciphertext TEXT NOT NULL,
      signature  TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS group_message_keys (
      message_id INTEGER NOT NULL REFERENCES group_messages(id),
      user_id    INTEGER NOT NULL REFERENCES users(id),
      enc_key    TEXT NOT NULL,
      PRIMARY KEY (message_id, user_id)
    );
  `);

  return {
    kind: 'postgres',
    async countUsers() {
      const r = await pool.query('SELECT COUNT(*)::int AS n FROM users');
      return r.rows[0].n;
    },
    async createUser(username, passwordHash, createdAt, isAdmin = 0) {
      const r = await pool.query(
        'INSERT INTO users (username, password_hash, created_at, is_admin) VALUES ($1, $2, $3, $4) RETURNING id',
        [username, passwordHash, createdAt, isAdmin ? 1 : 0]
      );
      return r.rows[0].id;
    },
    async getUserByUsername(username) {
      const r = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
      return r.rows[0] || null;
    },
    async getUserById(id) {
      const r = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
      return r.rows[0] || null;
    },
    async setPublicKeys(userId, encPubkey, sigPubkey) {
      await pool.query(
        'UPDATE users SET enc_pubkey = $1, sig_pubkey = $2 WHERE id = $3',
        [encPubkey, sigPubkey, userId]
      );
    },
    async listUsers(excludeId) {
      const r = await pool.query(
        'SELECT id, username, enc_pubkey, sig_pubkey FROM users WHERE id <> $1 ORDER BY username',
        [excludeId]
      );
      return r.rows;
    },
    async listAllUsers() {
      const r = await pool.query(`
        SELECT u.id, u.username, u.is_admin, u.created_at,
          (SELECT COUNT(*)::int FROM messages WHERE sender_id = u.id)   AS sent_count,
          (SELECT COUNT(*)::int FROM messages WHERE receiver_id = u.id) AS recv_count
        FROM users u ORDER BY u.id
      `);
      return r.rows;
    },
    async deleteUser(userId) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query('DELETE FROM group_message_keys WHERE user_id = $1', [userId]);
        const gms = await client.query('SELECT id FROM group_messages WHERE sender_id = $1', [userId]);
        for (const gm of gms.rows) {
          await client.query('DELETE FROM group_message_keys WHERE message_id = $1', [gm.id]);
        }
        await client.query('DELETE FROM group_messages WHERE sender_id = $1', [userId]);
        await client.query('DELETE FROM group_members WHERE user_id = $1', [userId]);
        await client.query('DELETE FROM messages WHERE sender_id = $1 OR receiver_id = $1', [userId]);
        await client.query('DELETE FROM users WHERE id = $1', [userId]);
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK');
        throw e;
      } finally {
        client.release();
      }
    },
    async createMessage(m) {
      const r = await pool.query(
        `INSERT INTO messages (sender_id, receiver_id, enc_key, iv, ciphertext, signature, created_at)
          VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
        [m.senderId, m.receiverId, m.encKey, m.iv, m.ciphertext, m.signature, m.createdAt]
      );
      return r.rows[0].id;
    },
    async getInbox(userId) {
      const r = await pool.query(
        'SELECT * FROM messages WHERE receiver_id = $1 ORDER BY created_at DESC',
        [userId]
      );
      return r.rows;
    },
    async getSent(userId) {
      const r = await pool.query(
        'SELECT * FROM messages WHERE sender_id = $1 ORDER BY created_at DESC',
        [userId]
      );
      return r.rows;
    },
    // --- 단체방 ---
    async createGroup(name, createdBy, createdAt, memberIds) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const r = await client.query(
          'INSERT INTO groups (name, created_by, created_at) VALUES ($1, $2, $3) RETURNING id',
          [name, createdBy, createdAt]
        );
        const groupId = r.rows[0].id;
        const allMembers = [...new Set([createdBy, ...memberIds])];
        for (const uid of allMembers) {
          await client.query(
            'INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)',
            [groupId, uid]
          );
        }
        await client.query('COMMIT');
        return groupId;
      } catch (e) {
        await client.query('ROLLBACK');
        throw e;
      } finally {
        client.release();
      }
    },
    async listGroupsForUser(userId) {
      const r = await pool.query(
        `SELECT g.id, g.name, g.created_by, g.created_at
           FROM groups g
           JOIN group_members gm ON gm.group_id = g.id
          WHERE gm.user_id = $1
          ORDER BY g.id`,
        [userId]
      );
      return r.rows;
    },
    async getGroupById(groupId) {
      const r = await pool.query('SELECT * FROM groups WHERE id = $1', [groupId]);
      return r.rows[0] || null;
    },
    async getGroupMembers(groupId) {
      const r = await pool.query(
        `SELECT u.id, u.username, u.enc_pubkey, u.sig_pubkey
           FROM users u
           JOIN group_members gm ON gm.user_id = u.id
          WHERE gm.group_id = $1
          ORDER BY u.username`,
        [groupId]
      );
      return r.rows;
    },
    async isGroupMember(groupId, userId) {
      const r = await pool.query(
        'SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2',
        [groupId, userId]
      );
      return r.rows.length > 0;
    },
    async createGroupMessage(groupId, senderId, iv, ciphertext, signature, createdAt, memberKeys) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const r = await client.query(
          `INSERT INTO group_messages (group_id, sender_id, iv, ciphertext, signature, created_at)
            VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
          [groupId, senderId, iv, ciphertext, signature, createdAt]
        );
        const msgId = r.rows[0].id;
        for (const { userId, encKey } of memberKeys) {
          await client.query(
            'INSERT INTO group_message_keys (message_id, user_id, enc_key) VALUES ($1, $2, $3)',
            [msgId, userId, encKey]
          );
        }
        await client.query('COMMIT');
        return msgId;
      } catch (e) {
        await client.query('ROLLBACK');
        throw e;
      } finally {
        client.release();
      }
    },
    async getGroupMessages(groupId, userId) {
      const r = await pool.query(
        `SELECT gm.id, gm.sender_id, gm.iv, gm.ciphertext, gm.signature, gm.created_at,
                gmk.enc_key
           FROM group_messages gm
           JOIN group_message_keys gmk ON gmk.message_id = gm.id AND gmk.user_id = $2
          WHERE gm.group_id = $1
          ORDER BY gm.created_at ASC`,
        [groupId, userId]
      );
      return r.rows;
    },
  };
}

async function tryPostgres() {
  const url = process.env.DATABASE_URL;
  if (!url) return null;
  try {
    const pg = await import('pg');
    const { Pool } = pg.default;
    const isLocal = /localhost|127\.0\.0\.1/.test(url);
    const pool = new Pool({
      connectionString: url,
      ssl: isLocal ? false : { rejectUnauthorized: false },
    });
    await pool.query('SELECT 1');
    return await buildPgBackend(pool);
  } catch (err) {
    console.error('[store] PostgreSQL 연결 실패:', err.message);
    return null;
  }
}

// ===========================================================================
// 2) SQLite 백엔드
// ===========================================================================
async function trySqlite() {
  try {
    const mod = await import('better-sqlite3');
    const Database = mod.default;
    const db = new Database(path.join(DB_DIR, 'messenger.sqlite'));
    db.pragma('journal_mode = WAL');

    db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        username      TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        enc_pubkey    TEXT,
        sig_pubkey    TEXT,
        is_admin      INTEGER NOT NULL DEFAULT 0,
        created_at    TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS messages (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id    INTEGER NOT NULL,
        receiver_id  INTEGER NOT NULL,
        enc_key      TEXT NOT NULL,
        iv           TEXT NOT NULL,
        ciphertext   TEXT NOT NULL,
        signature    TEXT NOT NULL,
        created_at   TEXT NOT NULL,
        FOREIGN KEY (sender_id)   REFERENCES users(id),
        FOREIGN KEY (receiver_id) REFERENCES users(id)
      );
      CREATE TABLE IF NOT EXISTS groups (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        name       TEXT NOT NULL,
        created_by INTEGER NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS group_members (
        group_id  INTEGER NOT NULL,
        user_id   INTEGER NOT NULL,
        PRIMARY KEY (group_id, user_id)
      );
      CREATE TABLE IF NOT EXISTS group_messages (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id   INTEGER NOT NULL,
        sender_id  INTEGER NOT NULL,
        iv         TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        signature  TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS group_message_keys (
        message_id INTEGER NOT NULL,
        user_id    INTEGER NOT NULL,
        enc_key    TEXT NOT NULL,
        PRIMARY KEY (message_id, user_id)
      );
    `);

    const cols = db.prepare("PRAGMA table_info(users)").all();
    if (!cols.some((c) => c.name === 'is_admin')) {
      db.exec('ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0');
    }

    return {
      kind: 'sqlite',
      async countUsers() {
        return db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
      },
      async createUser(username, passwordHash, createdAt, isAdmin = 0) {
        const info = db
          .prepare('INSERT INTO users (username, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?)')
          .run(username, passwordHash, createdAt, isAdmin ? 1 : 0);
        return Number(info.lastInsertRowid);
      },
      async getUserByUsername(username) {
        return db.prepare('SELECT * FROM users WHERE username = ?').get(username) || null;
      },
      async getUserById(id) {
        return db.prepare('SELECT * FROM users WHERE id = ?').get(id) || null;
      },
      async setPublicKeys(userId, encPubkey, sigPubkey) {
        db.prepare('UPDATE users SET enc_pubkey = ?, sig_pubkey = ? WHERE id = ?')
          .run(encPubkey, sigPubkey, userId);
      },
      async listUsers(excludeId) {
        return db
          .prepare('SELECT id, username, enc_pubkey, sig_pubkey FROM users WHERE id != ? ORDER BY username')
          .all(excludeId);
      },
      async listAllUsers() {
        return db
          .prepare(`
            SELECT u.id, u.username, u.is_admin, u.created_at,
              (SELECT COUNT(*) FROM messages WHERE sender_id = u.id)   AS sent_count,
              (SELECT COUNT(*) FROM messages WHERE receiver_id = u.id) AS recv_count
            FROM users u ORDER BY u.id
          `)
          .all();
      },
      async deleteUser(userId) {
        const tx = db.transaction((id) => {
          db.prepare('DELETE FROM group_message_keys WHERE user_id = ?').run(id);
          const gms = db.prepare('SELECT id FROM group_messages WHERE sender_id = ?').all(id);
          for (const gm of gms) {
            db.prepare('DELETE FROM group_message_keys WHERE message_id = ?').run(gm.id);
          }
          db.prepare('DELETE FROM group_messages WHERE sender_id = ?').run(id);
          db.prepare('DELETE FROM group_members WHERE user_id = ?').run(id);
          db.prepare('DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?').run(id, id);
          db.prepare('DELETE FROM users WHERE id = ?').run(id);
        });
        tx(userId);
      },
      async createMessage(m) {
        const info = db
          .prepare(`INSERT INTO messages (sender_id, receiver_id, enc_key, iv, ciphertext, signature, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)`)
          .run(m.senderId, m.receiverId, m.encKey, m.iv, m.ciphertext, m.signature, m.createdAt);
        return Number(info.lastInsertRowid);
      },
      async getInbox(userId) {
        return db
          .prepare('SELECT * FROM messages WHERE receiver_id = ? ORDER BY created_at DESC')
          .all(userId);
      },
      async getSent(userId) {
        return db
          .prepare('SELECT * FROM messages WHERE sender_id = ? ORDER BY created_at DESC')
          .all(userId);
      },
      // --- 단체방 ---
      async createGroup(name, createdBy, createdAt, memberIds) {
        const tx = db.transaction(() => {
          const info = db.prepare(
            'INSERT INTO groups (name, created_by, created_at) VALUES (?, ?, ?)'
          ).run(name, createdBy, createdAt);
          const groupId = Number(info.lastInsertRowid);
          const allMembers = [...new Set([createdBy, ...memberIds])];
          for (const uid of allMembers) {
            db.prepare('INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)').run(groupId, uid);
          }
          return groupId;
        });
        return tx();
      },
      async listGroupsForUser(userId) {
        return db.prepare(
          `SELECT g.id, g.name, g.created_by, g.created_at
             FROM groups g
             JOIN group_members gm ON gm.group_id = g.id
            WHERE gm.user_id = ?
            ORDER BY g.id`
        ).all(userId);
      },
      async getGroupById(groupId) {
        return db.prepare('SELECT * FROM groups WHERE id = ?').get(groupId) || null;
      },
      async getGroupMembers(groupId) {
        return db.prepare(
          `SELECT u.id, u.username, u.enc_pubkey, u.sig_pubkey
             FROM users u
             JOIN group_members gm ON gm.user_id = u.id
            WHERE gm.group_id = ?
            ORDER BY u.username`
        ).all(groupId);
      },
      async isGroupMember(groupId, userId) {
        return !!db.prepare(
          'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?'
        ).get(groupId, userId);
      },
      async createGroupMessage(groupId, senderId, iv, ciphertext, signature, createdAt, memberKeys) {
        const tx = db.transaction(() => {
          const info = db.prepare(
            `INSERT INTO group_messages (group_id, sender_id, iv, ciphertext, signature, created_at)
              VALUES (?, ?, ?, ?, ?, ?)`
          ).run(groupId, senderId, iv, ciphertext, signature, createdAt);
          const msgId = Number(info.lastInsertRowid);
          for (const { userId, encKey } of memberKeys) {
            db.prepare(
              'INSERT INTO group_message_keys (message_id, user_id, enc_key) VALUES (?, ?, ?)'
            ).run(msgId, userId, encKey);
          }
          return msgId;
        });
        return tx();
      },
      async getGroupMessages(groupId, userId) {
        return db.prepare(
          `SELECT gm.id, gm.sender_id, gm.iv, gm.ciphertext, gm.signature, gm.created_at,
                  gmk.enc_key
             FROM group_messages gm
             JOIN group_message_keys gmk ON gmk.message_id = gm.id AND gmk.user_id = ?
            WHERE gm.group_id = ?
            ORDER BY gm.created_at ASC`
        ).all(userId, groupId);
      },
    };
  } catch (err) {
    return null;
  }
}

// ===========================================================================
// 3) JSON 파일 백엔드 (폴백)
// ===========================================================================
function jsonBackend() {
  const file = path.join(DB_DIR, 'messenger.json');
  let data = { users: [], messages: [], groups: [], groupMembers: [], groupMessages: [], groupMessageKeys: [], seqUser: 0, seqMsg: 0, seqGroup: 0, seqGMsg: 0 };

  if (fs.existsSync(file)) {
    try {
      const loaded = JSON.parse(fs.readFileSync(file, 'utf8'));
      data = { ...data, ...loaded };
    } catch {
      // 초기화
    }
  }

  function persist() {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
  }

  return {
    kind: 'json',
    async countUsers() { return data.users.length; },
    async createUser(username, passwordHash, createdAt, isAdmin = 0) {
      const id = ++data.seqUser;
      data.users.push({ id, username, password_hash: passwordHash, enc_pubkey: null, sig_pubkey: null, is_admin: isAdmin ? 1 : 0, created_at: createdAt });
      persist();
      return id;
    },
    async getUserByUsername(username) {
      return data.users.find((u) => u.username === username) || null;
    },
    async getUserById(id) {
      return data.users.find((u) => u.id === id) || null;
    },
    async setPublicKeys(userId, encPubkey, sigPubkey) {
      const u = data.users.find((x) => x.id === userId);
      if (u) { u.enc_pubkey = encPubkey; u.sig_pubkey = sigPubkey; persist(); }
    },
    async listUsers(excludeId) {
      return data.users.filter((u) => u.id !== excludeId)
        .map((u) => ({ id: u.id, username: u.username, enc_pubkey: u.enc_pubkey, sig_pubkey: u.sig_pubkey }))
        .sort((a, b) => a.username.localeCompare(b.username));
    },
    async listAllUsers() {
      return data.users.map((u) => ({
        id: u.id, username: u.username, is_admin: u.is_admin ? 1 : 0, created_at: u.created_at,
        sent_count: data.messages.filter((m) => m.sender_id === u.id).length,
        recv_count: data.messages.filter((m) => m.receiver_id === u.id).length,
      })).sort((a, b) => a.id - b.id);
    },
    async deleteUser(userId) {
      const msgIds = data.groupMessages.filter((m) => m.sender_id === userId).map((m) => m.id);
      data.groupMessageKeys = data.groupMessageKeys.filter(
        (k) => k.user_id !== userId && !msgIds.includes(k.message_id)
      );
      data.groupMessages = data.groupMessages.filter((m) => m.sender_id !== userId);
      data.groupMembers = data.groupMembers.filter((m) => m.user_id !== userId);
      data.messages = data.messages.filter((m) => m.sender_id !== userId && m.receiver_id !== userId);
      data.users = data.users.filter((u) => u.id !== userId);
      persist();
    },
    async createMessage(m) {
      const id = ++data.seqMsg;
      data.messages.push({ id, sender_id: m.senderId, receiver_id: m.receiverId, enc_key: m.encKey, iv: m.iv, ciphertext: m.ciphertext, signature: m.signature, created_at: m.createdAt });
      persist();
      return id;
    },
    async getInbox(userId) {
      return data.messages.filter((m) => m.receiver_id === userId).sort((a, b) => b.created_at.localeCompare(a.created_at));
    },
    async getSent(userId) {
      return data.messages.filter((m) => m.sender_id === userId).sort((a, b) => b.created_at.localeCompare(a.created_at));
    },
    // --- 단체방 ---
    async createGroup(name, createdBy, createdAt, memberIds) {
      const id = ++data.seqGroup;
      data.groups.push({ id, name, created_by: createdBy, created_at: createdAt });
      const allMembers = [...new Set([createdBy, ...memberIds])];
      for (const uid of allMembers) {
        if (!data.groupMembers.find((m) => m.group_id === id && m.user_id === uid)) {
          data.groupMembers.push({ group_id: id, user_id: uid });
        }
      }
      persist();
      return id;
    },
    async listGroupsForUser(userId) {
      const myGroupIds = data.groupMembers.filter((m) => m.user_id === userId).map((m) => m.group_id);
      return data.groups.filter((g) => myGroupIds.includes(g.id)).sort((a, b) => a.id - b.id);
    },
    async getGroupById(groupId) {
      return data.groups.find((g) => g.id === groupId) || null;
    },
    async getGroupMembers(groupId) {
      const memberIds = data.groupMembers.filter((m) => m.group_id === groupId).map((m) => m.user_id);
      return data.users.filter((u) => memberIds.includes(u.id))
        .map((u) => ({ id: u.id, username: u.username, enc_pubkey: u.enc_pubkey, sig_pubkey: u.sig_pubkey }))
        .sort((a, b) => a.username.localeCompare(b.username));
    },
    async isGroupMember(groupId, userId) {
      return !!data.groupMembers.find((m) => m.group_id === groupId && m.user_id === userId);
    },
    async createGroupMessage(groupId, senderId, iv, ciphertext, signature, createdAt, memberKeys) {
      const id = ++data.seqGMsg;
      data.groupMessages.push({ id, group_id: groupId, sender_id: senderId, iv, ciphertext, signature, created_at: createdAt });
      for (const { userId, encKey } of memberKeys) {
        data.groupMessageKeys.push({ message_id: id, user_id: userId, enc_key: encKey });
      }
      persist();
      return id;
    },
    async getGroupMessages(groupId, userId) {
      const myKeys = {};
      for (const k of data.groupMessageKeys) {
        if (k.user_id === userId) myKeys[k.message_id] = k.enc_key;
      }
      return data.groupMessages
        .filter((m) => m.group_id === groupId && myKeys[m.id] !== undefined)
        .map((m) => ({ ...m, enc_key: myKeys[m.id] }))
        .sort((a, b) => a.created_at.localeCompare(b.created_at));
    },
  };
}

// ===========================================================================
// 초기화
// ===========================================================================
export async function initStore() {
  if (backend) return backend;
  backend = (await tryPostgres()) || (await trySqlite()) || jsonBackend();
  console.log(`[store] 백엔드: ${backend.kind}`);
  return backend;
}

export function getStore() {
  if (!backend) throw new Error('Store not initialized. Call initStore() first.');
  return backend;
}
