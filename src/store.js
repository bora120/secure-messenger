// src/store.js
// 데이터 저장 계층 (3-tier 자동 선택).
//
// 우선순위:
//   1) PostgreSQL  — 환경변수 DATABASE_URL 이 있을 때 (외부 DB / 배포용)
//   2) SQLite      — better-sqlite3 가 설치돼 있을 때 (로컬 개발용)
//   3) JSON 파일   — 위 둘 다 안 되면 폴백 (설치 없이 즉시 실행)
//
// 모든 백엔드는 동일한 "async" 메서드 인터페이스를 제공한다.
// SQLite/JSON 은 본래 동기이지만 async 로 감싸서, 호출부가 백엔드 종류와
// 무관하게 항상 await 만 쓰면 되도록 통일했다.

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

// pool 을 받아 PostgreSQL 백엔드 객체를 만든다.
// 실제 실행에서는 pg 의 Pool 을, 테스트에서는 pglite 등 호환 pool 을 주입한다.
// pool 은 query(text, params) 와 connect() 를 제공해야 한다.
export async function buildPgBackend(pool) {
  // 스키마 생성 (없을 때만)
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
      // 트랜잭션으로 메시지 먼저 삭제 후 사용자 삭제
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
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
        `INSERT INTO messages
          (sender_id, receiver_id, enc_key, iv, ciphertext, signature, created_at)
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
  };
}

async function tryPostgres() {
  const url = process.env.DATABASE_URL;
  if (!url) return null; // DATABASE_URL 이 없으면 PostgreSQL 사용 안 함

  try {
    const pg = await import('pg');
    const { Pool } = pg.default;

    // Render 등 클라우드 PostgreSQL 은 SSL 을 요구한다.
    // 로컬 PostgreSQL(예: localhost)은 SSL 이 없을 수 있으므로 구분한다.
    const isLocal = /localhost|127\.0\.0\.1/.test(url);
    const pool = new Pool({
      connectionString: url,
      ssl: isLocal ? false : { rejectUnauthorized: false },
    });

    // 연결 확인
    await pool.query('SELECT 1');

    return await buildPgBackend(pool);
  } catch (err) {
    console.error('[store] PostgreSQL 연결 실패:', err.message);
    return null;
  }
}

// ===========================================================================
// 2) SQLite 백엔드 (better-sqlite3)
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
    `);

    // 마이그레이션: 이전 버전 DB에 is_admin 컬럼이 없으면 추가한다.
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
          db.prepare('DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?').run(id, id);
          db.prepare('DELETE FROM users WHERE id = ?').run(id);
        });
        tx(userId);
      },
      async createMessage(m) {
        const info = db
          .prepare(`INSERT INTO messages
            (sender_id, receiver_id, enc_key, iv, ciphertext, signature, created_at)
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
  let data = { users: [], messages: [], seqUser: 0, seqMsg: 0 };

  if (fs.existsSync(file)) {
    try {
      data = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch {
      data = { users: [], messages: [], seqUser: 0, seqMsg: 0 };
    }
  }

  function persist() {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
  }

  return {
    kind: 'json',
    async countUsers() {
      return data.users.length;
    },
    async createUser(username, passwordHash, createdAt, isAdmin = 0) {
      const id = ++data.seqUser;
      data.users.push({
        id,
        username,
        password_hash: passwordHash,
        enc_pubkey: null,
        sig_pubkey: null,
        is_admin: isAdmin ? 1 : 0,
        created_at: createdAt,
      });
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
      if (u) {
        u.enc_pubkey = encPubkey;
        u.sig_pubkey = sigPubkey;
        persist();
      }
    },
    async listUsers(excludeId) {
      return data.users
        .filter((u) => u.id !== excludeId)
        .map((u) => ({
          id: u.id,
          username: u.username,
          enc_pubkey: u.enc_pubkey,
          sig_pubkey: u.sig_pubkey,
        }))
        .sort((a, b) => a.username.localeCompare(b.username));
    },
    async listAllUsers() {
      return data.users
        .map((u) => ({
          id: u.id,
          username: u.username,
          is_admin: u.is_admin ? 1 : 0,
          created_at: u.created_at,
          sent_count: data.messages.filter((m) => m.sender_id === u.id).length,
          recv_count: data.messages.filter((m) => m.receiver_id === u.id).length,
        }))
        .sort((a, b) => a.id - b.id);
    },
    async deleteUser(userId) {
      data.messages = data.messages.filter(
        (m) => m.sender_id !== userId && m.receiver_id !== userId
      );
      data.users = data.users.filter((u) => u.id !== userId);
      persist();
    },
    async createMessage(m) {
      const id = ++data.seqMsg;
      data.messages.push({
        id,
        sender_id: m.senderId,
        receiver_id: m.receiverId,
        enc_key: m.encKey,
        iv: m.iv,
        ciphertext: m.ciphertext,
        signature: m.signature,
        created_at: m.createdAt,
      });
      persist();
      return id;
    },
    async getInbox(userId) {
      return data.messages
        .filter((m) => m.receiver_id === userId)
        .sort((a, b) => b.created_at.localeCompare(a.created_at));
    },
    async getSent(userId) {
      return data.messages
        .filter((m) => m.sender_id === userId)
        .sort((a, b) => b.created_at.localeCompare(a.created_at));
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
