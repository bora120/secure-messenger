// src/auth.js
// 인증 관련 헬퍼: 비밀번호 해싱, JWT 발급/검증, 인증 미들웨어.

import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { getStore } from './store.js';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me-in-production';
const JWT_EXPIRES_IN = '2h';

export async function hashPassword(plain) {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(plain, salt);
}

export async function verifyPassword(plain, hash) {
  return bcrypt.compare(plain, hash);
}

export function issueToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username, isAdmin: Boolean(user.is_admin) },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

// Express 미들웨어: Authorization: Bearer <token> 검증
export function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const parts = header.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({ error: '인증 토큰이 필요합니다.' });
  }
  try {
    const payload = jwt.verify(parts[1], JWT_SECRET);
    req.user = {
      id: payload.sub,
      username: payload.username,
      isAdmin: Boolean(payload.isAdmin),
    };
    next();
  } catch {
    return res.status(401).json({ error: '유효하지 않거나 만료된 토큰입니다.' });
  }
}

// requireAuth 뒤에 붙여 쓰는 미들웨어: 관리자만 통과시킨다.
// 토큰의 isAdmin만 믿지 않고, DB에서 현재 권한을 다시 확인한다
// (권한 박탈 후 남아있는 옛 토큰을 막기 위함).
export async function requireAdmin(req, res, next) {
  try {
    const store = getStore();
    const user = await store.getUserById(req.user.id);
    if (!user || !user.is_admin) {
      return res.status(403).json({ error: '관리자 권한이 필요합니다.' });
    }
    next();
  } catch (err) {
    return res.status(500).json({ error: '권한 확인 중 오류가 발생했습니다.' });
  }
}
