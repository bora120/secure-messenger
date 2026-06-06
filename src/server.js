// src/server.js
// 보안 메시지 시스템 서버.
// 회원가입/로그인, 공개키 등록/조회, 암호문+서명 메시지 송수신을 담당한다.
//
// 보안 설계 요점:
//  - 서버는 평문 메시지를 절대 보지 못한다 (종단간 암호화).
//  - 서버는 개인키를 절대 보관하지 않는다 (클라이언트 IndexedDB에 저장).
//  - 서버는 암호문, 암호화된 AES 키, IV, 서명만 저장/중계한다.

import express from 'express';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { initStore, getStore } from './store.js';
import {
  hashPassword,
  verifyPassword,
  issueToken,
  requireAuth,
  requireAdmin,
} from './auth.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

// 사용자명 검증: 3~20자 영문/숫자/언더스코어
function validUsername(u) {
  return typeof u === 'string' && /^[A-Za-z0-9_]{3,20}$/.test(u);
}

// ---------------------------------------------------------------------------
// 인증
// ---------------------------------------------------------------------------

// 회원가입 + 공개키 등록 (한 번에 처리)
app.post('/api/auth/register', async (req, res) => {
  const { username, password, encPubkey, sigPubkey } = req.body || {};
  if (!validUsername(username)) {
    return res.status(400).json({ error: '사용자명은 3~20자의 영문/숫자/언더스코어여야 합니다.' });
  }
  if (typeof password !== 'string' || password.length < 4) {
    return res.status(400).json({ error: '비밀번호는 4자 이상이어야 합니다.' });
  }
  if (!encPubkey || !sigPubkey) {
    return res.status(400).json({ error: '공개키(암호화/서명)가 필요합니다.' });
  }

  const store = getStore();
  if (await store.getUserByUsername(username)) {
    return res.status(409).json({ error: '이미 존재하는 사용자명입니다.' });
  }

  // 첫 번째로 가입한 사용자를 자동으로 관리자로 지정한다.
  const isFirstUser = (await store.countUsers()) === 0;

  const hash = await hashPassword(password);
  const id = await store.createUser(username, hash, new Date().toISOString(), isFirstUser ? 1 : 0);
  await store.setPublicKeys(id, encPubkey, sigPubkey);

  const user = await store.getUserById(id);
  const token = issueToken(user);
  return res.status(201).json({
    token,
    user: { id: user.id, username: user.username, isAdmin: Boolean(user.is_admin) },
  });
});

// 로그인 + JWT 발급
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: '사용자명과 비밀번호가 필요합니다.' });
  }
  const store = getStore();
  const user = await store.getUserByUsername(username);
  if (!user) {
    return res.status(401).json({ error: '사용자명 또는 비밀번호가 올바르지 않습니다.' });
  }
  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) {
    return res.status(401).json({ error: '사용자명 또는 비밀번호가 올바르지 않습니다.' });
  }
  const token = issueToken(user);
  return res.json({
    token,
    user: { id: user.id, username: user.username, isAdmin: Boolean(user.is_admin) },
    hasKeys: Boolean(user.enc_pubkey && user.sig_pubkey),
  });
});

// 로그인된 사용자가 공개키를 (재)등록 — 다른 기기에서 새 키쌍을 만들 때 사용
app.put('/api/keys', requireAuth, async (req, res) => {
  const { encPubkey, sigPubkey } = req.body || {};
  if (!encPubkey || !sigPubkey) {
    return res.status(400).json({ error: '공개키(암호화/서명)가 필요합니다.' });
  }
  const store = getStore();
  await store.setPublicKeys(req.user.id, encPubkey, sigPubkey);
  return res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// 사용자 / 공개키 조회
// ---------------------------------------------------------------------------

// 자신을 제외한 사용자 목록 (메시지 보낼 상대 선택용)
app.get('/api/users', requireAuth, async (req, res) => {
  const store = getStore();
  const users = await store.listUsers(req.user.id);
  return res.json({ users });
});

// 특정 사용자의 공개키 조회 (암호화/서명검증에 필요)
app.get('/api/users/:id/pubkey', requireAuth, async (req, res) => {
  const store = getStore();
  const target = await store.getUserById(Number(req.params.id));
  if (!target) {
    return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
  }
  return res.json({
    id: target.id,
    username: target.username,
    encPubkey: target.enc_pubkey,
    sigPubkey: target.sig_pubkey,
  });
});

// ---------------------------------------------------------------------------
// 메시지
// ---------------------------------------------------------------------------

// 메시지 전송: 암호문 + 암호화된 키 + IV + 서명을 저장
app.post('/api/messages', requireAuth, async (req, res) => {
  const { receiverId, encKey, iv, ciphertext, signature } = req.body || {};
  if (
    receiverId == null ||
    !encKey ||
    !iv ||
    !ciphertext ||
    !signature
  ) {
    return res.status(400).json({ error: '메시지 필드가 누락되었습니다.' });
  }
  const store = getStore();
  const receiver = await store.getUserById(Number(receiverId));
  if (!receiver) {
    return res.status(404).json({ error: '수신자를 찾을 수 없습니다.' });
  }
  const id = await store.createMessage({
    senderId: req.user.id,
    receiverId: Number(receiverId),
    encKey,
    iv,
    ciphertext,
    signature,
    createdAt: new Date().toISOString(),
  });
  return res.status(201).json({ id });
});

// 받은 메시지함 — 송신자 정보와 송신자 서명 공개키를 함께 내려준다
app.get('/api/messages/inbox', requireAuth, async (req, res) => {
  const store = getStore();
  const rows = await store.getInbox(req.user.id);
  // 각 메시지마다 송신자 정보를 비동기로 조회하므로 Promise.all 로 모은다.
  const out = await Promise.all(rows.map(async (m) => {
    const sender = await store.getUserById(m.sender_id);
    return {
      id: m.id,
      senderId: m.sender_id,
      senderName: sender ? sender.username : '(알 수 없음)',
      senderSigPubkey: sender ? sender.sig_pubkey : null,
      encKey: m.enc_key,
      iv: m.iv,
      ciphertext: m.ciphertext,
      signature: m.signature,
      createdAt: m.created_at,
    };
  }));
  return res.json({ messages: out });
});

// 보낸 메시지함
app.get('/api/messages/sent', requireAuth, async (req, res) => {
  const store = getStore();
  const rows = await store.getSent(req.user.id);
  const out = await Promise.all(rows.map(async (m) => {
    const receiver = await store.getUserById(m.receiver_id);
    return {
      id: m.id,
      receiverId: m.receiver_id,
      receiverName: receiver ? receiver.username : '(알 수 없음)',
      createdAt: m.created_at,
    };
  }));
  return res.json({ messages: out });
});

// ---------------------------------------------------------------------------
// 관리자 전용
// ---------------------------------------------------------------------------

// 현재 로그인한 사용자가 관리자인지 확인 (프론트에서 관리 패널 표시 여부 판단)
app.get('/api/admin/check', requireAuth, async (req, res) => {
  const store = getStore();
  const user = await store.getUserById(req.user.id);
  return res.json({ isAdmin: Boolean(user && user.is_admin) });
});

// 전체 사용자 목록 + 메시지 통계 (관리자만)
app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const store = getStore();
  return res.json({ users: await store.listAllUsers() });
});

// 사용자 삭제 (관리자만). 해당 사용자의 메시지도 함께 삭제된다.
app.delete('/api/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const store = getStore();
  const targetId = Number(req.params.id);
  const target = await store.getUserById(targetId);
  if (!target) {
    return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
  }
  // 관리자가 자기 자신을 삭제하는 것은 막는다 (관리자 부재 방지).
  if (targetId === req.user.id) {
    return res.status(400).json({ error: '자기 자신은 삭제할 수 없습니다.' });
  }
  await store.deleteUser(targetId);
  return res.json({ ok: true });
});

// 헬스체크
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// ---------------------------------------------------------------------------
// 서버 시작
// ---------------------------------------------------------------------------
async function main() {
  await initStore();
  // 호스트를 0.0.0.0으로 명시한다. 클라우드 호스팅(Render 등)은 공개 접속을
  // 위해 0.0.0.0 바인딩을 요구한다. 로컬에서는 localhost로 접속하면 된다.
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[server] 포트 ${PORT} 에서 실행 중 (로컬: http://localhost:${PORT})`);
  });
}

// 이 파일을 직접 실행할 때만 서버를 띄운다.
// 테스트에서 import할 때는 app 객체만 가져가고 main()은 돌지 않는다.
// pathToFileURL을 쓰면 Windows(file:///C:/...)와 Linux/macOS 경로를 모두
// 올바르게 비교할 수 있다.
const isDirectRun = import.meta.url === pathToFileURL(process.argv[1] || '').href;

if (isDirectRun) {
  main().catch((err) => {
    console.error('서버 시작 실패:', err);
    process.exit(1);
  });
}

export default app;

// ===========================================================================
// 단체방 API
// ===========================================================================

// 단체방 생성
app.post('/api/groups', requireAuth, async (req, res) => {
  const { name, memberIds } = req.body || {};
  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    return res.status(400).json({ error: '방 이름을 입력해주세요.' });
  }
  if (!Array.isArray(memberIds) || memberIds.length === 0) {
    return res.status(400).json({ error: '멤버를 1명 이상 선택해야 합니다.' });
  }
  const store = getStore();
  const id = await store.createGroup(
    name.trim(),
    req.user.id,
    new Date().toISOString(),
    memberIds.map(Number)
  );
  return res.status(201).json({ id });
});

// 내가 속한 단체방 목록
app.get('/api/groups', requireAuth, async (req, res) => {
  const store = getStore();
  const groups = await store.listGroupsForUser(req.user.id);
  const out = await Promise.all(groups.map(async (g) => {
    const members = await store.getGroupMembers(g.id);
    return { id: g.id, name: g.name, createdBy: g.created_by, createdAt: g.created_at, members };
  }));
  return res.json({ groups: out });
});

// 단체방 멤버 조회 (암호화용 공개키 포함)
app.get('/api/groups/:id/members', requireAuth, async (req, res) => {
  const store = getStore();
  const groupId = Number(req.params.id);
  if (!(await store.isGroupMember(groupId, req.user.id))) {
    return res.status(403).json({ error: '이 방의 멤버가 아닙니다.' });
  }
  const members = await store.getGroupMembers(groupId);
  return res.json({ members });
});

// 단체방 메시지 전송
app.post('/api/groups/:id/messages', requireAuth, async (req, res) => {
  const store = getStore();
  const groupId = Number(req.params.id);
  if (!(await store.isGroupMember(groupId, req.user.id))) {
    return res.status(403).json({ error: '이 방의 멤버가 아닙니다.' });
  }
  const { iv, ciphertext, signature, memberKeys } = req.body || {};
  if (!iv || !ciphertext || !signature || !Array.isArray(memberKeys) || memberKeys.length === 0) {
    return res.status(400).json({ error: '메시지 필드가 누락되었습니다.' });
  }
  const id = await store.createGroupMessage(
    groupId,
    req.user.id,
    iv,
    ciphertext,
    signature,
    new Date().toISOString(),
    memberKeys
  );
  return res.status(201).json({ id });
});

// 단체방 메시지 조회
app.get('/api/groups/:id/messages', requireAuth, async (req, res) => {
  const store = getStore();
  const groupId = Number(req.params.id);
  if (!(await store.isGroupMember(groupId, req.user.id))) {
    return res.status(403).json({ error: '이 방의 멤버가 아닙니다.' });
  }
  const rows = await store.getGroupMessages(groupId, req.user.id);
  const out = await Promise.all(rows.map(async (m) => {
    const sender = await store.getUserById(m.sender_id);
    return {
      id: m.id,
      senderId: m.sender_id,
      senderName: sender ? sender.username : '(알 수 없음)',
      senderSigPubkey: sender ? sender.sig_pubkey : null,
      iv: m.iv,
      ciphertext: m.ciphertext,
      signature: m.signature,
      encKey: m.enc_key,
      createdAt: m.created_at,
    };
  }));
  return res.json({ messages: out });
});

// [추가] 단체방 나가기
app.delete('/api/groups/:id/leave', requireAuth, async (req, res) => {
  const store = getStore();
  const groupId = Number(req.params.id);
  if (!(await store.isGroupMember(groupId, req.user.id))) {
    return res.status(403).json({ error: '이 방의 멤버가 아닙니다.' });
  }
  await store.leaveGroup(groupId, req.user.id);
  return res.json({ ok: true });
});
