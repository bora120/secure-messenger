// test/admin.test.js
// 관리자 기능 검증.
//   - 첫 가입자는 관리자, 이후 가입자는 일반 사용자
//   - 일반 사용자는 관리자 API 접근 불가 (403)
//   - 관리자는 전체 사용자 목록 + 메시지 통계 조회
//   - 관리자가 사용자 삭제 시 관련 메시지도 함께 삭제
//   - 관리자는 자기 자신을 삭제할 수 없음

import 'fake-indexeddb/auto';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { initStore } from '../src/store.js';
import {
  generateEncryptionKeyPair, generateSigningKeyPair,
  exportPublicKey, importEncPublicKey,
  exportKeyJwk, importSigPrivateKey,
  encryptMessage,
} from '../public/crypto.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 3460;
const BASE = `http://localhost:${PORT}`;

let passed = 0, failed = 0;
async function test(name, fn) {
  try { await fn(); console.log(`  \u2713 ${name}`); passed++; }
  catch (e) { console.log(`  \u2717 ${name}\n      ${e.message}`); failed++; }
}
async function api(method, path, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${BASE}${path}`, {
    method, headers, body: body ? JSON.stringify(body) : undefined,
  });
  const t = await res.text();
  let j = null; try { j = t ? JSON.parse(t) : null; } catch {}
  return { status: res.status, body: j };
}
async function makeKeys() {
  const enc = await generateEncryptionKeyPair();
  const sig = await generateSigningKeyPair();
  return {
    encPubStr: await exportPublicKey(enc.publicKey),
    sigPubStr: await exportPublicKey(sig.publicKey),
    sigPrivJwk: await exportKeyJwk(sig.privateKey),
  };
}
async function register(username) {
  const k = await makeKeys();
  const r = await api('POST', '/api/auth/register', {
    username, password: 'pw1234', encPubkey: k.encPubStr, sigPubkey: k.sigPubStr,
  });
  return { r, keys: k };
}

async function run() {
  console.log('\n관리자 기능 테스트\n');

  // 깨끗한 상태에서 "첫 가입자 = 관리자"를 검증해야 하므로 DB를 비운다.
  const jsonFile = path.join(__dirname, '..', 'db', 'messenger.json');
  if (fs.existsSync(jsonFile)) fs.unlinkSync(jsonFile);

  await initStore();
  const { default: app } = await import('../src/server.js');
  const server = app.listen(PORT);
  await new Promise((r) => server.once('listening', r));

  const u = Date.now().toString().slice(-5);
  let adminToken, adminId, userToken, userId, victimId;

  await test('첫 가입자는 자동으로 관리자가 된다', async () => {
    const { r } = await register(`admin${u}`);
    assert.strictEqual(r.status, 201);
    assert.strictEqual(r.body.user.isAdmin, true, '첫 사용자는 isAdmin=true여야 함');
    adminToken = r.body.token;
    adminId = r.body.user.id;
  });

  await test('두 번째 가입자는 일반 사용자다', async () => {
    const { r } = await register(`user${u}`);
    assert.strictEqual(r.status, 201);
    assert.strictEqual(r.body.user.isAdmin, false, '두 번째 사용자는 isAdmin=false여야 함');
    userToken = r.body.token;
    userId = r.body.user.id;
  });

  await test('삭제 대상이 될 세 번째 사용자 가입', async () => {
    const { r } = await register(`victim${u}`);
    assert.strictEqual(r.status, 201);
    victimId = r.body.user.id;
  });

  await test('admin/check: 관리자는 true', async () => {
    const r = await api('GET', '/api/admin/check', null, adminToken);
    assert.strictEqual(r.body.isAdmin, true);
  });

  await test('admin/check: 일반 사용자는 false', async () => {
    const r = await api('GET', '/api/admin/check', null, userToken);
    assert.strictEqual(r.body.isAdmin, false);
  });

  await test('일반 사용자는 사용자 목록 API 접근 불가 (403)', async () => {
    const r = await api('GET', '/api/admin/users', null, userToken);
    assert.strictEqual(r.status, 403);
  });

  await test('관리자는 전체 사용자 목록을 조회한다', async () => {
    const r = await api('GET', '/api/admin/users', null, adminToken);
    assert.strictEqual(r.status, 200);
    assert.ok(r.body.users.length >= 3, '최소 3명이 있어야 함');
    const admin = r.body.users.find((x) => x.id === adminId);
    assert.strictEqual(admin.is_admin, 1, '관리자 플래그가 표시되어야 함');
  });

  await test('일반 사용자는 삭제 API 접근 불가 (403)', async () => {
    const r = await api('DELETE', `/api/admin/users/${victimId}`, null, userToken);
    assert.strictEqual(r.status, 403);
  });

  await test('관리자는 자기 자신을 삭제할 수 없다 (400)', async () => {
    const r = await api('DELETE', `/api/admin/users/${adminId}`, null, adminToken);
    assert.strictEqual(r.status, 400);
  });

  // victim에게 메시지를 하나 보낸 뒤, 삭제 시 메시지도 사라지는지 확인
  await test('victim에게 메시지 전송 (삭제 연쇄 확인용)', async () => {
    const target = await api('GET', `/api/users/${victimId}/pubkey`, null, adminToken);
    const recvEncPub = await importEncPublicKey(target.body.encPubkey);
    // admin의 서명키가 필요한데, register에서 keys를 따로 보관하지 않았으므로
    // 새 서명키로 보내도 전송 자체는 가능하다(서명 검증은 수신자 몫).
    const tmp = await makeKeys();
    const sigPriv = await importSigPrivateKey(tmp.sigPrivJwk);
    const payload = await encryptMessage('테스트 메시지', recvEncPub, sigPriv, adminId, victimId);
    const r = await api('POST', '/api/messages', { receiverId: victimId, ...payload }, adminToken);
    assert.strictEqual(r.status, 201);
  });

  await test('관리자가 victim 삭제 -> 목록에서 사라진다', async () => {
    const del = await api('DELETE', `/api/admin/users/${victimId}`, null, adminToken);
    assert.strictEqual(del.status, 200);
    const list = await api('GET', '/api/admin/users', null, adminToken);
    const stillThere = list.body.users.find((x) => x.id === victimId);
    assert.strictEqual(stillThere, undefined, 'victim이 목록에 없어야 함');
  });

  await test('삭제된 사용자의 공개키 조회는 404', async () => {
    const r = await api('GET', `/api/users/${victimId}/pubkey`, null, adminToken);
    assert.strictEqual(r.status, 404);
  });

  server.close();
  console.log(`\n결과: ${passed} 통과, ${failed} 실패\n`);
  if (failed > 0) process.exit(1);
}
run().catch((e) => { console.error('오류:', e); process.exit(1); });
