// test/fullflow.test.js
// app.js가 브라우저에서 수행하는 전체 사용자 시나리오를 그대로 재현한다.
//   - fake-indexeddb로 개인키 로컬 저장 재현
//   - WebCrypto로 실제 키 생성/암호화/서명
//   - 실제 HTTP 서버와 통신
//
// 두 사용자(Alice, Bob)가 각자 다른 "브라우저"(별도 IndexedDB 네임스페이스를
// 흉내내기 위해 사용자명으로 분리)를 쓴다고 가정한다.

import 'fake-indexeddb/auto';
import assert from 'node:assert';
import { initStore } from '../src/store.js';
import { savePrivateKeys, loadPrivateKeys } from '../public/keystore.js';
import {
  generateEncryptionKeyPair, generateSigningKeyPair,
  exportPublicKey, importEncPublicKey, importSigPublicKey,
  exportKeyJwk, importEncPrivateKey, importSigPrivateKey,
  encryptMessage, decryptMessage,
} from '../public/crypto.js';

const PORT = 3459;
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
  if (!res.ok) throw new Error((j && j.error) || `HTTP ${res.status}`);
  return j;
}

// 브라우저에서의 "회원가입" 동작을 그대로 재현
async function registerLikeBrowser(username, password) {
  const enc = await generateEncryptionKeyPair();
  const sig = await generateSigningKeyPair();
  const r = await api('POST', '/api/auth/register', {
    username, password,
    encPubkey: await exportPublicKey(enc.publicKey),
    sigPubkey: await exportPublicKey(sig.publicKey),
  });
  // 개인키는 로컬(IndexedDB)에만 저장 — 서버 전송 안 함
  await savePrivateKeys(username,
    await exportKeyJwk(enc.privateKey),
    await exportKeyJwk(sig.privateKey));
  return r;
}

async function run() {
  console.log('\n전체 흐름 시뮬레이션 (서버 + WebCrypto + IndexedDB)\n');
  await initStore();
  const { default: app } = await import('../src/server.js');
  const server = app.listen(PORT);
  await new Promise((r) => server.once('listening', r));

  const u = Date.now().toString().slice(-5);
  const aliceName = `alice${u}`, bobName = `bob${u}`;
  let alice, bob;

  await test('Alice/Bob 가입 — 개인키는 로컬에만 저장', async () => {
    alice = await registerLikeBrowser(aliceName, 'pw1234');
    bob = await registerLikeBrowser(bobName, 'pw5678');
    assert.ok(alice.token && bob.token);
  });

  await test('서버 DB에는 개인키가 저장되어 있지 않다', async () => {
    // 공개키 조회 시 개인키 필드가 전혀 없어야 함
    const r = await api('GET', `/api/users/${bob.user.id}/pubkey`, null, alice.token);
    const blob = JSON.stringify(r).toLowerCase();
    assert.ok(!blob.includes('"d"'), 'JWK 개인 지수 d가 노출되면 안 됨');
    assert.ok(r.encPubkey && r.sigPubkey, '공개키는 있어야 함');
  });

  const secret = '내일 오후 3시 정기 회의 잊지 마세요. 자료는 공유폴더에 있습니다.';

  await test('Alice가 Bob에게 암호화+서명 전송 (브라우저 동작 재현)', async () => {
    const myKeys = await loadPrivateKeys(aliceName);
    const sigPriv = await importSigPrivateKey(myKeys.sigPrivJwk);
    const target = await api('GET', `/api/users/${bob.user.id}/pubkey`, null, alice.token);
    const recvEncPub = await importEncPublicKey(target.encPubkey);
    const payload = await encryptMessage(secret, recvEncPub, sigPriv, alice.user.id, bob.user.id);
    await api('POST', '/api/messages', { receiverId: bob.user.id, ...payload }, alice.token);
  });

  await test('Bob이 받은편지함에서 복호화 + 서명검증 (브라우저 동작 재현)', async () => {
    const { messages } = await api('GET', '/api/messages/inbox', null, bob.token);
    assert.ok(messages.length >= 1);
    const m = messages[0];
    const myKeys = await loadPrivateKeys(bobName);
    const encPriv = await importEncPrivateKey(myKeys.encPrivJwk);
    const senderSigPub = await importSigPublicKey(m.senderSigPubkey);
    const { plaintext, verified } = await decryptMessage(
      { encKey: m.encKey, iv: m.iv, ciphertext: m.ciphertext, signature: m.signature },
      encPriv, senderSigPub, m.senderId, bob.user.id);
    assert.strictEqual(plaintext, secret);
    assert.strictEqual(verified, true);
  });

  await test('변조된 메시지를 서버에서 받으면 Bob이 감지한다', async () => {
    // 공격자가 DB의 암호문을 바꾼 상황을 흉내: inbox 응답을 조작
    const { messages } = await api('GET', '/api/messages/inbox', null, bob.token);
    const m = { ...messages[0] };
    const buf = Buffer.from(m.ciphertext, 'base64');
    buf[Math.floor(buf.length / 2)] ^= 0xff;
    m.ciphertext = buf.toString('base64');

    const myKeys = await loadPrivateKeys(bobName);
    const encPriv = await importEncPrivateKey(myKeys.encPrivJwk);
    const senderSigPub = await importSigPublicKey(m.senderSigPubkey);

    let detected = false;
    try {
      await decryptMessage(
        { encKey: m.encKey, iv: m.iv, ciphertext: m.ciphertext, signature: m.signature },
        encPriv, senderSigPub, m.senderId, bob.user.id);
    } catch {
      detected = true; // GCM 인증 실패로 복호화 단계에서 잡힘
    }
    assert.strictEqual(detected, true, '변조가 감지되어야 함');
  });

  server.close();
  console.log(`\n결과: ${passed} 통과, ${failed} 실패\n`);
  if (failed > 0) process.exit(1);
}
run().catch((e) => { console.error('오류:', e); process.exit(1); });
