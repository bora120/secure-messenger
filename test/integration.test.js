// test/integration.test.js
// 서버를 같은 프로세스 안에서 띄우고 실제 HTTP 요청으로 전체 흐름을 검증한다.
//   회원가입(Alice, Bob) -> 로그인 -> 사용자/공개키 조회
//   -> Alice가 Bob에게 암호화+서명 메시지 전송
//   -> Bob 받은편지함 조회 -> 복호화 + 서명 검증
//
// crypto.js를 그대로 import하여 클라이언트와 동일한 암호화 경로를 사용한다.

import assert from 'node:assert';
import { initStore } from '../src/store.js';
import {
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  exportPublicKey,
  importEncPublicKey,
  importSigPublicKey,
  exportKeyJwk,
  importEncPrivateKey,
  importSigPrivateKey,
  encryptMessage,
  decryptMessage,
} from '../public/crypto.js';

const PORT = 3457;
const BASE = `http://localhost:${PORT}`;

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try {
    await fn();
    console.log(`  \u2713 ${name}`);
    passed++;
  } catch (err) {
    console.log(`  \u2717 ${name}`);
    console.log(`      ${err.message}`);
    failed++;
  }
}

async function api(method, path, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* leave null */ }
  return { status: res.status, body: json };
}

// 한 사용자에 대한 키 묶음을 만든다
async function makeKeys() {
  const encPair = await generateEncryptionKeyPair();
  const sigPair = await generateSigningKeyPair();
  return {
    encPair,
    sigPair,
    encPubStr: await exportPublicKey(encPair.publicKey),
    sigPubStr: await exportPublicKey(sigPair.publicKey),
    encPrivJwk: await exportKeyJwk(encPair.privateKey),
    sigPrivJwk: await exportKeyJwk(sigPair.privateKey),
  };
}

async function run() {
  console.log('\n통합 테스트 (실제 HTTP)\n');

  // 임시 DB 파일을 쓰도록 별도 디렉터리 지정은 생략 — 테스트 후 정리
  await initStore();
  const { default: app } = await import('../src/server.js');
  const server = app.listen(PORT);
  await new Promise((r) => server.once('listening', r));

  let aliceToken, bobToken, aliceId, bobId;
  const aliceKeys = await makeKeys();
  const bobKeys = await makeKeys();
  const uniq = Date.now().toString().slice(-6);
  const aliceName = `alice_${uniq}`;
  const bobName = `bob_${uniq}`;

  await test('Alice 회원가입 + 공개키 등록', async () => {
    const r = await api('POST', '/api/auth/register', {
      username: aliceName,
      password: 'pw1234',
      encPubkey: aliceKeys.encPubStr,
      sigPubkey: aliceKeys.sigPubStr,
    });
    assert.strictEqual(r.status, 201, `상태 201 기대, 실제 ${r.status}`);
    assert.ok(r.body.token, '토큰이 발급되어야 함');
    aliceToken = r.body.token;
    aliceId = r.body.user.id;
  });

  await test('Bob 회원가입 + 공개키 등록', async () => {
    const r = await api('POST', '/api/auth/register', {
      username: bobName,
      password: 'pw5678',
      encPubkey: bobKeys.encPubStr,
      sigPubkey: bobKeys.sigPubStr,
    });
    assert.strictEqual(r.status, 201);
    bobToken = r.body.token;
    bobId = r.body.user.id;
  });

  await test('중복 사용자명 거부', async () => {
    const r = await api('POST', '/api/auth/register', {
      username: aliceName,
      password: 'pw1234',
      encPubkey: aliceKeys.encPubStr,
      sigPubkey: aliceKeys.sigPubStr,
    });
    assert.strictEqual(r.status, 409, '중복 가입은 409여야 함');
  });

  await test('잘못된 비밀번호로 로그인 실패', async () => {
    const r = await api('POST', '/api/auth/login', {
      username: aliceName,
      password: 'wrong',
    });
    assert.strictEqual(r.status, 401);
  });

  await test('Alice 정상 로그인', async () => {
    const r = await api('POST', '/api/auth/login', {
      username: aliceName,
      password: 'pw1234',
    });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body.hasKeys, true, '키가 등록되어 있어야 함');
    aliceToken = r.body.token;
  });

  await test('인증 없이 보호된 API 접근 거부', async () => {
    const r = await api('GET', '/api/users', null, null);
    assert.strictEqual(r.status, 401);
  });

  await test('Alice가 사용자 목록 조회 (Bob 포함)', async () => {
    const r = await api('GET', '/api/users', null, aliceToken);
    assert.strictEqual(r.status, 200);
    const found = r.body.users.find((u) => u.id === bobId);
    assert.ok(found, '목록에 Bob이 있어야 함');
  });

  let bobEncPubForAlice;
  await test('Alice가 Bob의 공개키 조회', async () => {
    const r = await api('GET', `/api/users/${bobId}/pubkey`, null, aliceToken);
    assert.strictEqual(r.status, 200);
    assert.ok(r.body.encPubkey, '암호화 공개키가 있어야 함');
    bobEncPubForAlice = await importEncPublicKey(r.body.encPubkey);
  });

  const secret = '점심 같이 먹을래? 회의실 302호에서 보자. 🍱';
  await test('Alice -> Bob 암호화+서명 메시지 전송', async () => {
    const aliceSigPriv = await importSigPrivateKey(aliceKeys.sigPrivJwk);
    const payload = await encryptMessage(secret, bobEncPubForAlice, aliceSigPriv, aliceId, bobId);
    const r = await api('POST', '/api/messages', {
      receiverId: bobId,
      ...payload,
    }, aliceToken);
    assert.strictEqual(r.status, 201, `전송은 201이어야 함, 실제 ${r.status}`);
  });

  await test('Bob 받은편지함에서 메시지 복호화 + 서명 검증', async () => {
    const login = await api('POST', '/api/auth/login', { username: bobName, password: 'pw5678' });
    bobToken = login.body.token;

    const r = await api('GET', '/api/messages/inbox', null, bobToken);
    assert.strictEqual(r.status, 200);
    assert.ok(r.body.messages.length >= 1, '받은 메시지가 있어야 함');

    const msg = r.body.messages[0];
    const bobEncPriv = await importEncPrivateKey(bobKeys.encPrivJwk);
    const senderSigPub = await importSigPublicKey(msg.senderSigPubkey);

    const { plaintext, verified } = await decryptMessage(
      { encKey: msg.encKey, iv: msg.iv, ciphertext: msg.ciphertext, signature: msg.signature },
      bobEncPriv,
      senderSigPub,
      msg.senderId,
      bobId
    );
    assert.strictEqual(plaintext, secret, '복호화된 평문이 원문과 일치해야 함');
    assert.strictEqual(verified, true, '서명 검증이 통과해야 함');
    assert.strictEqual(msg.senderName, aliceName, '송신자명이 Alice여야 함');
  });

  await test('서버에 저장된 데이터는 평문을 포함하지 않음', async () => {
    const r = await api('GET', '/api/messages/inbox', null, bobToken);
    const msg = r.body.messages[0];
    const blob = JSON.stringify(msg);
    assert.ok(!blob.includes('점심'), '서버 응답(암호문)에 평문이 노출되면 안 됨');
  });

  server.close();
  console.log(`\n결과: ${passed} 통과, ${failed} 실패\n`);
  if (failed > 0) process.exit(1);
}

run().catch((err) => {
  console.error('통합 테스트 오류:', err);
  process.exit(1);
});
