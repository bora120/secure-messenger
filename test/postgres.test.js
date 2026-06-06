// test/postgres.test.js
// store.js 의 PostgreSQL 백엔드(buildPgBackend)를 pglite 로 검증한다.
// pglite 는 실제 PostgreSQL 엔진(WASM)이므로, 여기서 통과하면
// 같은 SQL 이 Render PostgreSQL 등 실제 환경에서도 동작한다.
//
// pglite 를 pg 의 Pool 처럼 보이게 하는 얇은 어댑터를 씌운다:
//   - query(text, params) : 그대로 위임
//   - connect()           : 같은 연결을 감싼 client 를 반환 (BEGIN/COMMIT 용)

import assert from 'node:assert';
import { PGlite } from '@electric-sql/pglite';
import { buildPgBackend } from '../src/store.js';

let passed = 0, failed = 0;
async function test(name, fn) {
  try { await fn(); console.log(`  \u2713 ${name}`); passed++; }
  catch (e) { console.log(`  \u2717 ${name}\n      ${e.message}`); failed++; }
}

// pglite -> pg Pool 호환 어댑터
function makePool(db) {
  return {
    query: (text, params) => db.query(text, params),
    // pg 의 pool.connect() 흉내: 같은 db 를 쓰는 client 를 돌려준다.
    connect: async () => ({
      query: (text, params) => db.query(text, params),
      release: () => {},
    }),
  };
}

async function run() {
  console.log('\nPostgreSQL 백엔드 테스트 (pglite 엔진)\n');

  const db = new PGlite();
  const pool = makePool(db);
  const store = await buildPgBackend(pool);

  let aliceId, bobId, victimId;

  await test('백엔드 종류가 postgres 다', async () => {
    assert.strictEqual(store.kind, 'postgres');
  });

  await test('countUsers: 초기 0', async () => {
    assert.strictEqual(await store.countUsers(), 0);
  });

  await test('createUser + 첫 사용자 관리자', async () => {
    aliceId = await store.createUser('alice', 'hash1', new Date().toISOString(), 1);
    assert.ok(aliceId >= 1);
    const u = await store.getUserById(aliceId);
    assert.strictEqual(u.username, 'alice');
    assert.strictEqual(u.is_admin, 1);
  });

  await test('createUser: 두 번째 일반 사용자', async () => {
    bobId = await store.createUser('bob', 'hash2', new Date().toISOString(), 0);
    const u = await store.getUserById(bobId);
    assert.strictEqual(u.is_admin, 0);
  });

  await test('getUserByUsername', async () => {
    const u = await store.getUserByUsername('bob');
    assert.strictEqual(u.id, bobId);
  });

  await test('중복 username 은 DB 제약으로 거부된다', async () => {
    let threw = false;
    try {
      await store.createUser('alice', 'x', new Date().toISOString(), 0);
    } catch { threw = true; }
    assert.strictEqual(threw, true, 'UNIQUE 제약 위반이어야 함');
  });

  await test('setPublicKeys / 조회', async () => {
    await store.setPublicKeys(bobId, 'ENC_PUB', 'SIG_PUB');
    const u = await store.getUserById(bobId);
    assert.strictEqual(u.enc_pubkey, 'ENC_PUB');
    assert.strictEqual(u.sig_pubkey, 'SIG_PUB');
  });

  await test('listUsers: 자신 제외', async () => {
    const list = await store.listUsers(aliceId);
    assert.ok(list.find((u) => u.id === bobId));
    assert.ok(!list.find((u) => u.id === aliceId));
  });

  await test('createMessage + getInbox', async () => {
    await store.setPublicKeys(aliceId, 'A_ENC', 'A_SIG');
    await store.createMessage({
      senderId: aliceId, receiverId: bobId,
      encKey: 'k', iv: 'iv', ciphertext: 'c', signature: 's',
      createdAt: new Date().toISOString(),
    });
    const inbox = await store.getInbox(bobId);
    assert.strictEqual(inbox.length, 1);
    assert.strictEqual(inbox[0].sender_id, aliceId);
    assert.strictEqual(inbox[0].ciphertext, 'c');
  });

  await test('getSent', async () => {
    const sent = await store.getSent(aliceId);
    assert.strictEqual(sent.length, 1);
    assert.strictEqual(sent[0].receiver_id, bobId);
  });

  await test('listAllUsers: 통계 포함', async () => {
    const all = await store.listAllUsers();
    const alice = all.find((u) => u.id === aliceId);
    const bob = all.find((u) => u.id === bobId);
    assert.strictEqual(alice.sent_count, 1, 'alice 보낸 1');
    assert.strictEqual(bob.recv_count, 1, 'bob 받은 1');
  });

  await test('deleteUser: 트랜잭션으로 메시지까지 삭제', async () => {
    victimId = await store.createUser('victim', 'h', new Date().toISOString(), 0);
    await store.setPublicKeys(victimId, 'V_ENC', 'V_SIG');
    // alice -> victim 메시지 하나
    await store.createMessage({
      senderId: aliceId, receiverId: victimId,
      encKey: 'k', iv: 'iv', ciphertext: 'cc', signature: 'ss',
      createdAt: new Date().toISOString(),
    });
    // victim 삭제
    await store.deleteUser(victimId);
    const gone = await store.getUserById(victimId);
    assert.strictEqual(gone, null, 'victim 이 삭제되어야 함');
    // victim 이 받은 메시지도 사라져야 함 (alice 의 sent 에서 victim 행이 없어야)
    const sent = await store.getSent(aliceId);
    assert.ok(!sent.find((m) => m.receiver_id === victimId), 'victim 관련 메시지 삭제됨');
  });

  console.log(`\n결과: ${passed} 통과, ${failed} 실패\n`);
  if (failed > 0) process.exit(1);
}
run().catch((e) => { console.error('오류:', e); process.exit(1); });
