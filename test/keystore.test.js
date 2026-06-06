// test/keystore.test.js
// keystore.js (IndexedDB 개인키 저장)를 fake-indexeddb로 검증한다.
// 브라우저 없이 IndexedDB API를 순수 JS로 구현한 polyfill을 전역에 주입한다.

import 'fake-indexeddb/auto';
import assert from 'node:assert';
import {
  savePrivateKeys,
  loadPrivateKeys,
  hasPrivateKeys,
} from '../public/keystore.js';
import {
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  exportKeyJwk,
  importEncPrivateKey,
  importSigPrivateKey,
} from '../public/crypto.js';

let passed = 0, failed = 0;
async function test(name, fn) {
  try { await fn(); console.log(`  \u2713 ${name}`); passed++; }
  catch (e) { console.log(`  \u2717 ${name}\n      ${e.message}`); failed++; }
}

async function run() {
  console.log('\nIndexedDB 키 저장소 테스트\n');

  await test('가입 전에는 개인키가 없다', async () => {
    const exists = await hasPrivateKeys('charlie');
    assert.strictEqual(exists, false);
  });

  await test('개인키 저장 후 존재한다', async () => {
    const enc = await generateEncryptionKeyPair();
    const sig = await generateSigningKeyPair();
    await savePrivateKeys(
      'charlie',
      await exportKeyJwk(enc.privateKey),
      await exportKeyJwk(sig.privateKey)
    );
    const exists = await hasPrivateKeys('charlie');
    assert.strictEqual(exists, true);
  });

  await test('저장한 개인키를 다시 CryptoKey로 복원할 수 있다', async () => {
    const keys = await loadPrivateKeys('charlie');
    assert.ok(keys, '키 묶음이 조회되어야 함');
    const encPriv = await importEncPrivateKey(keys.encPrivJwk);
    const sigPriv = await importSigPrivateKey(keys.sigPrivJwk);
    assert.strictEqual(encPriv.type, 'private');
    assert.strictEqual(sigPriv.type, 'private');
  });

  await test('사용자별로 키가 분리된다', async () => {
    const enc = await generateEncryptionKeyPair();
    const sig = await generateSigningKeyPair();
    await savePrivateKeys(
      'dana',
      await exportKeyJwk(enc.privateKey),
      await exportKeyJwk(sig.privateKey)
    );
    const c = await loadPrivateKeys('charlie');
    const d = await loadPrivateKeys('dana');
    assert.notDeepStrictEqual(c.encPrivJwk, d.encPrivJwk, '서로 다른 키여야 함');
  });

  console.log(`\n결과: ${passed} 통과, ${failed} 실패\n`);
  if (failed > 0) process.exit(1);
}
run().catch((e) => { console.error(e); process.exit(1); });
