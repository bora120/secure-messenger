// test/security.test.js
// crypto.js 보안 기능 검증.
// Node 22의 WebCrypto 전역(crypto.subtle, btoa/atob)을 그대로 사용하므로
// 브라우저용 crypto.js를 수정 없이 import할 수 있다.
//
// 검증 시나리오 (계획서의 테스트 요구사항과 일치):
//   1. 정상 메시지 송수신 -> 복호화 성공 + 서명 검증 성공
//   2. 메시지(암호문) 변조 -> 복호화 단계에서 실패
//   3. 서명 변조 -> 복호화는 되지만 서명 검증 실패
//   4. 잘못된 키로 복호화 시도 -> 복호화 실패

import assert from 'node:assert';
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

function corruptB64(b64) {
  // base64 문자열의 중간 바이트 하나를 바꿔 변조를 시뮬레이션
  const buf = Buffer.from(b64, 'base64');
  const mid = Math.floor(buf.length / 2);
  buf[mid] = buf[mid] ^ 0xff;
  return buf.toString('base64');
}

async function run() {
  console.log('\n보안 기능 테스트\n');

  // --- 키쌍 준비: Alice(송신자), Bob(수신자) ---
  const aliceSig = await generateSigningKeyPair();
  const bobEnc = await generateEncryptionKeyPair();

  // 키 export/import 왕복 (실제 앱처럼 JWK 직렬화를 거친 키를 사용)
  const bobEncPubStr = await exportPublicKey(bobEnc.publicKey);
  const bobEncPub = await importEncPublicKey(bobEncPubStr);

  const aliceSigPubStr = await exportPublicKey(aliceSig.publicKey);
  const aliceSigPub = await importSigPublicKey(aliceSigPubStr);

  const bobEncPrivJwk = await exportKeyJwk(bobEnc.privateKey);
  const bobEncPriv = await importEncPrivateKey(bobEncPrivJwk);

  const aliceSigPrivJwk = await exportKeyJwk(aliceSig.privateKey);
  const aliceSigPriv = await importSigPrivateKey(aliceSigPrivJwk);

  const original = '안녕하세요 Bob, 이건 비밀 메시지입니다. 🔐 secret-123';
  const ALICE = 1, BOB = 2; // 송신자/수신자 ID (서명에 묶임)

  // --- 시나리오 1: 정상 송수신 ---
  await test('정상 메시지: 복호화 성공 + 서명 검증 성공', async () => {
    const payload = await encryptMessage(original, bobEncPub, aliceSigPriv, ALICE, BOB);
    const { plaintext, verified } = await decryptMessage(payload, bobEncPriv, aliceSigPub, ALICE, BOB);
    assert.strictEqual(plaintext, original, '복호화된 평문이 원문과 일치해야 함');
    assert.strictEqual(verified, true, '서명 검증이 통과해야 함');
  });

  // --- 시나리오 2: 암호문 변조 ---
  await test('암호문 변조: 복호화 단계에서 실패해야 함', async () => {
    const payload = await encryptMessage(original, bobEncPub, aliceSigPriv, ALICE, BOB);
    payload.ciphertext = corruptB64(payload.ciphertext);
    let threw = false;
    try {
      await decryptMessage(payload, bobEncPriv, aliceSigPub, ALICE, BOB);
    } catch {
      threw = true;
    }
    assert.strictEqual(threw, true, 'AES-GCM 인증 태그 불일치로 예외가 발생해야 함');
  });

  // --- 시나리오 3: 서명 변조 ---
  await test('서명 변조: 복호화는 되지만 검증은 실패해야 함', async () => {
    const payload = await encryptMessage(original, bobEncPub, aliceSigPriv, ALICE, BOB);
    payload.signature = corruptB64(payload.signature);
    const { plaintext, verified } = await decryptMessage(payload, bobEncPriv, aliceSigPub, ALICE, BOB);
    assert.strictEqual(plaintext, original, '본문은 정상 복호화되어야 함');
    assert.strictEqual(verified, false, '서명 검증은 실패해야 함');
  });

  // --- 시나리오 4: 잘못된 키로 복호화 ---
  await test('잘못된 개인키로 복호화: 실패해야 함', async () => {
    const payload = await encryptMessage(original, bobEncPub, aliceSigPriv, ALICE, BOB);
    // Bob이 아닌 제3자(Eve)의 개인키
    const eveEnc = await generateEncryptionKeyPair();
    const eveEncPrivJwk = await exportKeyJwk(eveEnc.privateKey);
    const eveEncPriv = await importEncPrivateKey(eveEncPrivJwk);
    let threw = false;
    try {
      await decryptMessage(payload, eveEncPriv, aliceSigPub, ALICE, BOB);
    } catch {
      threw = true;
    }
    assert.strictEqual(threw, true, '엉뚱한 키로는 AES 키 복호화가 실패해야 함');
  });

  // --- 시나리오 5: 위조된 송신자 (다른 사람이 서명) ---
  await test('위조 서명자: 다른 송신자 공개키로 검증 시 실패해야 함', async () => {
    const payload = await encryptMessage(original, bobEncPub, aliceSigPriv, ALICE, BOB);
    // Mallory가 Alice인 척하지만 검증은 Mallory의 공개키로
    const malSig = await generateSigningKeyPair();
    const malSigPubStr = await exportPublicKey(malSig.publicKey);
    const malSigPub = await importSigPublicKey(malSigPubStr);
    const { verified } = await decryptMessage(payload, bobEncPriv, malSigPub, ALICE, BOB);
    assert.strictEqual(verified, false, '서명자 불일치로 검증이 실패해야 함');
  });

  // --- 시나리오 6: 재전송/대상 변경 공격 방어 ---
  await test('수신자 바꿔치기: 서명에 묶인 ID가 달라 검증 실패', async () => {
    // Alice가 Bob(2)에게 보낸 메시지를, 공격자가 수신자를 Carol(3)로 바꿔
    // 재전송했다고 가정. 본문 복호화는 Bob 키로 되더라도 서명 검증은
    // ID가 안 맞아 실패해야 한다.
    const payload = await encryptMessage(original, bobEncPub, aliceSigPriv, ALICE, BOB);
    const CAROL = 3;
    const { verified } = await decryptMessage(payload, bobEncPriv, aliceSigPub, ALICE, CAROL);
    assert.strictEqual(verified, false, '수신자 ID 불일치로 검증이 실패해야 함');
  });

  console.log(`\n결과: ${passed} 통과, ${failed} 실패\n`);
  if (failed > 0) process.exit(1);
}

run().catch((err) => {
  console.error('테스트 실행 오류:', err);
  process.exit(1);
});
