// public/crypto.js
// 클라이언트 측 암호화 핵심 모듈 (브라우저 Web Crypto API 사용).
//
// 이 프로젝트의 보안은 전적으로 이 파일에 달려 있다.
//
// 키 구성 (사용자당 RSA 키쌍 2개):
//   1) 암호화용 키쌍  : RSA-OAEP (SHA-256)  — 메시지 기밀성
//   2) 서명용 키쌍    : RSA-PSS  (SHA-256)  — 무결성 + 송신자 인증
//
// 메시지 암호화 = 하이브리드 방식:
//   - RSA로 긴 메시지를 직접 암호화하면 키 길이 제한에 걸리므로,
//   - 임의의 AES-256-GCM 키로 본문을 암호화하고,
//   - 그 AES 키만 수신자의 RSA-OAEP 공개키로 암호화한다.
//
// 전자서명:
//   - 송신자는 평문(원문 바이트)에 대해 RSA-PSS 서명을 만든다.
//   - 수신자는 복호화로 평문을 복원한 뒤, 송신자 공개키로 서명을 검증한다.

const enc = new TextEncoder();
const dec = new TextDecoder();

// --- base64 <-> ArrayBuffer 변환 ------------------------------------------
function bufToB64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function b64ToBuf(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

// ===========================================================================
// 1. 키쌍 생성
// ===========================================================================

// 암호화용 RSA-OAEP 키쌍 생성 (2048비트)
export async function generateEncryptionKeyPair() {
  return crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true, // extractable: 개인키를 IndexedDB에 저장하려면 추출 가능해야 함
    ['encrypt', 'decrypt']
  );
}

// 서명용 RSA-PSS 키쌍 생성 (2048비트)
export async function generateSigningKeyPair() {
  return crypto.subtle.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify']
  );
}

// ===========================================================================
// 2. 키 내보내기 / 가져오기
// ===========================================================================

// 공개키 -> JWK 문자열 (서버에 저장)
export async function exportPublicKey(key) {
  const jwk = await crypto.subtle.exportKey('jwk', key);
  return JSON.stringify(jwk);
}

// JWK 문자열 -> 암호화용 공개키
export async function importEncPublicKey(jwkStr) {
  const jwk = JSON.parse(jwkStr);
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt']
  );
}

// JWK 문자열 -> 서명검증용 공개키
export async function importSigPublicKey(jwkStr) {
  const jwk = JSON.parse(jwkStr);
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSA-PSS', hash: 'SHA-256' },
    true,
    ['verify']
  );
}

// CryptoKey -> JWK 객체 (IndexedDB 저장용; 구조화 복제로도 저장 가능하나
// JWK로 통일하면 디버깅과 이식이 쉽다)
export async function exportKeyJwk(key) {
  return crypto.subtle.exportKey('jwk', key);
}

// JWK 객체 -> 암호화용 개인키
export async function importEncPrivateKey(jwk) {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['decrypt']
  );
}

// JWK 객체 -> 서명용 개인키
export async function importSigPrivateKey(jwk) {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSA-PSS', hash: 'SHA-256' },
    true,
    ['sign']
  );
}

// ===========================================================================
// 3. 메시지 암호화 (송신자 측)
// ===========================================================================
//
// 입력:
//   plaintext              : 보낼 평문 문자열
//   receiverEncPublicKey   : 수신자의 RSA-OAEP 공개키
//   senderSigPrivateKey    : 송신자의 RSA-PSS 개인키
//   senderId, receiverId   : 송신자/수신자 ID (서명에 함께 묶음)
// 출력 (모두 base64 문자열):
//   { encKey, iv, ciphertext, signature }
//
// 보안 강화: 서명 대상을 평문만이 아니라 "송신자ID|수신자ID|평문"으로 묶는다.
// 이렇게 하면 공격자가 암호문을 가로채 다른 사람에게 재전송(replay)하거나
// 송신자/수신자를 바꿔치기해도 서명 검증이 실패한다.

// 서명 대상 바이트를 만든다: "senderId|receiverId|" + 평문
function buildSigningPayload(senderId, receiverId, plaintextBytes) {
  const prefix = enc.encode(`${senderId}|${receiverId}|`);
  const combined = new Uint8Array(prefix.length + plaintextBytes.length);
  combined.set(prefix, 0);
  combined.set(plaintextBytes, prefix.length);
  return combined;
}

export async function encryptMessage(
  plaintext, receiverEncPublicKey, senderSigPrivateKey, senderId, receiverId
) {
  const data = enc.encode(plaintext);

  // (1) 1회용 AES-256-GCM 키 생성
  const aesKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  // (2) IV(12바이트) 생성 후 본문을 AES-GCM으로 암호화
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipherBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    data
  );

  // (3) AES 키를 raw로 추출하여 수신자 RSA-OAEP 공개키로 암호화
  const rawAes = await crypto.subtle.exportKey('raw', aesKey);
  const encKeyBuf = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    receiverEncPublicKey,
    rawAes
  );

  // (4) 전자서명 생성 (RSA-PSS) — 송신자/수신자 ID를 평문과 함께 서명
  const signingPayload = buildSigningPayload(senderId, receiverId, data);
  const sigBuf = await crypto.subtle.sign(
    { name: 'RSA-PSS', saltLength: 32 },
    senderSigPrivateKey,
    signingPayload
  );

  return {
    encKey: bufToB64(encKeyBuf),
    iv: bufToB64(iv.buffer),
    ciphertext: bufToB64(cipherBuf),
    signature: bufToB64(sigBuf),
  };
}

// ===========================================================================
// 4. 메시지 복호화 + 서명 검증 (수신자 측)
// ===========================================================================
//
// 입력:
//   payload               : { encKey, iv, ciphertext, signature } (base64)
//   receiverEncPrivateKey : 수신자의 RSA-OAEP 개인키
//   senderSigPublicKey    : 송신자의 RSA-PSS 공개키
//   senderId, receiverId  : 서명 검증에 사용할 송신자/수신자 ID
// 출력:
//   { plaintext, verified }
//   - plaintext : 복호화된 평문 (복호화 실패 시 예외 발생)
//   - verified  : 서명 검증 통과 여부 (true/false)

export async function decryptMessage(
  payload, receiverEncPrivateKey, senderSigPublicKey, senderId, receiverId
) {
  // (1) 암호화된 AES 키를 수신자 RSA-OAEP 개인키로 복호화
  const rawAes = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    receiverEncPrivateKey,
    b64ToBuf(payload.encKey)
  );

  // (2) AES 키 복원
  const aesKey = await crypto.subtle.importKey(
    'raw',
    rawAes,
    { name: 'AES-GCM', length: 256 },
    true,
    ['decrypt']
  );

  // (3) 본문 복호화 (변조되었으면 GCM 인증 태그 불일치로 여기서 예외 발생)
  const dataBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(b64ToBuf(payload.iv)) },
    aesKey,
    b64ToBuf(payload.ciphertext)
  );

  const plaintext = dec.decode(dataBuf);

  // (4) 서명 검증: "송신자ID|수신자ID|평문"에 대해 송신자 공개키로 확인.
  //     송신자가 없거나(senderSigPublicKey=null) ID가 안 맞으면 verified=false.
  let verified = false;
  if (senderSigPublicKey) {
    const signingPayload = buildSigningPayload(
      senderId, receiverId, new Uint8Array(dataBuf)
    );
    verified = await crypto.subtle.verify(
      { name: 'RSA-PSS', saltLength: 32 },
      senderSigPublicKey,
      b64ToBuf(payload.signature),
      signingPayload
    );
  }

  return { plaintext, verified };
}
