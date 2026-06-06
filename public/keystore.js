// public/keystore.js
// 개인키를 브라우저 IndexedDB에 보관한다.
// 개인키는 절대 서버로 전송되지 않으며, 이 브라우저에만 존재한다.
// 사용자명별로 { encPrivJwk, sigPrivJwk } 한 묶음을 저장한다.

const DB_NAME = 'secure-messenger-keys';
const STORE = 'privkeys';
const VERSION = 1;

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { keyPath: 'username' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

// 개인키 묶음 저장 (JWK 객체 형태로)
export async function savePrivateKeys(username, encPrivJwk, sigPrivJwk) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put({ username, encPrivJwk, sigPrivJwk });
    tx.oncomplete = () => resolve(true);
    tx.onerror = () => reject(tx.error);
  });
}

// 개인키 묶음 조회 (없으면 null)
export async function loadPrivateKeys(username) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readonly');
    const req = tx.objectStore(STORE).get(username);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

// 개인키 존재 여부
export async function hasPrivateKeys(username) {
  const keys = await loadPrivateKeys(username);
  return Boolean(keys);
}
