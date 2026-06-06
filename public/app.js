// public/app.js
// 프론트엔드 메인 로직: 인증, 키 관리, 메시지 송수신 UI 연결.

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
} from './crypto.js';

import {
  savePrivateKeys,
  loadPrivateKeys,
  hasPrivateKeys,
} from './keystore.js';

// --- 세션 상태 (메모리에만 보관; 토큰은 sessionStorage) ---
const state = {
  token: sessionStorage.getItem('token') || null,
  user: JSON.parse(sessionStorage.getItem('user') || 'null'),
};

const $ = (id) => document.getElementById(id);

// --- API 헬퍼 ---
async function api(method, path, body) {
  const headers = { 'Content-Type': 'application/json' };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const res = await fetch(`/api${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* ignore */ }
  if (!res.ok) {
    throw new Error((json && json.error) || `요청 실패 (${res.status})`);
  }
  return json;
}

function setSession(token, user) {
  state.token = token;
  state.user = user;
  sessionStorage.setItem('token', token);
  sessionStorage.setItem('user', JSON.stringify(user));
}

function clearSession() {
  state.token = null;
  state.user = null;
  sessionStorage.removeItem('token');
  sessionStorage.removeItem('user');
}

// --- 화면 전환 ---
function showAuth() {
  $('authView').classList.remove('hidden');
  $('messengerView').classList.add('hidden');
  $('session').classList.add('hidden');
}

async function showMessenger() {
  $('authView').classList.add('hidden');
  $('messengerView').classList.remove('hidden');
  $('session').classList.remove('hidden');
  $('me').textContent = `${state.user.username} 님`;

  // 개인키 존재 여부 확인
  const ok = await hasPrivateKeys(state.user.username);
  $('keyWarning').classList.toggle('hidden', ok);

  await loadRecipients();
  await loadInbox();
  await setupAdminPanel();
}

// 관리자면 관리 패널을 노출하고 사용자 목록을 불러온다.
async function setupAdminPanel() {
  try {
    const { isAdmin } = await api('GET', '/admin/check');
    $('adminPanel').classList.toggle('hidden', !isAdmin);
    if (isAdmin) await loadAdminUsers();
  } catch {
    $('adminPanel').classList.add('hidden');
  }
}

async function loadAdminUsers() {
  const list = $('adminUserList');
  list.innerHTML = '<p class="empty">불러오는 중...</p>';
  try {
    const { users } = await api('GET', '/admin/users');
    if (users.length === 0) {
      list.innerHTML = '<p class="empty">사용자가 없습니다.</p>';
      return;
    }
    list.innerHTML = '';
    for (const u of users) {
      const row = document.createElement('div');
      row.className = 'admin-row';

      const info = document.createElement('div');
      info.className = 'admin-info';
      const adminTag = u.is_admin ? ' <span class="badge ok">관리자</span>' : '';
      info.innerHTML =
        `<strong>${escapeHtml(u.username)}</strong>${adminTag}` +
        `<span class="admin-stats">ID ${u.id} · 보낸 ${u.sent_count} · 받은 ${u.recv_count}</span>`;
      row.appendChild(info);

      // 자기 자신은 삭제 버튼을 두지 않는다.
      if (u.id !== state.user.id) {
        const delBtn = document.createElement('button');
        delBtn.className = 'btn-danger';
        delBtn.textContent = '삭제';
        delBtn.addEventListener('click', () => deleteUser(u.id, u.username));
        row.appendChild(delBtn);
      } else {
        const meTag = document.createElement('span');
        meTag.className = 'admin-stats';
        meTag.textContent = '(나)';
        row.appendChild(meTag);
      }
      list.appendChild(row);
    }
  } catch (err) {
    list.innerHTML = `<p class="empty">오류: ${escapeHtml(err.message)}</p>`;
  }
}

async function deleteUser(id, username) {
  const confirmed = window.confirm(
    `정말 "${username}" 사용자를 삭제할까요?\n이 사용자가 주고받은 모든 메시지도 함께 삭제됩니다.`
  );
  if (!confirmed) return;
  try {
    await api('DELETE', `/admin/users/${id}`);
    await loadAdminUsers();
    await loadRecipients(); // 수신자 목록도 갱신
  } catch (err) {
    alert(`삭제 오류: ${err.message}`);
  }
}

// --- 인증 탭 전환 ---
$('tabLogin').addEventListener('click', () => {
  $('tabLogin').classList.add('active');
  $('tabRegister').classList.remove('active');
  $('loginForm').classList.remove('hidden');
  $('registerForm').classList.add('hidden');
  $('authMsg').textContent = '';
});
$('tabRegister').addEventListener('click', () => {
  $('tabRegister').classList.add('active');
  $('tabLogin').classList.remove('active');
  $('registerForm').classList.remove('hidden');
  $('loginForm').classList.add('hidden');
  $('authMsg').textContent = '';
});

// --- 회원가입: 키쌍 생성 -> 공개키만 서버 전송, 개인키는 로컬 저장 ---
$('registerForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = $('regUsername').value.trim();
  const password = $('regPassword').value;
  $('authMsg').textContent = '키쌍 생성 중...';

  try {
    const encPair = await generateEncryptionKeyPair();
    const sigPair = await generateSigningKeyPair();

    const encPubkey = await exportPublicKey(encPair.publicKey);
    const sigPubkey = await exportPublicKey(sigPair.publicKey);

    const result = await api('POST', '/auth/register', {
      username, password, encPubkey, sigPubkey,
    });

    // 개인키를 IndexedDB에 저장 (서버로는 전송하지 않음)
    const encPrivJwk = await exportKeyJwk(encPair.privateKey);
    const sigPrivJwk = await exportKeyJwk(sigPair.privateKey);
    await savePrivateKeys(username, encPrivJwk, sigPrivJwk);

    setSession(result.token, result.user);
    await showMessenger();
  } catch (err) {
    $('authMsg').textContent = `오류: ${err.message}`;
  }
});

// --- 로그인 ---
$('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = $('loginUsername').value.trim();
  const password = $('loginPassword').value;
  $('authMsg').textContent = '로그인 중...';
  try {
    const result = await api('POST', '/auth/login', { username, password });
    setSession(result.token, result.user);
    await showMessenger();
  } catch (err) {
    $('authMsg').textContent = `오류: ${err.message}`;
  }
});

// --- 로그아웃 ---
$('logoutBtn').addEventListener('click', () => {
  clearSession();
  showAuth();
});

// --- 새 키쌍 재생성 (개인키 분실 시) ---
$('regenKeysBtn').addEventListener('click', async () => {
  try {
    const encPair = await generateEncryptionKeyPair();
    const sigPair = await generateSigningKeyPair();
    const encPubkey = await exportPublicKey(encPair.publicKey);
    const sigPubkey = await exportPublicKey(sigPair.publicKey);
    await api('PUT', '/keys', { encPubkey, sigPubkey });
    await savePrivateKeys(
      state.user.username,
      await exportKeyJwk(encPair.privateKey),
      await exportKeyJwk(sigPair.privateKey)
    );
    $('keyWarning').classList.add('hidden');
    await loadInbox();
  } catch (err) {
    alert(`키 재생성 오류: ${err.message}`);
  }
});

// --- 수신자 목록 채우기 ---
async function loadRecipients() {
  try {
    const { users } = await api('GET', '/users');
    const sel = $('recipient');
    sel.innerHTML = '';
    if (users.length === 0) {
      const opt = document.createElement('option');
      opt.textContent = '(다른 사용자가 없습니다)';
      opt.value = '';
      sel.appendChild(opt);
      return;
    }
    for (const u of users) {
      const opt = document.createElement('option');
      opt.value = u.id;
      opt.textContent = u.username;
      opt.dataset.encPubkey = u.enc_pubkey || '';
      sel.appendChild(opt);
    }
  } catch (err) {
    $('sendMsg').textContent = `사용자 목록 오류: ${err.message}`;
  }
}

// --- 메시지 전송 ---
$('sendBtn').addEventListener('click', async () => {
  const sel = $('recipient');
  const receiverId = sel.value;
  const plaintext = $('messageBody').value.trim();
  $('sendMsg').textContent = '';

  if (!receiverId) { $('sendMsg').textContent = '받는 사람을 선택하세요.'; return; }
  if (!plaintext) { $('sendMsg').textContent = '메시지를 입력하세요.'; return; }

  try {
    // 내 서명 개인키 로드
    const myKeys = await loadPrivateKeys(state.user.username);
    if (!myKeys) {
      $('sendMsg').textContent = '이 브라우저에 개인키가 없어 서명할 수 없습니다.';
      return;
    }
    const sigPriv = await importSigPrivateKey(myKeys.sigPrivJwk);

    // 수신자 공개키 조회
    const target = await api('GET', `/users/${receiverId}/pubkey`);
    if (!target.encPubkey) {
      $('sendMsg').textContent = '수신자의 공개키가 등록되어 있지 않습니다.';
      return;
    }
    const recvEncPub = await importEncPublicKey(target.encPubkey);

    // 암호화 + 서명 (송신자=나, 수신자=상대 ID를 서명에 묶음)
    const payload = await encryptMessage(
      plaintext, recvEncPub, sigPriv, state.user.id, Number(receiverId)
    );

    await api('POST', '/messages', { receiverId: Number(receiverId), ...payload });

    $('messageBody').value = '';
    $('sendMsg').textContent = '✅ 암호화되어 전송되었습니다.';
  } catch (err) {
    $('sendMsg').textContent = `전송 오류: ${err.message}`;
  }
});

// --- 받은편지함 로드 + 복호화 ---
$('refreshBtn').addEventListener('click', loadInbox);

// --- 관리자 패널 새로고침 ---
$('adminRefreshBtn').addEventListener('click', loadAdminUsers);

async function loadInbox() {
  const list = $('messageList');
  list.innerHTML = '<p class="empty">불러오는 중...</p>';

  let myKeys;
  try {
    myKeys = await loadPrivateKeys(state.user.username);
  } catch {
    myKeys = null;
  }

  try {
    const { messages } = await api('GET', '/messages/inbox');
    if (messages.length === 0) {
      list.innerHTML = '<p class="empty">받은 메시지가 없습니다.</p>';
      return;
    }

    list.innerHTML = '';
    for (const m of messages) {
      const card = document.createElement('div');
      card.className = 'message';

      const meta = document.createElement('div');
      meta.className = 'message-meta';
      const time = new Date(m.createdAt).toLocaleString('ko-KR');
      meta.innerHTML = `<strong>${escapeHtml(m.senderName)}</strong><span>${time}</span>`;
      card.appendChild(meta);

      const bodyEl = document.createElement('div');
      bodyEl.className = 'message-body';

      if (!myKeys) {
        bodyEl.textContent = '🔒 개인키가 없어 복호화할 수 없습니다.';
        bodyEl.classList.add('locked');
      } else {
        try {
          const encPriv = await importEncPrivateKey(myKeys.encPrivJwk);
          const senderSigPub = m.senderSigPubkey
            ? await importSigPublicKey(m.senderSigPubkey)
            : null;

          const { plaintext, verified } = await decryptMessage(
            { encKey: m.encKey, iv: m.iv, ciphertext: m.ciphertext, signature: m.signature },
            encPriv,
            senderSigPub,
            m.senderId,
            state.user.id
          );

          bodyEl.textContent = plaintext;

          const badge = document.createElement('span');
          badge.className = verified ? 'badge ok' : 'badge bad';
          badge.textContent = verified ? '✔ 서명 검증됨' : '✖ 서명 검증 실패 (변조 의심)';
          card.appendChild(badge);
        } catch (err) {
          bodyEl.textContent = '⚠️ 복호화 실패 — 키가 일치하지 않거나 데이터가 손상되었습니다.';
          bodyEl.classList.add('locked');
        }
      }

      card.appendChild(bodyEl);
      list.appendChild(card);
    }
  } catch (err) {
    list.innerHTML = `<p class="empty">오류: ${escapeHtml(err.message)}</p>`;
  }
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// --- 시작 시 세션 복원 ---
(async function boot() {
  if (state.token && state.user) {
    try {
      await api('GET', '/users'); // 토큰 유효성 확인
      await showMessenger();
      return;
    } catch {
      clearSession();
    }
  }
  showAuth();
})();
