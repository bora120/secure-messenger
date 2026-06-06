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
  decryptGroupMessage,  // ← 단체방 전용 복호화+검증 함수 추가
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

  // 로그인 전/후 헤더 전환
  document.body.classList.add('auth-mode');
  document.body.classList.remove('logged-in');
}

async function showMessenger() {
  $('authView').classList.add('hidden');
  $('messengerView').classList.remove('hidden');
  $('session').classList.remove('hidden');
  $('me').textContent = `${state.user.username} 님`;

  // 로그인 전환
  document.body.classList.add('logged-in');
  document.body.classList.remove('auth-mode');

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

// ===========================================================================
// 단체방 UI
// ===========================================================================

// --- 메인 탭 전환 ---
let currentView = 'dm';
document.querySelectorAll('.main-tab').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.main-tab').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    currentView = btn.dataset.view;
    $('dmView').classList.toggle('hidden', currentView !== 'dm');
    $('groupView').classList.toggle('hidden', currentView !== 'group');
    if (currentView === 'group') loadGroups();
  });
});

// --- 단체방 만들기 폼 토글 ---
$('showCreateGroupBtn').addEventListener('click', async () => {
  const form = $('createGroupForm');
  const isHidden = form.classList.contains('hidden');
  form.classList.toggle('hidden', !isHidden);
  if (isHidden) await populateMemberChecklist();
});
$('cancelGroupBtn').addEventListener('click', () => {
  $('createGroupForm').classList.add('hidden');
  $('createGroupMsg').textContent = '';
});

async function populateMemberChecklist() {
  const list = $('groupMemberList');
  list.innerHTML = '<span style="font-size:0.8rem;color:var(--text-muted)">불러오는 중...</span>';
  try {
    const { users } = await api('GET', '/users');
    if (users.length === 0) {
      list.innerHTML = '<span style="font-size:0.8rem;color:var(--text-muted)">(다른 사용자 없음)</span>';
      return;
    }
    list.innerHTML = '';
    for (const u of users) {
      const label = document.createElement('label');
      label.className = 'member-check-item';
      label.innerHTML = `<input type="checkbox" value="${u.id}" /> ${escapeHtml(u.username)}`;
      list.appendChild(label);
    }
  } catch (err) {
    list.innerHTML = `<span style="font-size:0.8rem;color:red">${escapeHtml(err.message)}</span>`;
  }
}

// --- 단체방 생성 ---
$('createGroupBtn').addEventListener('click', async () => {
  const name = $('groupName').value.trim();
  const memberIds = [...$('groupMemberList').querySelectorAll('input[type=checkbox]:checked')]
    .map((cb) => Number(cb.value));
  $('createGroupMsg').textContent = '';

  if (!name) { $('createGroupMsg').textContent = '방 이름을 입력해주세요.'; return; }
  if (memberIds.length === 0) { $('createGroupMsg').textContent = '멤버를 1명 이상 선택해주세요.'; return; }

  try {
    await api('POST', '/groups', { name, memberIds });
    $('createGroupForm').classList.add('hidden');
    $('groupName').value = '';
    $('createGroupMsg').textContent = '';
    await loadGroups();
  } catch (err) {
    $('createGroupMsg').textContent = `오류: ${err.message}`;
  }
});

// --- 단체방 목록 로드 ---
let currentGroupId = null;
let currentGroupMembers = [];

async function loadGroups() {
  const list = $('groupList');
  list.innerHTML = '<p class="empty">불러오는 중...</p>';
  try {
    const { groups } = await api('GET', '/groups');
    if (groups.length === 0) {
      list.innerHTML = '<p class="empty">참여 중인 단체방이 없습니다.</p>';
      return;
    }
    list.innerHTML = '';
    for (const g of groups) {
      const item = document.createElement('div');
      item.className = 'group-item' + (g.id === currentGroupId ? ' active' : '');
      item.dataset.gid = g.id;
      const memberNames = g.members.map((m) => m.username).join(', ');
      item.innerHTML = `
        <div class="group-item-name">${escapeHtml(g.name)}</div>
        <div class="group-item-meta">${escapeHtml(memberNames)}</div>
      `;
      item.addEventListener('click', () => openGroupChat(g));
      list.appendChild(item);
    }
  } catch (err) {
    list.innerHTML = `<p class="empty">오류: ${escapeHtml(err.message)}</p>`;
  }
}

// --- 단체방 채팅 열기 ---
async function openGroupChat(group) {
  currentGroupId = group.id;
  currentGroupMembers = group.members;

  // 사이드바 active 표시
  document.querySelectorAll('.group-item').forEach((el) => {
    el.classList.toggle('active', Number(el.dataset.gid) === group.id);
  });

  $('groupChatPlaceholder').classList.add('hidden');
  $('groupChatRoom').classList.remove('hidden');
  $('groupChatName').textContent = group.name;
  $('groupChatMembers').textContent = group.members.map((m) => m.username).join(', ');

  $('groupLeaveBtn').onclick = () => leaveGroup(group.id, group.name);

  await loadGroupMessages();
}

// --- 단체방 메시지 로드 ---
$('groupRefreshBtn').addEventListener('click', loadGroupMessages);

async function loadGroupMessages() {
  if (!currentGroupId) return;
  const list = $('groupMessageList');
  list.innerHTML = '<p class="empty" style="text-align:center">불러오는 중...</p>';

  let myKeys;
  try { myKeys = await loadPrivateKeys(state.user.username); } catch { myKeys = null; }

  try {
    const { messages } = await api('GET', `/groups/${currentGroupId}/messages`);
    list.innerHTML = '';

    if (messages.length === 0) {
      list.innerHTML = '<p class="empty" style="text-align:center">메시지가 없습니다. 첫 메시지를 보내보세요!</p>';
      return;
    }

    for (const m of messages) {
      const isMine = m.senderId === state.user.id;
      const card = document.createElement('div');
      card.className = 'chat-msg ' + (isMine ? 'mine' : 'theirs');

      if (!isMine) {
        const senderEl = document.createElement('div');
        senderEl.className = 'chat-msg-sender';
        senderEl.textContent = m.senderName;
        card.appendChild(senderEl);
      }

      const bubble = document.createElement('div');
      bubble.className = 'chat-msg-bubble';

      if (!myKeys) {
        bubble.textContent = '🔒 개인키 없음';
        bubble.classList.add('locked');
      } else {
        try {
          const encPriv = await importEncPrivateKey(myKeys.encPrivJwk);
          const senderSigPub = m.senderSigPubkey
            ? await importSigPublicKey(m.senderSigPubkey)
            : null;

          // ✅ 수정: DM용 decryptMessage 대신 단체방 전용 decryptGroupMessage 사용
          // 단체방 서명 포맷 "group:groupId|senderId|평문" 으로 정확히 검증
          const { plaintext, verified } = await decryptGroupMessage(
            { encKey: m.encKey, iv: m.iv, ciphertext: m.ciphertext, signature: m.signature },
            encPriv,
            senderSigPub,
            currentGroupId,  // groupId
            m.senderId       // senderId
          );

          bubble.textContent = plaintext;

          const verifyBadge = document.createElement('div');
          verifyBadge.className = 'chat-msg-verify';
          verifyBadge.innerHTML = verified
            ? '<span class="badge ok" style="font-size:0.65rem">✔ 서명 검증됨</span>'
            : '<span class="badge bad" style="font-size:0.65rem">✖ 서명 실패</span>';
          card.appendChild(bubble);
          card.appendChild(verifyBadge);

          const timeEl = document.createElement('div');
          timeEl.className = 'chat-msg-time';
          timeEl.textContent = new Date(m.createdAt).toLocaleString('ko-KR');
          card.appendChild(timeEl);
          list.appendChild(card);
          continue;
        } catch {
          bubble.textContent = '⚠️ 복호화 실패';
          bubble.classList.add('locked');
        }
      }

      card.appendChild(bubble);
      const timeEl = document.createElement('div');
      timeEl.className = 'chat-msg-time';
      timeEl.textContent = new Date(m.createdAt).toLocaleString('ko-KR');
      card.appendChild(timeEl);
      list.appendChild(card);
    }

    list.scrollTop = list.scrollHeight;
  } catch (err) {
    list.innerHTML = `<p class="empty">오류: ${escapeHtml(err.message)}</p>`;
  }
}

// --- 단체방 메시지 전송 ---
$('groupSendBtn').addEventListener('click', async () => {
  if (!currentGroupId) return;
  const plaintext = $('groupMessageBody').value.trim();
  $('groupSendMsg').textContent = '';
  if (!plaintext) { $('groupSendMsg').textContent = '메시지를 입력하세요.'; return; }

  try {
    const myKeys = await loadPrivateKeys(state.user.username);
    if (!myKeys) { $('groupSendMsg').textContent = '개인키가 없어 서명할 수 없습니다.'; return; }

    const sigPriv = await importSigPrivateKey(myKeys.sigPrivJwk);
    const data_enc = new TextEncoder().encode(plaintext);

    // AES-256-GCM 키 생성
    const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, data_enc);
    const rawAes = await crypto.subtle.exportKey('raw', aesKey);

    // 각 멤버의 공개키로 AES 키를 개별 암호화
    const memberKeys = [];
    for (const member of currentGroupMembers) {
      if (!member.enc_pubkey) continue;
      const memberPub = await importEncPublicKey(member.enc_pubkey);
      const encKeyBuf = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, memberPub, rawAes);
      memberKeys.push({ userId: member.id, encKey: bufToB64(encKeyBuf) });
    }

    // 서명: 그룹ID + 송신자ID + 평문
    const prefix = new TextEncoder().encode(`group:${currentGroupId}|${state.user.id}|`);
    const sigPayload = new Uint8Array(prefix.length + data_enc.length);
    sigPayload.set(prefix, 0);
    sigPayload.set(data_enc, prefix.length);
    const sigBuf = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, sigPriv, sigPayload);

    await api('POST', `/groups/${currentGroupId}/messages`, {
      iv: bufToB64(iv.buffer),
      ciphertext: bufToB64(cipherBuf),
      signature: bufToB64(sigBuf),
      memberKeys,
    });

    $('groupMessageBody').value = '';
    await loadGroupMessages();
  } catch (err) {
    $('groupSendMsg').textContent = `전송 오류: ${err.message}`;
  }
});

// bufToB64 헬퍼 (crypto.js 내부 함수 재노출)
function bufToB64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

// --- [추가] 단체방 나가기 ---
async function leaveGroup(groupId, groupName) {
  const confirmed = window.confirm(
    `"${groupName}" 방에서 나가시겠습니까?\n나간 후에는 새 메시지를 받을 수 없습니다.`
  );
  if (!confirmed) return;
  try {
    await api('DELETE', `/groups/${groupId}/leave`);
    
    // 채팅창 닫고 초기 화면으로 복귀
    currentGroupId = null;
    currentGroupMembers = [];
    $('groupChatRoom').classList.add('hidden');
    $('groupChatPlaceholder').classList.remove('hidden');
    
    // 목록 새로고침
    await loadGroups();
  } catch (err) {
    alert(`나가기 오류: ${err.message}`);
  }
}
