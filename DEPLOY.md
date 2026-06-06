# 배포 가이드 (Render + 외부 PostgreSQL)

이 문서는 프로젝트를 인터넷에 올려서 여러 사람이 각자 가입하고
1:1 메시지를 주고받게 하는 방법을 단계별로 설명한다.
외부 PostgreSQL 데이터베이스를 사용하므로 데이터가 영구 보관된다.

소요 시간: 약 15분. 신용카드 불필요(무료 플랜).

---

## 데이터 저장 구조 요약

이 앱은 환경에 따라 DB를 자동 선택한다.

| 환경 | 사용하는 DB | 조건 |
|------|------------|------|
| 배포(Render) | **PostgreSQL** | 환경변수 `DATABASE_URL` 이 있으면 자동 |
| 로컬 개발 | SQLite 또는 JSON | `DATABASE_URL` 이 없을 때 |

즉, 로컬에서는 아무 설정 없이 `npm start` 하면 JSON/SQLite로 돌고,
배포하면 자동으로 PostgreSQL을 쓴다. 코드 수정은 필요 없다.

---

## 사전 준비물

- GitHub 계정 (https://github.com)
- Render 계정 (https://render.com — GitHub으로 가입하면 편함)
- 이 프로젝트 폴더

---

## 1단계: GitHub에 코드 올리기

### 방법 A — GitHub Desktop (쉬움, 추천)

1. https://desktop.github.com 에서 설치 후 로그인
2. `File > Add Local Repository` → 이 프로젝트 폴더 선택
3. "create a repository" 링크가 뜨면 클릭
4. 커밋 메시지(예: `first commit`) 입력 후 `Commit to main`
5. `Publish repository` 클릭 → Publish

### 방법 B — 명령어

```bash
cd secure-messenger
git init
git add .
git commit -m "first commit"
git remote add origin https://github.com/내아이디/secure-messenger.git
git branch -M main
git push -u origin main
```

> `node_modules` 와 로컬 DB 파일은 `.gitignore` 에 있어 안 올라간다. 정상이다.

---

## 2단계: Blueprint로 한 번에 배포 (DB까지 자동)

저장소에 `render.yaml` 이 있어서, 웹 서비스와 PostgreSQL을 한 번에 만들 수 있다.

1. https://render.com 로그인
2. 우측 상단 `New +` → `Blueprint` 클릭
3. 방금 올린 GitHub 저장소를 선택 → `Connect`
4. Render가 `render.yaml` 을 읽어 아래 두 가지를 자동으로 보여준다:
   - `secure-messenger` (웹 서비스)
   - `secure-messenger-db` (PostgreSQL 데이터베이스)
5. `Apply` (또는 `Create`) 클릭

그러면 Render가 다음을 자동으로 처리한다:
- PostgreSQL DB 생성
- DB 연결 문자열을 웹 서비스의 `DATABASE_URL` 환경변수로 주입
- `JWT_SECRET` 랜덤 생성
- 빌드(`npm install`) 후 실행(`npm start`)

---

## 3단계: 배포 확인

- 빌드 로그에 `[store] 백엔드: postgres` 가 보이면 PostgreSQL 연결 성공이다.
  (만약 `[store] 백엔드: json` 이면 DATABASE_URL 주입이 안 된 것 — 5단계 참고)
- `[server] 포트 ... 에서 실행 중` 줄이 보이면 서버 정상 기동.
- 상단에 `https://secure-messenger-xxxx.onrender.com` 주소가 생긴다.
- 그 주소를 열면 로그인/회원가입 화면이 뜬다.

이 주소를 친구들에게 공유하면 각자 가입해서 1:1 메시지를 주고받을 수 있다.
**제일 먼저 가입하는 계정이 관리자**가 된다.

---

## HTTPS는 자동 (중요)

이 앱의 암호화(Web Crypto API)는 HTTPS 또는 localhost 에서만 동작한다.
Render가 주는 `onrender.com` 주소는 자동 HTTPS라 그대로 암호화가 작동한다.

---

## 데이터 영속성 (PostgreSQL의 장점)

JSON/SQLite 와 달리, PostgreSQL 은 별도 DB 서버에 저장되므로
웹 서비스가 슬립에 들어갔다 깨거나 재배포해도 **가입자·메시지가 유지된다.**

> 단, Render 무료 PostgreSQL은 생성 후 약 90일 뒤 만료되는 정책이 있을 수 있다.
> 장기 운영 시 Render 대시보드에서 DB 상태를 확인하라.

---

## 무료 플랜에서 알아둘 점

1. **첫 접속이 느리다.** 웹 서비스가 15분 비활성 시 슬립에 들어가고,
   깨어나는 데 30초~1분 걸린다. 처음 로딩이 길어도 정상이다.
   (데이터는 PostgreSQL에 있으므로 사라지지 않는다.)

2. **개인키는 각자 브라우저에 저장된다.** 이 설계는 배포해도 그대로다.
   A가 자기 PC에서 가입하면 A의 개인키는 A의 브라우저(IndexedDB)에만 있다.
   다른 PC/브라우저로 로그인하면 이전 메시지는 복호화할 수 없다.
   이것은 "서버도 내용을 못 보는" 종단간 암호화의 핵심 설계다.

---

## 코드 수정 후 재배포

GitHub에 다시 push하면 Render가 자동으로 재빌드·재배포한다.
GitHub Desktop이면 커밋 후 `Push origin`.

---

## 문제 해결

- **로그에 `[store] 백엔드: json` 이 뜸 (PostgreSQL 연결 안 됨)**
  → Render 대시보드 > 웹 서비스 > Environment 에서 `DATABASE_URL` 이
    있는지 확인. Blueprint로 배포했다면 자동 주입되지만, 수동 생성한
    경우 DB의 "Internal Connection String" 을 복사해 직접 추가한다.

- **`SELECT 1` 또는 연결 타임아웃 에러**
  → DB와 웹 서비스가 같은 리전(Region)인지 확인. 다르면 느리거나 막힌다.

- **빌드 실패: better-sqlite3 컴파일 에러**
  → 무시해도 된다. `optionalDependencies` 라 실패해도 앱은 정상 빌드되고,
    배포 환경에선 어차피 PostgreSQL을 쓴다.

- **회원가입 시 암호화 오류**
  → 주소가 `https://` 인지 확인. Render 기본 주소는 https라 보통 문제없다.

- **"Application failed to respond"**
  → 슬립에서 깨어나는 중. 1분 기다렸다 새로고침.

---

## 로컬에서 PostgreSQL로 테스트하고 싶다면 (선택)

로컬에 PostgreSQL을 설치했다면, 환경변수로 연결할 수 있다.

```bash
# 예시 (로컬 PostgreSQL)
# Windows PowerShell:
$env:DATABASE_URL="postgresql://postgres:비밀번호@localhost:5432/messenger"; npm start

# macOS / Linux:
DATABASE_URL="postgresql://postgres:비밀번호@localhost:5432/messenger" npm start
```

`[store] 백엔드: postgres` 가 뜨면 로컬 PostgreSQL 연결 성공이다.
설정하지 않으면 그냥 JSON으로 동작하므로, 로컬 개발에는 굳이 필요 없다.
