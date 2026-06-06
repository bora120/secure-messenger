// test/static.test.js
// 정적 파일 서빙과 모듈 경로가 올바른지 확인한다.
import assert from 'node:assert';
import { initStore } from '../src/store.js';

const PORT = 3458;
const BASE = `http://localhost:${PORT}`;

let passed = 0, failed = 0;
async function test(name, fn) {
  try { await fn(); console.log(`  \u2713 ${name}`); passed++; }
  catch (e) { console.log(`  \u2717 ${name}\n      ${e.message}`); failed++; }
}

async function run() {
  console.log('\n정적 파일 / 라우팅 테스트\n');
  await initStore();
  const { default: app } = await import('../src/server.js');
  const server = app.listen(PORT);
  await new Promise((r) => server.once('listening', r));

  const files = [
    ['/', 'text/html'],
    ['/index.html', 'text/html'],
    ['/app.js', 'javascript'],
    ['/crypto.js', 'javascript'],
    ['/keystore.js', 'javascript'],
    ['/styles.css', 'text/css'],
  ];

  for (const [path, ctype] of files) {
    await test(`GET ${path} -> 200 (${ctype})`, async () => {
      const res = await fetch(`${BASE}${path}`);
      assert.strictEqual(res.status, 200, `상태 ${res.status}`);
      const ct = res.headers.get('content-type') || '';
      assert.ok(ct.includes(ctype), `content-type "${ct}"에 "${ctype}" 포함 기대`);
    });
  }

  await test('app.js가 crypto.js, keystore.js를 import 하는지', async () => {
    const res = await fetch(`${BASE}/app.js`);
    const txt = await res.text();
    assert.ok(txt.includes("from './crypto.js'"), 'crypto.js import 필요');
    assert.ok(txt.includes("from './keystore.js'"), 'keystore.js import 필요');
  });

  server.close();
  console.log(`\n결과: ${passed} 통과, ${failed} 실패\n`);
  if (failed > 0) process.exit(1);
}
run().catch((e) => { console.error(e); process.exit(1); });
