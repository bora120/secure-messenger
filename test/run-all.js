// test/run-all.js
// 모든 테스트를 순차 실행한다.
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const files = [
  'security.test.js',
  'keystore.test.js',
  'static.test.js',
  'postgres.test.js',
  'admin.test.js',
  'integration.test.js',
  'fullflow.test.js',
];

let allOk = true;
for (const f of files) {
  console.log(`\n${'='.repeat(50)}\n실행: ${f}\n${'='.repeat(50)}`);
  const res = spawnSync('node', [path.join(__dirname, f)], { stdio: 'inherit' });
  if (res.status !== 0) allOk = false;
}

console.log(`\n${'='.repeat(50)}`);
console.log(allOk ? '✅ 전체 테스트 통과' : '❌ 일부 테스트 실패');
console.log('='.repeat(50));
process.exit(allOk ? 0 : 1);
