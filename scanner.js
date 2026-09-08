// safechk scanner engine
// Principle: we ONLY read what the user's own browser already downloads.
// No probing of databases, no auth-header stripping, no data reads.
// We look at: response headers, TLS, public HTML, and the JS bundles
// the page itself loads. Everything here is "looking at the front door,"
// never "opening it."

import https from 'node:https';
import http from 'node:http';
import { URL } from 'node:url';

const UA = 'safechk-scanner/0.1 (+consumer safety check)';
const TIMEOUT = 12000;
const MAX_BUNDLE_BYTES = 4_000_000; // cap so one huge file can't hang us

function fetchRaw(target, { method = 'GET' } = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(target); } catch { return reject(new Error('bad-url')); }
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request(
      u,
      { method, headers: { 'User-Agent': UA, Accept: '*/*' }, timeout: TIMEOUT },
      (res) => {
        // follow one redirect level (common: http->https, /->/en)
        if ([301, 302, 307, 308].includes(res.statusCode) && res.headers.location) {
          res.resume();
          const next = new URL(res.headers.location, u).toString();
          return resolve(fetchRaw(next, { method }));
        }
        let size = 0;
        const chunks = [];
        res.on('data', (c) => {
          size += c.length;
          if (size <= MAX_BUNDLE_BYTES) chunks.push(c);
        });
        res.on('end', () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
            tls: u.protocol === 'https:',
            finalUrl: u.toString(),
          })
        );
      }
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end();
  });
}

// --- individual checks -------------------------------------------------

function checkTransport(page) {
  // Is the connection encrypted at all?
  if (!page.tls) {
    return {
      id: 'https',
      pass: false,
      weight: 'critical',
      user: '이 앱은 암호화되지 않은 연결(HTTP)을 씁니다. 입력한 정보가 오가는 도중 훔쳐볼 수 있어요.',
      dev: 'Served over HTTP, not HTTPS.',
    };
  }
  const hsts = page.headers['strict-transport-security'];
  return {
    id: 'https',
    pass: true,
    weight: 'critical',
    user: hsts
      ? '암호화된 연결(HTTPS)을 쓰고, 항상 암호화를 강제하도록 설정돼 있어요.'
      : '암호화된 연결(HTTPS)을 씁니다.',
    dev: hsts ? 'HTTPS + HSTS present.' : 'HTTPS present, HSTS header missing.',
  };
}

function checkSecurityHeaders(page) {
  const h = page.headers;
  const present = [];
  const missing = [];
  const wanted = {
    'content-security-policy': '외부 악성 스크립트 차단(CSP)',
    'x-frame-options': '피싱용 화면 삽입 방지',
    'x-content-type-options': '파일 위장 공격 방지',
    'referrer-policy': '이동 기록 노출 최소화',
  };
  for (const [key, label] of Object.entries(wanted)) {
    if (h[key]) present.push(label);
    else missing.push(label);
  }
  const pass = missing.length <= 1; // allow one soft-miss
  return {
    id: 'headers',
    pass,
    weight: 'medium',
    user: pass
      ? '기본적인 브라우저 보안 장치를 갖췄어요.'
      : `기본 보안 장치가 여러 개 빠져 있어요: ${missing.join(', ')}.`,
    dev: `present:[${present.length}] missing:[${missing.join(',')}]`,
  };
}

// The high-impact one for vibe-coded apps: secrets sitting in the browser bundle.
// We scan text the browser already has. We do NOT use any key we find.
// CRITICAL = keys that should NEVER be in the browser (real damage if leaked).
const SECRET_PATTERNS = [
  { re: /sk_live_[0-9a-zA-Z]{16,}/, name: 'Stripe 실결제 키' },
  { re: /sk-[a-zA-Z0-9]{20,}/, name: 'OpenAI/Anthropic 계열 비밀 키' },
  { re: /AKIA[0-9A-Z]{16}/, name: 'AWS 액세스 키' },
  { re: /sb_secret_[0-9a-zA-Z]{16,}/, name: 'Supabase 비밀 키' },
  { re: /service_role/, name: 'Supabase service_role (DB 전체 권한) 흔적' },
  { re: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/, name: '개인 암호화 키' },
  { re: /ghp_[0-9a-zA-Z]{36}/, name: 'GitHub 토큰' },
];
// These are normally MEANT to be public (Google Maps/YouTube keys, Firebase config).
// Their presence alone is not a breach — only worth a gentle note.
const PUBLIC_KEY_PATTERNS = [
  { re: /AIza[0-9A-Za-z\-_]{35}/, name: 'Google API 키(공개용일 수 있음)' },
];

async function checkExposedSecrets(page) {
  const hits = new Set();
  const softHits = new Set();

  const scanAll = (t) => {
    if (!t) return;
    for (const { re, name } of SECRET_PATTERNS) if (re.test(t)) hits.add(name);
    for (const { re, name } of PUBLIC_KEY_PATTERNS) if (re.test(t)) softHits.add(name);
  };

  scanAll(page.body);

  const scriptSrcs = [...page.body.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)]
    .map((m) => m[1])
    .slice(0, 8);
  for (const src of scriptSrcs) {
    let abs;
    try { abs = new URL(src, page.finalUrl).toString(); } catch { continue; }
    try { const js = await fetchRaw(abs); scanAll(js.body); } catch {}
  }

  const sourceMap = /\/\/# sourceMappingURL=/.test(page.body);
  const found = [...hits];

  if (found.length) {
    return {
      id: 'secrets', pass: false, weight: 'critical',
      user: `앱을 만든 사람의 비밀 키가 브라우저 코드에 그대로 노출돼 있어요 (${found.join(', ')}). 이건 앱 전체가 뚫릴 수 있다는 강한 위험 신호예요.`,
      dev: `exposed: ${found.join(', ')}`,
      extra: sourceMap ? '소스맵이 노출돼 원본 코드가 들여다보입니다.' : null,
    };
  }
  if (softHits.size) {
    return {
      id: 'secrets', pass: true, weight: 'low',
      user: `공개용으로 쓰이는 키(${[...softHits].join(', ')})가 보이지만, 이런 키는 원래 브라우저에 드러나도 되는 경우가 많아요. 곧바로 위험한 신호는 아니에요.`,
      dev: `public keys: ${[...softHits].join(', ')}`,
    };
  }
  return {
    id: 'secrets', pass: true, weight: 'critical',
    user: '민감한 비밀 키가 화면 코드에 노출된 흔적은 없어요.',
    dev: 'no secret patterns in client bundle',
    extra: sourceMap ? '소스맵이 노출돼 원본 코드가 들여다보입니다.' : null,
  };
}

function scanText(text, hits) {
  if (!text) return;
  for (const { re, name } of SECRET_PATTERNS) {
    if (re.test(text)) hits.add(name);
  }
}

function checkPrivacyPolicy(page) {
  const body = page.body.toLowerCase();
  const signals = [
    'privacy',
    '개인정보',
    '처리방침',
    'privacy policy',
    '개인정보처리방침',
  ];
  const hasPolicy = signals.some((s) => body.includes(s));
  // Korean PIPA-flavored: do they at least mention collection & retention?
  const mentionsCollection = /(수집|collect)/i.test(page.body);
  const mentionsRetention = /(파기|보유|retention|delete)/i.test(page.body);

  let pass = hasPolicy;
  let msg;
  if (!hasPolicy) {
    msg = '개인정보 처리방침을 찾을 수 없어요. 내 정보를 어떻게 다루는지 밝히지 않는다는 뜻이에요.';
  } else if (mentionsCollection && mentionsRetention) {
    msg = '개인정보 처리방침이 있고, 무엇을 수집하고 언제 파기하는지 안내가 보여요.';
  } else {
    msg = '처리방침은 있지만, 수집 항목이나 파기 절차 안내가 부족해 보여요.';
    pass = true; // present but thin -> not a hard fail
  }
  return { id: 'privacy', pass, weight: 'high', user: msg, dev: `policy:${hasPolicy} collect:${mentionsCollection} retain:${mentionsRetention}` };
}

// Cookie flags — read from Set-Cookie the server already sent. Passive. ✅
function checkCookies(page) {
  const raw = page.headers['set-cookie'];
  if (!raw) {
    return { id: 'cookies', pass: true, weight: 'low',
      user: '설정된 쿠키가 없거나 확인할 수 없어요.', dev: 'no Set-Cookie' };
  }
  const cookies = Array.isArray(raw) ? raw : [raw];
  const insecure = cookies.filter(
    (c) => !/httponly/i.test(c) || !/secure/i.test(c)
  ).length;
  const pass = insecure === 0;
  return {
    id: 'cookies', pass, weight: 'medium',
    user: pass
      ? '쿠키에 기본 보호 장치(HttpOnly·Secure)가 걸려 있어요.'
      : '쿠키에 보호 장치가 빠져 있어, 로그인 정보가 탈취될 위험이 있어요.',
    dev: `cookies:${cookies.length} insecure:${insecure}`,
  };
}

// CORS — read Access-Control-Allow-Origin the server sent. Passive. ✅
function checkCORS(page) {
  const acao = page.headers['access-control-allow-origin'];
  const wildcard = acao === '*';
  return {
    id: 'cors', pass: !wildcard, weight: 'medium',
    user: wildcard
      ? '아무 사이트나 이 앱의 데이터를 요청할 수 있게 열려 있어요(CORS 와일드카드).'
      : '외부 접근 제어(CORS) 설정이 무분별하게 열려 있지 않아요.',
    dev: `ACAO:${acao || 'none'}`,
  };
}

// Tech stack — read from headers/bundle the browser already has. Passive. ✅
// (informational only — no score penalty)
function checkTechStack(page) {
  const found = [];
  const server = page.headers['server'];
  const poweredBy = page.headers['x-powered-by'];
  if (server) found.push(server);
  if (poweredBy) found.push(poweredBy);
  if (/supabase/i.test(page.body)) found.push('Supabase');
  if (/firebase/i.test(page.body)) found.push('Firebase');
  if (/_next\//.test(page.body)) found.push('Next.js');
  const leaky = !!(server || poweredBy); // exposing version = minor info leak
  return {
    id: 'stack', pass: !leaky, weight: 'low',
    user: leaky
      ? `서버 종류·버전이 그대로 노출돼 있어요 (${[server, poweredBy].filter(Boolean).join(', ')}). 공격자에게 힌트가 됩니다.`
      : found.length
        ? `사용 기술이 확인됐어요: ${found.join(', ')}.`
        : '서버 정보가 불필요하게 노출되지 않았어요.',
    dev: `stack:[${found.join(',')}]`,
  };
}

// Mixed content — HTTPS page loading http:// resources. Passive (reads body). ✅
function checkMixedContent(page) {
  if (!page.tls) return { id:'mixed', pass:true, weight:'low', user:'', dev:'skip (not https)', skip:true };
  const httpRefs = (page.body.match(/(?:src|href)=["']http:\/\/[^"']+/gi) || [])
    .filter(u => !/http:\/\/(www\.)?w3\.org/i.test(u));
  const pass = httpRefs.length === 0;
  return {
    id:'mixed', pass, weight:'medium',
    user: pass
      ? '암호화된 페이지 안에서 안전하지 않은 항목을 불러오지 않아요.'
      : '자물쇠가 걸린 페이지인데, 일부 항목을 암호화 없이 불러오고 있어요. 그 부분은 새어나갈 수 있어요.',
    dev:`http refs:${httpRefs.length}`,
  };
}

// --- checklist extras: real lookups, graceful "확인 불가" on failure ---
import dns from 'node:dns/promises';

// SPF / DMARC — real DNS TXT lookups. If DNS is blocked, mark 확인 불가. ✅
async function checkEmailAuth(page) {
  let host;
  try { host = new URL(page.finalUrl).hostname.replace(/^www\./,''); } catch {}
  if (!host) return { id:'email', pass:true, weight:'low', unknown:true,
    user:'', dev:'no host', skip:true };
  try {
    const spfRecs = await dns.resolveTxt(host);
    const hasSPF = spfRecs.some(r => r.join('').toLowerCase().includes('v=spf1'));
    let hasDMARC = false;
    try {
      const d = await dns.resolveTxt('_dmarc.' + host);
      hasDMARC = d.some(r => r.join('').toLowerCase().includes('v=dmarc1'));
    } catch {}
    const pass = hasSPF && hasDMARC;
    return { id:'email', pass, weight:'low',
      user: pass
        ? '이메일 사칭을 막는 설정(SPF·DMARC)이 갖춰져 있어요.'
        : '이메일 사칭을 막는 설정이 일부 빠져 있어, 이 앱을 사칭한 메일이 올 수 있어요.',
      dev:`spf:${hasSPF} dmarc:${hasDMARC}` };
  } catch {
    return { id:'email', pass:true, weight:'low', unknown:true,
      user:'이메일 사칭 방지 설정(SPF·DMARC)은 이 환경에서 확인하지 못했어요. 서버가 외부 DNS 조회를 막고 있어서예요.',
      dev:'dns blocked' };
  }
}

// CT log — real crt.sh lookup. If blocked, 확인 불가. ✅
async function checkCTLog(page) {
  let host;
  try { host = new URL(page.finalUrl).hostname.replace(/^www\./,''); } catch {}
  if (!host) return { id:'ct', skip:true };
  try {
    const r = await fetch('https://crt.sh/?q=' + encodeURIComponent(host) + '&output=json',
      { signal: AbortSignal.timeout(9000) });
    const data = await r.json();
    const subs = new Set(data.flatMap(d => (d.name_value||'').split('\n'))
      .map(s => s.trim().toLowerCase()).filter(Boolean));
    const n = subs.size;
    const pass = n <= 30;
    return { id:'ct', pass, weight:'low',
      user: pass
        ? `공개 인증서 기록상 노출된 하위 도메인이 ${n}개로, 관리 범위 안이에요.`
        : `공개 인증서 기록에 하위 도메인이 ${n}개나 드러나 있어, 공격 대상이 넓어질 수 있어요.`,
      dev:`ct subs:${n}` };
  } catch {
    return { id:'ct', pass:true, weight:'low', unknown:true,
      user:'인증서 투명성(CT) 기록은 이 환경에서 확인하지 못했어요. 서버가 외부 조회(crt.sh)를 막고 있어서예요.',
      dev:'ct blocked' };
  }
}

// Known-risky library versions — passive, reads what the browser already got. ✅
// (lightweight CVE-style check: flags a few well-known outdated libs)
const RISKY_LIBS = [
  { re:/jquery[.\-/]1\.(?!12)\d/i, name:'jQuery 1.x (오래된 버전, 알려진 취약점 있음)' },
  { re:/angular[.\-/]1\.\d/i, name:'AngularJS 1.x (지원 종료)' },
  { re:/bootstrap[.\-/]3\.\d/i, name:'Bootstrap 3.x (오래된 버전)' },
];
function checkKnownVulnLibs(page) {
  const hits = RISKY_LIBS.filter(l => l.re.test(page.body)).map(l => l.name);
  const pass = hits.length === 0;
  return { id:'cve', pass, weight:'low',
    user: pass
      ? '알려진 위험 버전의 오래된 라이브러리는 발견되지 않았어요.'
      : `알려진 취약점이 있는 오래된 라이브러리를 쓰고 있어요 (${hits.join(', ')}).`,
    dev:`risky libs:${hits.length}` };
}

// --- scoring -----------------------------------------------------------

const WEIGHT_PENALTY = { critical: 40, high: 20, medium: 10, low: 5 };

function grade(checks) {
  let score = 100;
  for (const c of checks) {
    if (c.unknown) continue;
    if (!c.pass) score -= WEIGHT_PENALTY[c.weight] ?? 10;
  }
  score = Math.max(0, score);
  let letter = 'F';
  if (score >= 90) letter = 'A';
  else if (score >= 75) letter = 'B';
  else if (score >= 60) letter = 'C';
  else if (score >= 45) letter = 'D';
  else if (score >= 30) letter = 'E';
  return { score, letter };
}

function verdict(letter, checks) {
  const criticalFail = checks.some((c) => !c.pass && c.weight === 'critical');
  if (criticalFail) {
    return {
      headline: '이 앱엔 민감한 정보(비밀번호·결제·주민번호 등)를 넣지 마세요.',
      tone: 'danger',
    };
  }
  if (letter === 'A' || letter === 'B') {
    return { headline: '안전에 신경 쓴 흔적이 보여요. 일반적인 사용은 괜찮아 보입니다.', tone: 'ok' };
  }
  return {
    headline: '주의가 필요해요. 꼭 필요한 정보만 최소한으로 입력하세요.',
    tone: 'warn',
  };
}

export async function scan(target) {
  if (!/^https?:\/\//i.test(target)) target = 'https://' + target;
  const page = await fetchRaw(target);
  const checks = [
    checkTransport(page),
    await checkExposedSecrets(page),
    checkPrivacyPolicy(page),
    checkSecurityHeaders(page),
    checkCookies(page),
    checkCORS(page),
    checkMixedContent(page),
    checkTechStack(page),
    checkKnownVulnLibs(page),
    await checkEmailAuth(page),
    await checkCTLog(page),
  ].filter(c => c && !c.skip);
  const { score, letter } = grade(checks);
  const v = verdict(letter, checks);
  return {
    target: page.finalUrl,
    score,
    letter,
    verdict: v,
    checks,
    disclaimer:
      '돌다리는 브라우저가 이미 받아온 공개 정보만 봐요. 앱의 데이터베이스에 접근하거나 안에 든 데이터를 읽지는 않아요. 그래서 완벽한 안전을 보장한다기보다, 겉으로 드러난 안전 신호를 등급으로 보여드리는 거예요.',
  };
}
