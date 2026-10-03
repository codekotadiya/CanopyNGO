import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import middleware from '../middleware.js';
import {
  COOKIE_NAME,
  handleLaunchpadHandoff,
  verifyToken,
} from '../lib/launchpad-handoff.js';

const SECRET = 'test-only-secret';
const HOST = 'canopy-ngo.vercel.app';
const NOW = 1_700_000_000_000;

function bytesToBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

async function issuerSign(payload, secret) {
  const body = bytesToBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body));
  const sig = bytesToBase64Url(new Uint8Array(signature));
  return `${body}.${sig}`;
}

function handoffPayload(overrides = {}) {
  return {
    typ: 'handoff',
    aud: HOST,
    exp: Math.floor(NOW / 1000) + 60,
    nonce: 'nonce-1',
    ...overrides,
  };
}

function requestFor(token, { host = HOST, path = '/', extra = '' } = {}) {
  const url = new URL(`https://${host}${path}`);
  if (extra) url.searchParams.set('ref', extra);
  if (token !== undefined) url.searchParams.set('launchpad_token', token);
  return new Request(url);
}

function locationOf(response) {
  return new URL(response.headers.get('location'));
}

test('a valid token becomes a session and leaves the address bar', async () => {
  const token = await issuerSign(handoffPayload(), SECRET);
  const response = await handleLaunchpadHandoff(
    requestFor(token, { extra: 'newsletter' }),
    { LAUNCHPAD_PASSWORD: SECRET },
    NOW,
  );

  assert.equal(response.status, 302);
  const location = locationOf(response);
  assert.equal(location.host, HOST);
  assert.equal(location.pathname, '/');
  assert.equal(location.searchParams.get('launchpad_token'), null);
  assert.equal(location.searchParams.get('ref'), 'newsletter');
  assert.equal(location.toString().includes(token), false);
  assert.equal(location.toString().includes('launchpad_token'), false);

  const cookie = response.headers.get('set-cookie');
  assert.match(cookie, new RegExp(`^${COOKIE_NAME}=`));
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /Secure/);
  assert.match(cookie, /SameSite=Lax/);
  const sessionToken = cookie.slice(COOKIE_NAME.length + 1).split(';', 1)[0];
  const session = await verifyToken(sessionToken, SECRET);
  assert.equal(session.typ, 'session');
  assert.equal(session.exp, Math.floor(NOW / 1000) + 60 * 60 * 24 * 7);
});

test('an expired token is rejected and removed from the url', async () => {
  const token = await issuerSign(handoffPayload({ exp: Math.floor(NOW / 1000) - 1 }), SECRET);
  const response = await handleLaunchpadHandoff(
    requestFor(token),
    { LAUNCHPAD_PASSWORD: SECRET },
    NOW,
  );
  assert.equal(response.status, 302);
  assert.equal(locationOf(response).searchParams.has('launchpad_token'), false);
  assert.equal(response.headers.get('set-cookie'), null);
});

test('a wrong-audience token is rejected', async () => {
  const token = await issuerSign(handoffPayload({ aud: 'other.example' }), SECRET);
  const response = await handleLaunchpadHandoff(
    requestFor(token),
    { LAUNCHPAD_PASSWORD: SECRET },
    NOW,
  );
  assert.equal(response.headers.get('set-cookie'), null);
  assert.equal(locationOf(response).host, HOST);
  assert.equal(locationOf(response).search, '');
});

test('a bad signature is rejected', async () => {
  const token = await issuerSign(handoffPayload(), SECRET);
  const [body, signature] = token.split('.');
  const flipped = signature.slice(0, -1) + (signature.endsWith('A') ? 'B' : 'A');
  const response = await handleLaunchpadHandoff(
    requestFor(`${body}.${flipped}`),
    { LAUNCHPAD_PASSWORD: SECRET },
    NOW,
  );
  assert.equal(response.headers.get('set-cookie'), null);
  assert.equal(locationOf(response).searchParams.has('launchpad_token'), false);

  const short = await handleLaunchpadHandoff(
    requestFor(`${body}.${signature.slice(0, -2)}`),
    { LAUNCHPAD_PASSWORD: SECRET },
    NOW,
  );
  assert.equal(short.headers.get('set-cookie'), null);
});

test('a non-handoff token and a missing secret are rejected', async () => {
  const sessionLike = await issuerSign({
    typ: 'session',
    aud: HOST,
    exp: Math.floor(NOW / 1000) + 60,
    nonce: 'nonce-1',
  }, SECRET);
  const wrongType = await handleLaunchpadHandoff(
    requestFor(sessionLike),
    { LAUNCHPAD_PASSWORD: SECRET },
    NOW,
  );
  assert.equal(wrongType.headers.get('set-cookie'), null);

  const token = await issuerSign(handoffPayload(), SECRET);
  const missing = await handleLaunchpadHandoff(requestFor(token), {}, NOW);
  assert.equal(missing.headers.get('set-cookie'), null);
  assert.equal(locationOf(missing).searchParams.has('launchpad_token'), false);
});

test('visitors without a token keep the public response', async () => {
  const response = await handleLaunchpadHandoff(
    new Request(`https://${HOST}/#join`),
    { LAUNCHPAD_PASSWORD: SECRET },
    NOW,
  );
  assert.equal(response, null);

  const continued = await middleware(new Request(`https://${HOST}/`));
  assert.equal(continued.headers.get('x-middleware-next'), '1');
  assert.equal(continued.headers.get('set-cookie'), null);
});

test('the browser follows the redirect to the same page without the token', async () => {
  const token = await issuerSign(handoffPayload(), SECRET);
  const server = createServer(async (req, res) => {
    const request = new Request(`https://${HOST}${req.url}`);
    const response = await handleLaunchpadHandoff(request, { LAUNCHPAD_PASSWORD: SECRET }, NOW);
    if (!response) {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(readFileSync(new URL('../index.html', import.meta.url)));
      return;
    }
    res.writeHead(response.status, {
      location: response.headers.get('location'),
      'set-cookie': response.headers.get('set-cookie') ?? undefined,
      'cache-control': 'no-store',
    });
    res.end();
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const { port } = server.address();
    const first = await fetch(
      `http://127.0.0.1:${port}/?launchpad_token=${encodeURIComponent(token)}&ref=1`,
      { redirect: 'manual' },
    );
    assert.equal(first.status, 302);
    const location = first.headers.get('location');
    assert.equal(location.includes('launchpad_token'), false);
    assert.equal(location.includes(token), false);
    assert.match(first.headers.get('set-cookie'), new RegExp(`${COOKIE_NAME}=`));

    const landed = new URL(location);
    assert.equal(landed.origin, `https://${HOST}`);
    assert.equal(landed.searchParams.get('ref'), '1');

    const page = await fetch(`http://127.0.0.1:${port}${landed.pathname}${landed.search}`);
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.match(html, /Canopy Commons/);
    assert.equal(html.includes('launchpad_token'), false);
    assert.equal(html.includes(token), false);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }
});
