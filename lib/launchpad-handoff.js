/**
 * LaunchpadOS handoff receiver.
 * Contract: codekotadiya/lunchpados src/gate.js
 * Token: base64url(UTF-8 JSON) + "." + base64url(HMAC-SHA256 of that string).
 * HMAC key is the raw UTF-8 LAUNCHPAD_PASSWORD. The secret stays on the server.
 */

export const HANDOFF_QUERY_PARAM = 'launchpad_token';
export const COOKIE_NAME = 'canopy_session';
export const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;

export function readSecret(env) {
  const value = env?.LAUNCHPAD_PASSWORD;
  if (typeof value !== 'string' || value.length === 0) return null;
  return value;
}

function bytesToBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function base64UrlToBytes(value) {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function randomNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function hmac(message, secret) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(message),
  );
  return bytesToBase64Url(new Uint8Array(signature));
}

export async function signToken(payload, secret) {
  const body = bytesToBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const signature = await hmac(body, secret);
  return `${body}.${signature}`;
}

export async function verifyToken(token, secret) {
  if (typeof token !== 'string' || !secret) return null;
  const dot = token.indexOf('.');
  if (dot <= 0 || dot !== token.lastIndexOf('.')) return null;
  const body = token.slice(0, dot);
  const signature = token.slice(dot + 1);
  const expected = await hmac(body, secret);
  if (!safeEqual(signature, expected)) return null;
  try {
    const json = new TextDecoder().decode(base64UrlToBytes(body));
    const payload = JSON.parse(json);
    if (!payload || typeof payload.exp !== 'number' || typeof payload.typ !== 'string') return null;
    return payload;
  } catch {
    return null;
  }
}

function safeEqual(a, b) {
  const left = new TextEncoder().encode(String(a));
  const right = new TextEncoder().encode(String(b));
  const length = Math.max(left.length, right.length);
  let diff = left.length === right.length ? 0 : 1;
  for (let i = 0; i < length; i += 1) {
    diff |= (left[i] ?? 0) ^ (right[i] ?? 0);
  }
  return diff === 0;
}

function requestHost(request) {
  const url = new URL(request.url);
  let host = url.host.toLowerCase();
  if (url.protocol === 'https:' && host.endsWith(':443')) host = host.slice(0, -4);
  if (url.protocol === 'http:' && host.endsWith(':80')) host = host.slice(0, -3);
  return host;
}

function sessionCookie(token) {
  return [
    `${COOKIE_NAME}=${token}`,
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    'Path=/',
    `Max-Age=${SESSION_TTL_SECONDS}`,
  ].join('; ');
}

/**
 * Valid handoff: set this app's session cookie and redirect to the same URL
 * without launchpad_token. Invalid or missing secret: redirect without a
 * session. No token: leave the public page alone.
 */
export async function handleLaunchpadHandoff(request, env, now = Date.now()) {
  const url = new URL(request.url);
  if (!url.searchParams.has(HANDOFF_QUERY_PARAM)) return null;

  const token = url.searchParams.get(HANDOFF_QUERY_PARAM) ?? '';
  const clean = new URL(url);
  clean.searchParams.delete(HANDOFF_QUERY_PARAM);

  const headers = new Headers({
    location: clean.toString(),
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
  });

  const secret = readSecret(env);
  const payload = secret ? await verifyToken(token, secret) : null;
  const host = requestHost(request);
  const accepted = Boolean(
    payload
    && payload.typ === 'handoff'
    && payload.aud === host
    && payload.exp * 1000 > now,
  );

  if (accepted) {
    const session = await signToken({
      typ: 'session',
      exp: Math.floor(now / 1000) + SESSION_TTL_SECONDS,
      nonce: randomNonce(),
    }, secret);
    headers.set('set-cookie', sessionCookie(session));
  }

  return new Response(null, { status: 302, headers });
}
