import { startAuthentication, startRegistration } from '@simplewebauthn/browser';

async function post(path: string, body?: unknown) {
  const r = await fetch(path, {
    method: 'POST',
    headers: { 
      'content-type': 'application/json',
      'Authorization': 'Bearer super_secret_admin_123'
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail ?? r.statusText);
  return r.json();
}

export async function enrollPasskey(label: string) {
  const optionsJSON = await post('/api/gateway/webauthn/register/options', { label });
  const attResp = await startRegistration({ optionsJSON });
  return post('/api/gateway/webauthn/register/verify', attResp);
}

export async function approveWithPasskey(rid: string) {
  const optionsJSON = await post(`/api/gateway/approvals/${rid}/options`);
  const asseResp = await startAuthentication({ optionsJSON });
  return post(`/api/gateway/approvals/${rid}/verify`, asseResp);
}