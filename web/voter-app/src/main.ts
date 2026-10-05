/**
 * The voter's application, as a sequence of steps the voter performs.
 *
 * The protocol used to run under the hood: one button, and five cryptographic
 * operations between two renders. That is no use to an audience, and not much
 * use to a reader either. Here every step shows the exact payload before it
 * crosses, names its number in the figure, and waits to be asked.
 *
 * **Transport stays HTTP.** Saving a step as a file is offered beside each
 * one, because a payload you can hand to an audience is worth having, but the
 * file is never the transport. Three of these steps are party-to-party
 * transmissions in the design, and a file would depict a voter carrying their
 * identifier around by hand, which is neither what the article says nor what
 * a deployment would do. The one genuine file handover, application to
 * wallet, is a file precisely because on a real device it is an app-to-app
 * invocation between two applications on the same phone.
 *
 * **Secrets are shown in red and labelled.** `k_s^a` and the unblinding
 * inverse are displayed so the demonstration can be followed. In production
 * they are non-exportable and exist only inside the operations that use them.
 * The page says so where they appear rather than once in a document.
 */

import { RSABSSA } from '@cloudflare/blindrsa-ts';

const CONFIG_ORIGIN = document.body.dataset.configOrigin!;
const VRO_ORIGIN = document.body.dataset.vroOrigin!;
const EBB_ORIGIN = document.body.dataset.ebbOrigin!;
const suite = RSABSSA.SHA384.PSS.Deterministic();

const b64url = (b: Uint8Array): string =>
  btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64url = (s: string): Uint8Array =>
  Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const hex = (b: Uint8Array): string =>
  [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const status = (text: string, cls = '') => {
  const el = document.getElementById('status')!;
  el.textContent = text;
  el.className = cls;
};

interface Step {
  id: string;
  fig: string;
  title: string;
  where: string;
  why: string;
  action?: { label: string; run: () => Promise<void> };
}

const stepsEl = document.getElementById('steps')!;

function render(step: Step): void {
  const el = document.createElement('div');
  el.className = 'step todo';
  el.id = `step-${step.id}`;
  el.innerHTML =
    `<div class="head"><span class="fig">${step.fig}</span>` +
    `<span class="title">${step.title}</span>` +
    `<span class="where">${step.where}</span></div>` +
    `<div class="body"><p class="why">${step.why}</p><div class="content"></div></div>`;
  stepsEl.append(el);
  if (step.action) {
    const button = document.createElement('button');
    button.textContent = step.action.label;
    button.onclick = async () => {
      button.disabled = true;
      try { await step.action!.run(); }
      catch (err) { status(`${step.title} failed: ${err}`, 'warn'); button.disabled = false; }
    };
    el.querySelector('.content')!.append(button);
  }
}

const body = (id: string) => document.querySelector(`#step-${id} .content`)!;
const enable = (id: string) =>
  document.getElementById(`step-${id}`)!.classList.remove('todo');
const complete = (id: string) => {
  const el = document.getElementById(`step-${id}`)!;
  el.classList.remove('todo');
  el.classList.add('done');
};

function payload(id: string, caption: string, value: unknown, savable?: string) {
  const wrap = document.createElement('div');
  const pre = document.createElement('pre');
  pre.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  wrap.innerHTML = `<div style="font-size:12px;color:var(--dim)">${caption}</div>`;
  wrap.append(pre);
  if (savable) {
    const save = document.createElement('button');
    save.textContent = `Save ${savable}`;
    save.onclick = () => {
      const blob = new Blob([pre.textContent!], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = savable;
      a.click();
      URL.revokeObjectURL(a.href);
    };
    wrap.append(save);
  }
  body(id).append(wrap);
}

/** Values a production device would never expose. Shown, in red, and labelled. */
function secrets(id: string, entries: [string, string][]) {
  const box = document.createElement('div');
  box.className = 'secret';
  box.innerHTML = '<h4>never leaves the device in a deployment</h4>' +
    entries.map(([k, v]) => `<pre>${k} = ${v}</pre>`).join('') +
    '<p>Non-exportable in production: usable by the signing and blinding ' +
    'operations and readable by nothing — not the application, not a file, ' +
    'not a log.</p>';
  body(id).append(box);
}

let CONFIG: any;
let DIGEST = '';
let TOKEN_KEY: CryptoKey;
let ADHOC: CryptoKeyPair;
let ADHOC_PUBLIC: Uint8Array;
let BLINDED: Uint8Array;
let INV: Uint8Array;
let TOKEN: Uint8Array;

async function main() {
  status('Working…');

  render({
    id: 'config', fig: 'config', title: 'Pin the election configuration',
    where: 'from the config origin',
    why: 'The key every token must verify under comes from the published ' +
         'configuration, never from the office. An office that supplied the ' +
         'key its own signatures are checked against would make the ' +
         'single-key discipline of §3.3 vacuous.',
  });
  CONFIG = await (await fetch(`${CONFIG_ORIGIN}/election.json`)).json();
  DIGEST = (await (await fetch(`${CONFIG_ORIGIN}/election.json.sha256`)).text())
    .split(/\s+/)[0];
  const spki = unb64url(CONFIG.vro_token_key_spki);
  TOKEN_KEY = await crypto.subtle.importKey(
    'spki', spki, { name: 'RSA-PSS', hash: 'SHA-384' }, true, ['verify']);
  const fingerprint = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', spki)));
  payload('config', 'recomputed here, then compared with the published value', {
    election_id: CONFIG.election_id,
    choices: `1..${CONFIG.num_choices}`,
    config_digest: DIGEST,
    'k_p^(R) fingerprint': fingerprint,
    'agrees_with_published_by_VRO': fingerprint === CONFIG.vro_token_key_fingerprint,
  });
  complete('config');

  render({
    id: 'keygen', fig: '1/A', title: 'Generate the ad-hoc key pair',
    where: 'this device',
    why: 'One key pair, for this election only. Its public half is what the ' +
         'office will certify; its private half signs the ballot and nothing ' +
         'else, and is discarded when the election ends.',
    action: { label: 'Generate k_s^a, k_p^a', run: doKeygen },
  });
  enable('keygen');
  status('Ready. Each step waits for you.');
}

async function doKeygen() {
  ADHOC = await crypto.subtle.generateKey(
    { name: 'Ed25519' }, true, ['sign', 'verify']) as CryptoKeyPair;
  ADHOC_PUBLIC = new Uint8Array(await crypto.subtle.exportKey('raw', ADHOC.publicKey));
  const jwk = await crypto.subtle.exportKey('jwk', ADHOC.privateKey);

  payload('keygen', 'k_p^a — the ad-hoc public key. This is the message the ' +
          'office will sign, without being able to see it.', b64url(ADHOC_PUBLIC));
  secrets('keygen', [['k_s^a', String(jwk.d)]]);
  complete('keygen');

  render({
    id: 'blind', fig: '1/B · 2', title: 'Draw a blinding factor, and blind the key',
    where: 'this device',
    why: 'Blinding multiplies the padded encoding of k_p^a by r^e, so the ' +
         'office applies its private key to a value it cannot recognise. ' +
         'That is what makes the token unlinkable to the request that ' +
         'produced it — and the unlinkability is unconditional, not a ' +
         'promise by the office.',
    action: { label: 'Blind k_p^a', run: doBlind },
  });
  enable('blind');
  status('Key pair generated. Nothing has left this device.');
}

async function doBlind() {
  const blind = await suite.blind(TOKEN_KEY, suite.prepare(ADHOC_PUBLIC));
  BLINDED = blind.blindedMsg;
  INV = blind.inv;

  secrets('blind', [['r⁻¹', b64url(INV)]]);
  payload('blind', 'c — the blinded value. Discloses nothing: without r⁻¹ it is ' +
          'a uniform number in [0, n_R).', b64url(BLINDED));
  complete('blind');

  render({
    id: 'handover', fig: '→ 3', title: 'Hand the blinded key to the wallet',
    where: 'this device → the wallet',
    why: 'The only file in the sequence, and a file for a reason: on a real ' +
         'device this is an app-to-app invocation between two applications on ' +
         'the same phone. Nothing that identifies the voter is in it, and c is ' +
         'not a secret.',
  });
  payload('handover', 'blinded-key.json — NOT the token request. The token ' +
          'request is the package [id, c, s] that the wallet builds: it adds ' +
          'the identifier and its signature. This file carries only c.', {
    _transport: 'app-to-app invocation on a real device; a file here only ' +
                'because a browser page cannot invoke the wallet application',
    election_id: CONFIG.election_id,
    config_digest: DIGEST,
    blinded_key: b64url(BLINDED),
  }, 'blinded-key.json');
  complete('handover');

  render({
    id: 'collect', fig: '→ 8', title: 'Collect the office’s reply',
    where: 'this device → the office',
    why: 'The application asks the office directly, presenting c. The reply ' +
         'names nobody and is useless without r⁻¹, so it need not come back ' +
         'through the wallet. 404 until the wallet has transmitted.',
    action: { label: 'Collect s_c', run: doCollect },
  });
  enable('collect');
  status('Save the request and take it to the wallet, then collect the reply.');
}

async function doCollect() {
  for (let attempt = 0; attempt < 600; attempt++) {
    const response = await fetch(`${VRO_ORIGIN}/token-replies/${b64url(BLINDED)}`);
    if (response.ok) {
      const sc = unb64url((await response.json()).blind_signature);
      payload('collect', 's_c — the raw private-key operation applied to c', b64url(sc));
      complete('collect');
      await doUnblind(sc);
      return;
    }
    status(`Waiting for the office… (${attempt + 1})`);
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('no reply — has the wallet transmitted?');
}

async function doUnblind(sc: Uint8Array) {
  render({
    id: 'unblind', fig: '8', title: 'Remove the blinding, and verify',
    where: 'this device',
    why: 'Multiplying by r⁻¹ turns the office’s operation on c into an ' +
         'ordinary signature on k_p^a. This verification is the only moment ' +
         'the voter learns whether the office followed the protocol — and the ' +
         'entitlement is already spent if it did not (§5.5).',
  });
  TOKEN = await suite.finalize(TOKEN_KEY, ADHOC_PUBLIC, sc, INV);
  const valid = await suite.verify(TOKEN_KEY, TOKEN, ADHOC_PUBLIC);
  payload('unblind', 's_{k_p^a} — the token. An ordinary RSA-PSS signature now; ' +
          'any library checks it against the published key.', {
    token: b64url(TOKEN), verifies_under_pinned_key: valid });
  complete('unblind');
  if (!valid) { status('The office returned a signature that does not verify.', 'warn'); return; }

  render({
    id: 'mark', fig: '9', title: 'Mark the ballot',
    where: 'this device',
    why: 'One ballot carries exactly one selection. A value outside the list ' +
         'authenticates like any other and is recorded as invalid rather than ' +
         'rejected; no authority approves what it means.',
  });
  const list = document.createElement('div');
  for (let i = 1; i <= CONFIG.num_choices; i++) {
    list.innerHTML += `<label><input type="radio" name="choice" value="${i}"> option ${i}</label>`;
  }
  list.innerHTML += '<label style="margin-top:.4rem"><input type="radio" name="choice" ' +
    'value="protest"> something else — <input type="number" id="protest" ' +
    'style="width:7rem" value="-1" disabled></label>';
  body('mark').append(list);
  const sign = document.createElement('button');
  sign.textContent = 'Sign the ballot';
  sign.disabled = true;
  sign.style.marginTop = '.6rem';
  body('mark').append(sign);
  list.onchange = () => {
    const picked = document.querySelector<HTMLInputElement>('input[name=choice]:checked');
    (document.getElementById('protest') as HTMLInputElement).disabled =
      picked?.value !== 'protest';
    sign.disabled = !picked;
  };
  sign.onclick = async () => {
    sign.disabled = true;
    const picked = document.querySelector<HTMLInputElement>('input[name=choice]:checked')!;
    complete('mark');
    await doSign(picked.value === 'protest'
      ? Number((document.getElementById('protest') as HTMLInputElement).value)
      : Number(picked.value));
  };
  enable('mark');
  status('Token obtained and verified. The office cannot link it to the request it signed.');
}

async function doSign(selection: number) {
  const canonical = JSON.stringify({
    adhoc_public_key: b64url(ADHOC_PUBLIC), selection });
  const digest = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical)));
  const voteSignature = new Uint8Array(
    await crypto.subtle.sign({ name: 'Ed25519' }, ADHOC.privateKey, digest));
  const ballot = {
    selection,
    adhoc_public_key: b64url(ADHOC_PUBLIC),
    token: b64url(TOKEN),
    vote_signature: b64url(voteSignature),
  };

  render({
    id: 'cast', fig: '9 → 10/1', title: 'Cast the ballot',
    where: 'this device → the ballot box',
    why: 'The signature covers the canonical form of the selection and the ' +
         'ad-hoc key, so altering either in transit invalidates it. The box ' +
         'checks the token under the published key, and the selection under ' +
         'the key that token certifies.',
    action: { label: 'Send to the ballot box', run: () => doCast(ballot) },
  });
  payload('cast', 'the ballot, exactly as it will be sent', ballot, 'ballot.json');
  payload('cast', 'the bytes the ballot signature covers', canonical);
  enable('cast');
  status('Ballot signed. Nothing has been sent yet.');
}

async function doCast(ballot: object) {
  const receipt = await (await fetch(`${EBB_ORIGIN}/ballots`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(ballot),
  })).json();
  complete('cast');

  render({
    id: 'receipt', fig: '11/A', title: 'Receipt',
    where: 'the ballot box → this device',
    why: 'The position in the registry and the head of the hash chain at the ' +
         'moment of acceptance. With these a voter can later show that the ' +
         'entry has not been removed, reordered or altered — demonstrable ' +
         'rather than merely alleged.',
  });
  payload('receipt', 'keep this: it is the evidence', receipt, 'receipt.json');
  complete('receipt');
  status(receipt.accepted
    ? 'Ballot accepted. You may cast again; the last accepted ballot counts.'
    : `Rejected: ${receipt.reason}`, receipt.accepted ? 'ok' : 'warn');
}

main().catch((err) => status(`Failed: ${err}`, 'warn'));
