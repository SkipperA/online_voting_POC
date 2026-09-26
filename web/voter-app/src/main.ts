/**
 * The voter's application: blinding here, the token collected from the office.
 *
 * Nothing on this origin reads, requests or receives `id`, and there is no
 * code path to one. The handover to the wallet is a file the voter saves and
 * carries -- the browser's own download, then the browser's own file picker
 * on the wallet's page. Clumsy on purpose: nothing passes between the two
 * origins except what the voter moved, so the boundary is not a claim about
 * configuration but a fact about what crossed.
 *
 * Nothing comes back through the page either. The wallet transmits `[id, c,
 * s]` to the office itself (B7), and this application collects the reply by
 * presenting `c`, which it has held since it generated it (B16). A 404 means
 * "not yet". So the file crosses in one direction and there is no return
 * channel to design, no correlation handle to invent, and no moment at which
 * the application must be told anything.
 */

import { RSABSSA } from '@cloudflare/blindrsa-ts';

const CONFIG_ORIGIN = document.body.dataset.configOrigin!;
const VRO_ORIGIN = document.body.dataset.vroOrigin!;
const suite = RSABSSA.SHA384.PSS.Deterministic();

const b64url = (b: Uint8Array): string =>
  btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const unb64url = (s: string): Uint8Array =>
  Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

const hex = (b: Uint8Array): string =>
  [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

function show(id: string, value: string, state: 'ok' | 'warn' | 'plain' = 'plain') {
  const el = document.getElementById(id)!;
  el.textContent = value;
  if (id !== 'status') el.className = `value ${state}`;
}

async function main() {
  // Set by the script, so "Loading…" persisting means the script never ran
  // rather than meaning it is slow. The previous wording made a bundle that
  // failed to load look like one that was merely working.
  show('status', 'Working…');

  // 1. The configuration, from the config origin. Never from the VRO: an
  //    office that supplied the key its own signatures are checked against
  //    would make the single-key discipline of §3.3 vacuous.
  const config = await (await fetch(`${CONFIG_ORIGIN}/election.json`)).json();
  const digestLine = await (await fetch(`${CONFIG_ORIGIN}/election.json.sha256`)).text();
  show('election', config.election_id);
  show('choices', `1..${config.num_choices}`);
  show('digest', digestLine.split(/\s+/)[0]);

  // 2. Import k_p^(R) and recompute its fingerprint rather than believing
  //    the one printed beside it.
  const spki = unb64url(config.vro_token_key_spki);
  const tokenKey = await crypto.subtle.importKey(
    'spki', spki, { name: 'RSA-PSS', hash: 'SHA-384' }, true, ['verify'],
  );
  const fingerprint = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', spki)));
  const agrees = fingerprint === config.vro_token_key_fingerprint;
  show('fingerprint', fingerprint, agrees ? 'ok' : 'warn');
  show('fp-agrees', agrees ? 'recomputed here, matches the published value'
                           : 'MISMATCH — this key is not the one published',
       agrees ? 'ok' : 'warn');
  show('modulus', `${(tokenKey.algorithm as RsaHashedKeyAlgorithm).modulusLength} bits`);

  // 3. The ad-hoc key pair. Generated here, and the private half never
  //    leaves: `extractable: false` means the page itself cannot export it.
  const adhoc = await crypto.subtle.generateKey(
    { name: 'Ed25519' }, false, ['sign', 'verify'],
  ) as CryptoKeyPair;
  const adhocPublic = new Uint8Array(await crypto.subtle.exportKey('raw', adhoc.publicKey));
  show('adhoc', hex(adhocPublic));
  show('adhoc-private', 'non-extractable — this page cannot read it', 'ok');

  // 4. Blind it. This is the step the whole design rests on: the office
  //    signs a value it cannot recognise, so it cannot later link the token
  //    to the citizen who asked for it.
  const prepared = suite.prepare(adhocPublic);
  const identical = prepared.length === adhocPublic.length &&
    prepared.every((b, i) => b === adhocPublic[i]);
  show('prepare', identical ? 'identity, as the Deterministic variant requires'
                            : 'UNEXPECTED — prepare() altered the message', identical ? 'ok' : 'warn');

  const { blindedMsg, inv } = await suite.blind(tokenKey, prepared);
  show('suite', suite.toString(), 'ok');
  show('blinded', `${blindedMsg.length} bytes · ${hex(blindedMsg.slice(0, 16))}…`);
  (document.getElementById('blinded') as HTMLElement).dataset.b64 = b64url(blindedMsg);
  show('inverse', `${inv.length} bytes, held here and nowhere else`);

  // 5. The handover. `c` is not a secret worth protecting: §5.3 notes that an
  //    intercepted `c` yields no advantage, because unblinding needs the `r`
  //    that never leaves this application. A file in Downloads discloses
  //    nothing about the voter or the vote.
  const request = {
    election_id: config.election_id,
    config_digest: digestLine.split(/\s+/)[0],
    blinded_key: b64url(blindedMsg),
  };
  const save = document.getElementById('save') as HTMLButtonElement;
  save.disabled = false;
  save.onclick = () => {
    const blob = new Blob([JSON.stringify(request, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'token-request.json';
    a.click();
    URL.revokeObjectURL(a.href);
    poll(tokenKey, adhocPublic, inv).catch((err) => {
      // A rejected fetch here is almost always the office refusing to be read
      // cross-origin. Left uncaught it leaves a status line that looks like
      // patience rather than failure.
      show('status', `Could not reach the office: ${err}`);
    });
  };

  show('status', 'Blinded. Save the request and take it to the wallet.');
}

/**
 * B16–B18. Poll, unblind, and verify before `r` is discarded.
 *
 * The verification is the only moment at which the voter learns whether the
 * office followed the protocol, and by then their single entitlement is
 * already spent -- which is why §5.5 requires a documented re-issuance path.
 */
async function poll(tokenKey: CryptoKey, adhocPublic: Uint8Array, inv: Uint8Array) {
  const c = (document.getElementById('blinded') as HTMLElement).dataset.b64!;
  show('status', 'Waiting for the office to release a token…');
  for (let attempt = 0; attempt < 600; attempt++) {
    const response = await fetch(`${VRO_ORIGIN}/token-replies/${c}`);
    if (response.ok) {
      const blindSignature = unb64url((await response.json()).blind_signature);
      const token = await suite.finalize(tokenKey, adhocPublic, blindSignature, inv);
      const valid = await suite.verify(tokenKey, token, adhocPublic);
      show('token', `${token.length} bytes · ${hex(token.slice(0, 16))}…`);
      show('token-valid',
           valid ? 'verifies under the pinned k_p^(R) — an ordinary RSA-PSS signature now'
                 : 'DOES NOT VERIFY — the office did not follow the protocol',
           valid ? 'ok' : 'warn');
      show('status', valid
        ? 'Token obtained and verified. The office cannot link it to the request it signed.'
        : 'The office returned a signature that does not verify.');
      return;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  show('status', 'No reply from the office. The wallet may not have transmitted yet.');
}

main().catch((err) => {
  document.getElementById('status')!.textContent = `Failed: ${err}`;
  document.getElementById('status')!.className = 'warn';
});
