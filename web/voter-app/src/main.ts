/**
 * Step one of the voter's application: the cryptography, and nothing else.
 *
 * No wallet, no ballot, no submission. What this page establishes is that
 * the blinding the design requires can be performed on the voter's own
 * device, in a browser, against the key the election publishes -- because
 * everything later is built on that and it is the part that could have
 * failed.
 *
 * Nothing here reads, requests or receives `id`. There is no code path to
 * one: the wallet holds it, and this origin never speaks to the wallet in
 * this step at all.
 */

import { RSABSSA } from '@cloudflare/blindrsa-ts';

const CONFIG_ORIGIN = document.body.dataset.configOrigin!;
const suite = RSABSSA.SHA384.PSS.Deterministic();

const unb64url = (s: string): Uint8Array =>
  Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

const hex = (b: Uint8Array): string =>
  [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

function show(id: string, value: string, state: 'ok' | 'warn' | 'plain' = 'plain') {
  const el = document.getElementById(id)!;
  el.textContent = value;
  el.className = `value ${state}`;
}

async function main() {
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
  show('inverse', `${inv.length} bytes, held here and nowhere else`);

  document.getElementById('status')!.textContent =
    'Blinding performed in this browser. No identifier was read, requested or received.';
}

main().catch((err) => {
  document.getElementById('status')!.textContent = `Failed: ${err}`;
  document.getElementById('status')!.className = 'warn';
});
