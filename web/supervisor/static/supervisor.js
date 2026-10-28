/**
 * The release register with identifiers, checked rather than displayed.
 *
 * Everything on the page is recomputed here: each commitment from its
 * [id, opening] pair, the chain from the genesis hash, and the office's
 * signatures against the keys pinned in the published configuration. A
 * supervisor who only read the numbers would be taking the word of the
 * party being supervised.
 */
const CONFIG = document.body.dataset.configOrigin;
const $ = (id) => document.getElementById(id);
const show = (id, text, cls) => {
  const e = $(id); e.textContent = text; e.className = `value ${cls || ''}`;
};
/**
 * Not `escape`: that is a built-in global, the legacy URL encoder, and a
 * page that calls it without defining its own gets %20 where it wanted a
 * space. Shadowing a global to mean something else is the trap; a name of
 * our own is the way out of it.
 */
const esc = (s) => String(s).replace(/[&<>]/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

const unb64 = (t) => Uint8Array.from(
  atob(t.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const b64 = (bytes) => btoa(String.fromCharCode(...bytes))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const hex = (bytes) => Array.from(bytes)
  .map((x) => x.toString(16).padStart(2, '0')).join('');

const sha256 = async (bytes) =>
  new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));

/** Canonical JSON: sorted keys, no whitespace. Keys are written in order. */
const canonical = (obj) => new TextEncoder().encode(JSON.stringify(obj));

async function verifyStatement(publicKeyB64, statement, signatureB64) {
  const key = await crypto.subtle.importKey(
    'raw', unb64(publicKeyB64), { name: 'Ed25519' }, false, ['verify']);
  const payload = await sha256(canonical(statement));
  return crypto.subtle.verify({ name: 'Ed25519' }, key, unb64(signatureB64), payload);
}

const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};

const fromHex = (h) => Uint8Array.from(h.match(/../g).map((b) => parseInt(b, 16)));

const beU64 = (n) => {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n));
  return out;
};

/** H(id ‖ opening) — the commitment the office published for one release. */
async function commitment(voterId, openingB64) {
  return b64(await sha256(concat(
    new TextEncoder().encode(voterId), unb64(openingB64))));
}

/** H(index ‖ prev ‖ canonical(payload)) at each position, as the ledger chains it. */
async function chainOver(entries, genesisHex) {
  let head = fromHex(genesisHex);
  for (let i = 0; i < entries.length; i += 1) {
    head = await sha256(concat(
      beU64(i), head, canonical({ commitment: entries[i].commitment })));
  }
  return hex(head);
}

async function refresh() {
  const response = await fetch('/data');
  if (response.status === 409) {
    show('status', 'The ballot box is still open. The register with identifiers '
       + 'in it is a live list of who has taken part, so it opens at the close.',
         'warn');
    return;
  }
  const data = await response.json();
  const config = await (await fetch(`${CONFIG}/election.json`)).json();
  const office = config.vro_statement_key;

  show('count', `${data.count}`);
  show('downloads', `${data.supervisor_downloads ?? '—'}`, 'muted');

  /*
   * Two checks, two verdicts. They used to be one line reading "the
   * register does not rebuild", which said that something was wrong with
   * the register and nothing about what -- and the two halves fail for
   * unrelated reasons and have unrelated remedies.
   *
   * Each commitment is H(id ‖ opening) over the pair the office holds, so
   * a mismatch means the office's own openings do not account for what it
   * published: the entry at that position names a citizen the commitment
   * does not cover. The identifiers are what is in doubt, and the rows
   * below name which ones.
   *
   * The chain is computed over the *published* commitments, in the order
   * published, from the genesis hash in the configuration. It can fail
   * with every commitment recomputing perfectly: an entry inserted,
   * dropped or reordered leaves each remaining commitment correct and the
   * head wrong. There the identifiers are sound and the sequence is not.
   *
   * So the first can fail while the second passes, and the second can
   * fail while the first passes. One verdict for both could only ever
   * name the weaker of the two findings.
   */
  const rebuilt = await Promise.all(
    data.releases.map((r) => commitment(r.voter_id, r.opening)));
  const wrong = data.releases
    .map((r, i) => (rebuilt[i] === r.commitment ? null : r.index))
    .filter((i) => i !== null);
  const total = data.releases.length;
  show('commitments', wrong.length
    ? `${wrong.length} of ${total} DO NOT RECOMPUTE — at position${
        wrong.length === 1 ? '' : 's'} ${wrong.join(', ')}`
    : `all ${total} recompute from the office's own [id, opening] pairs`,
    wrong.length ? 'warn' : 'ok');

  const head = await chainOver(data.releases, data.genesis_hash);
  show('chain', head === data.head
    ? `${total} commitments chain from the genesis hash to the signed head`
    // Short, because these cells are styled for base64 -- `word-break:
    // break-all` -- and a long sentence in one comes apart mid-word. The
    // prose under the rows carries what this failure means.
    : 'THE CHAIN DOES NOT REACH THE PUBLISHED HEAD',
    head === data.head ? 'ok' : 'warn');

  const headOk = await verifyStatement(office, {
    election_id: config.election_id, head: b64(fromHex(data.head)),
    statement: 'release-register-head',
  }, data.head_signature).catch(() => false);
  show('head-sig', headOk ? 'verifies' : 'DOES NOT VERIFY', headOk ? 'ok' : 'warn');

  const countOk = await verifyStatement(office, {
    count: data.count, election_id: config.election_id, statement: 'tokens-released',
  }, data.count_signature).catch(() => false);
  show('count-sig', countOk ? 'verifies' : 'DOES NOT VERIFY', countOk ? 'ok' : 'warn');

  const ids = data.releases.map((r) => r.voter_id);
  const repeated = [...new Set(ids.filter((v, i) => ids.indexOf(v) !== i))];
  // Neither kind of evidence, not merely "no Ed25519 signature". A
  // release asked for with a qualified electronic signature carries a
  // document digest instead, and reading its absence from this field as
  // "not asked for" accused the office of minting a token for a citizen
  // who had in fact asked with the strongest evidence in the system.
  // Clause S7, said before anything below is read. An office that enrols
  // a citizen because they asked cannot be checked against its own roll,
  // and the comparison this page opens with is the one that stops meaning
  // what it says. Printing it here rather than as a footnote, because a
  // reader who scrolls past it draws the wrong conclusion from every row.
  const grown = (data.self_enrolled || []).length;
  $('s7').innerHTML = data.enrol_on_qualified_signature
    ? `<div class="note note--substituted">`
      + `<span class="kind">Substituted · <code>S7</code></span>`
      + `<b>This office enrols citizens on their own signature</b>`
      + `A qualified signature is treated as the entitlement to vote, so an `
      + `identifier this office had never heard of was added to the roll when `
      + `it asked. ${grown} of the entries below arrived that way and are `
      + `marked. For those, comparing this register against the roll above `
      + `is not an independent check: the office was not given a roll naming `
      + `them, and a DÁP certificate carries no age, no citizenship and no `
      + `address — registration opens at fourteen. A real election closes `
      + `that gap with an attribute attestation, not by assuming.</div>`
    : '';

  const unasked = data.releases.filter((r) => evidence(r).kind === 'none');
  show('unasked', unasked.length
    ? `NO SIGNED REQUEST FOR: ${unasked.map((r) => r.voter_id).join(', ')}`
    : `every release carries the citizen's own signed request`,
    unasked.length ? 'warn' : 'ok');

  show('dupes', repeated.length
    ? `TWO RELEASES FOR: ${repeated.join(', ')}`
    : `${ids.length} identifiers, none repeated`, repeated.length ? 'warn' : 'ok');

  $('releases').innerHTML = data.releases.length
    ? data.releases.map((r, i) => `<tr>
        <td>${r.index}</td><td class="mono">${esc(r.voter_id)}${
          r.self_enrolled ? ' <span class="warn">· self-enrolled</span>' : ''}</td>
        <td class="mono">${esc(r.commitment.slice(0, 24))}…</td>
        <td class="${rebuilt[i] === r.commitment ? 'ok' : 'warn'}">${
          rebuilt[i] === r.commitment ? 'matches' : 'DOES NOT MATCH'}</td>
        <td class="${evidence(r).kind === 'none' ? 'warn' : 'ok'}">${
          esc(evidence(r).shown)}</td></tr>`).join('')
    : '<tr><td colspan="5">no tokens released</td></tr>';

  $('audit').innerHTML = data.audit.length
    ? data.audit.map((e) => `<tr>
        <td class="mono">${esc(e.voter_id)}</td><td>${esc(e.outcome)}</td>
        <td>${esc(e.reason)}</td></tr>`).join('')
    : '<tr><td colspan="3">nothing recorded</td></tr>';

  $('asof').textContent = `as of ${new Date().toLocaleTimeString()}`;
  show('status', 'Every figure above was recomputed here from the office\u2019s '
     + 'own record, against keys from the published configuration.', 'ok');
}

/**
 * What this release carries as the citizen's own request, by route.
 *
 * Two shapes, because there are two routes and the office must not differ
 * by a line below the identity boundary. The wallet route publishes the
 * Ed25519 signature itself; the qualified-signature route publishes the
 * signed document's digest and length and *not* the document, because
 * that document is verifiable by anyone against the European trust lists
 * without this office's cooperation and is therefore a far more portable
 * proof that a named citizen took part than anything the first route
 * produces (§3.7).
 *
 * A page that knew only the first shape reported the second as "NONE —
 * not asked for", which is the worst available misreading: it accuses
 * the office of inventing a release that was in fact asked for with a
 * qualified electronic signature.
 */
function evidence(release) {
  if (release.request_signature) {
    return {
      kind: 'wallet',
      shown: `${release.request_signature.slice(0, 16)}…`,
    };
  }
  if (release.request_document_sha256) {
    // Three states, and `null` is not `false`. The office answers `null`
    // when it had no trusted list to judge against, which is a fact about
    // its configuration; `false` is a finding about this signature.
    const q = release.request_qualified;
    return {
      kind: 'document',
      digest: release.request_document_sha256,
      qualified: q,
      note: q === true ? 'qualified electronic signature'
          : q === false ? 'a signature, but not a qualified one'
          : 'qualification not established — this office had no trusted list',
      shown: `sha-256 ${release.request_document_sha256.slice(0, 16)}…`
           + ` (${release.request_document_bytes} bytes)`
           + (q === true ? ' · qualified' : q === false ? ' · not qualified' : ''),
    };
  }
  return { kind: 'none', shown: 'NONE — not asked for' };
}

/**
 * D: were the released tokens asked for?
 *
 * The signature is checked here rather than displayed. A page that showed
 * the first few characters would catch a release the office invented out
 * of nothing and miss one carrying plausible rubbish, which is most of the
 * way to catching nothing.
 */
async function verifyRequests() {
  const data = await (await fetch('/data')).json();
  const { certificates } = await (await fetch('/certificates')).json();

  const rows = [];
  let good = 0;
  let missing = 0;
  let qualified = 0;
  for (const release of data.releases) {
    const key = certificates[release.voter_id];
    let verdict;
    let cls;
    const carried = evidence(release);
    if (carried.kind === 'none') {
      verdict = 'no signature — this release was not asked for';
      cls = 'warn';
      missing += 1;
    } else if (carried.kind === 'document') {
      // Honest about what this page can and cannot establish. The
      // signature is over a document this origin deliberately does not
      // publish, so it cannot be verified here at all -- calling that a
      // failure would be as wrong as calling it a pass. What the office
      // *did* establish, against its pinned trusted list, is reported as
      // it found it, including that it had no standing to find anything.
      verdict = `${carried.note}; the document is not published here, so `
              + 'check it against the digest above';
      cls = carried.qualified === true ? 'ok' : '';
      qualified += 1;
    } else if (!key) {
      verdict = 'no certificate on file for this identifier';
      cls = 'warn';
    } else {
      const ok = await verifyStatement(
        key,
        { blinded_key: release.blinded_key, voter_id: release.voter_id },
        release.request_signature).catch(() => false);
      verdict = ok ? `the key certified to ${release.voter_id}`
                   : 'DOES NOT VERIFY under that citizen\'s key';
      cls = ok ? 'ok' : 'warn';
      if (ok) good += 1;
    }
    rows.push(`<tr><td class="mono">${esc(release.voter_id)}</td>
      <td class="mono">${esc(carried.shown)}</td>
      <td class="${cls}">${esc(verdict)}</td></tr>`);
  }

  $('requests').innerHTML = rows.length
    ? rows.join('') : '<tr><td colspan="3">no tokens released</td></tr>';
  const total = data.releases.length;
  // Three buckets, not two, and the middle one is not a failure. Folding
  // the qualified-signature releases into either end would be this page
  // reporting a limitation of its own as a finding about the office.
  show('verdict', missing === 0
    ? `all ${total} releases were asked for: ${good} checked here, `
      + `${qualified} carrying a qualified signature to be checked against `
      + 'the document'
    : `${good} of ${total} verify here, ${qualified} are qualified `
      + `signatures, and ${missing} have no request behind them at all`,
    missing === 0 ? 'ok' : 'warn');
  $('verify-asof').textContent = `checked at ${new Date().toLocaleTimeString()}`;
}

$('verify').onclick = () => verifyRequests()
  .catch((err) => show('verdict', `could not check: ${err}`, 'warn'));

$('refresh').onclick = () => refresh();
$('download').onclick = () => { window.location = '/supervision'; };
refresh().catch((err) => show('status', `Could not read the register: ${err}`, 'warn'));


/**
 * Tie a signed document to a release, in the supervisor's own browser.
 *
 * This is what the published digest is *for*. The office withholds the
 * document because it is a portable proof that a named citizen took part
 * (§3.7), and a supervisor who has obtained one by some other route --
 * from the citizen, from a complaint, from a court -- can establish that
 * it is the request behind a particular release without asking the office
 * to confirm anything. The office cannot lie about a digest it published
 * and signed the chain over.
 *
 * Nothing leaves the page. A supervision surface that uploaded the
 * document in order to check it would be handing the office the one
 * artefact it was careful not to hold.
 */
document.getElementById('match-file')?.addEventListener('change', async (event) => {
  const where = document.getElementById('match-result');
  const file = event.target.files[0];
  if (!file) { where.textContent = '—'; return; }

  const bytes = new Uint8Array(await file.arrayBuffer());
  const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))]
    .map((b) => b.toString(16).padStart(2, '0')).join('');

  const data = await (await fetch('/data')).json();
  const hit = data.releases.find((r) => r.request_document_sha256 === digest);
  where.className = hit ? 'value ok' : 'value warn';
  where.textContent = hit
    ? `matches release ${hit.index}, ${hit.voter_id}`
    : `no release carries this digest (${digest.slice(0, 16)}…)`;
});
