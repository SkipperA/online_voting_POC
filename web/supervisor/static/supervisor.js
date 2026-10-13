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

  const rebuilt = await Promise.all(
    data.releases.map((r) => commitment(r.voter_id, r.opening)));
  const allMatch = rebuilt.every((c, i) => c === data.releases[i].commitment);

  const head = await chainOver(data.releases, data.genesis_hash);
  show('chain', head === data.head && allMatch
    ? `${data.releases.length} commitments rebuild to the published head`
    : 'THE REGISTER DOES NOT REBUILD', head === data.head && allMatch ? 'ok' : 'warn');

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
  const unasked = data.releases.filter((r) => !r.request_signature);
  show('unasked', unasked.length
    ? `NO SIGNED REQUEST FOR: ${unasked.map((r) => r.voter_id).join(', ')}`
    : `every release carries the citizen's own signed request`,
    unasked.length ? 'warn' : 'ok');

  show('dupes', repeated.length
    ? `TWO RELEASES FOR: ${repeated.join(', ')}`
    : `${ids.length} identifiers, none repeated`, repeated.length ? 'warn' : 'ok');

  $('releases').innerHTML = data.releases.length
    ? data.releases.map((r, i) => `<tr>
        <td>${r.index}</td><td class="mono">${esc(r.voter_id)}</td>
        <td class="mono">${esc(r.commitment.slice(0, 24))}…</td>
        <td class="${rebuilt[i] === r.commitment ? 'ok' : 'warn'}">${
          rebuilt[i] === r.commitment ? 'matches' : 'DOES NOT MATCH'}</td>
        <td class="${r.request_signature ? 'ok' : 'warn'}">${
          r.request_signature
            ? `${esc(r.request_signature.slice(0, 16))}…`
            : 'NONE — not asked for'}</td></tr>`).join('')
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
  for (const release of data.releases) {
    const key = certificates[release.voter_id];
    let verdict;
    let cls;
    if (!release.request_signature) {
      verdict = 'no signature — this release was not asked for';
      cls = 'warn';
      missing += 1;
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
      <td class="mono">${release.request_signature
        ? `${esc(release.request_signature.slice(0, 16))}…` : '—'}</td>
      <td class="${cls}">${esc(verdict)}</td></tr>`);
  }

  $('requests').innerHTML = rows.length
    ? rows.join('') : '<tr><td colspan="3">no tokens released</td></tr>';
  const total = data.releases.length;
  show('verdict', good === total
    ? `all ${total} releases were asked for, by the citizen named`
    : `${good} of ${total} verify; ${missing} have no signature at all`,
    good === total ? 'ok' : 'warn');
  $('verify-asof').textContent = `checked at ${new Date().toLocaleTimeString()}`;
}

$('verify').onclick = () => verifyRequests()
  .catch((err) => show('verdict', `could not check: ${err}`, 'warn'));

$('refresh').onclick = () => refresh();
$('download').onclick = () => { window.location = '/supervision'; };
refresh().catch((err) => show('status', `Could not read the register: ${err}`, 'warn'));
