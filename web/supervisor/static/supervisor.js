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
const escape = (s) => String(s).replace(/[&<>]/g,
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
  show('dupes', repeated.length
    ? `TWO RELEASES FOR: ${repeated.join(', ')}`
    : `${ids.length} identifiers, none repeated`, repeated.length ? 'warn' : 'ok');

  $('releases').innerHTML = data.releases.length
    ? data.releases.map((r, i) => `<tr>
        <td>${r.index}</td><td class="mono">${escape(r.voter_id)}</td>
        <td class="mono">${escape(r.commitment.slice(0, 24))}…</td>
        <td class="${rebuilt[i] === r.commitment ? 'ok' : 'warn'}">${
          rebuilt[i] === r.commitment ? 'matches' : 'DOES NOT MATCH'}</td></tr>`).join('')
    : '<tr><td colspan="4">no tokens released</td></tr>';

  $('audit').innerHTML = data.audit.length
    ? data.audit.map((e) => `<tr>
        <td class="mono">${escape(e.voter_id)}</td><td>${escape(e.outcome)}</td>
        <td>${escape(e.reason)}</td></tr>`).join('')
    : '<tr><td colspan="3">nothing recorded</td></tr>';

  $('asof').textContent = `as of ${new Date().toLocaleTimeString()}`;
  show('status', 'Every figure above was recomputed here from the office\u2019s '
     + 'own record, against keys from the published configuration.', 'ok');
}

$('refresh').onclick = () => refresh();
$('download').onclick = () => { window.location = '/supervision'; };
refresh().catch((err) => show('status', `Could not read the register: ${err}`, 'warn'));
