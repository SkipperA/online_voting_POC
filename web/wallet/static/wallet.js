/**
 * The wallet's consent page. No bundler: it needs no cryptography of its own.
 *
 * The signing happens in the wallet daemon behind this origin, which is where
 * the key lives. What the page contributes is the part that cannot be
 * delegated -- showing the voter what they are about to authorise, in a
 * surface the voting application does not control.
 *
 * It checks the request against the configuration it fetches *itself*, and
 * refuses on a mismatch. Otherwise a forged voting application could hand the
 * voter a file for a different election and the wallet would sign it blind,
 * which is precisely what this screen exists to prevent.
 */
const CONFIG_ORIGIN = document.body.dataset.configOrigin;

const $ = (id) => document.getElementById(id);
const show = (id, text, state) => {
  const el = $(id);
  el.textContent = text;
  if (state) el.className = `value ${state}`;
};

let request = null;
let config = null;

async function loadConfig() {
  config = await (await fetch(`${CONFIG_ORIGIN}/election.json`)).json();
  const line = await (await fetch(`${CONFIG_ORIGIN}/election.json.sha256`)).text();
  config.digest = line.split(/\s+/)[0];
}

async function loadPersonas() {
  const personas = (await (await fetch('/personas')).json()).personas;
  for (const select of [$('persona'), $('query-persona')]) {
    select.innerHTML = '<option value="">—</option>';
    for (const id of personas) {
      const option = document.createElement('option');
      option.value = id;
      option.textContent = id;
      select.append(option);
    }
  }
}

function ready() {
  $('sign').disabled = !(request && $('persona').value);
}

$('file').onchange = async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  try {
    request = JSON.parse(await file.text());
  } catch {
    show('status', 'That file is not a token request.');
    return;
  }

  // The two checks that make the consent screen worth having.
  const sameElection = request.election_id === config.election_id;
  const sameConfig = request.config_digest === config.digest;
  show('election', `${request.election_id}`, sameElection ? 'ok' : 'warn');
  show('digest', sameConfig
        ? 'matches the configuration this wallet fetched'
        : `MISMATCH\n  request : ${request.config_digest}\n  current : ${config.digest}\n` +
          '  Most likely the service was restarted after the request was saved, ' +
          'which mints a new election. Reload the voting application and save a ' +
          'new request.',
      sameConfig ? 'ok' : 'warn');
  show('blinded', `${request.blinded_key.slice(0, 32)}…`);

  if (!sameElection || !sameConfig) {
    request = null;
    $('sign').disabled = true;
    show('status', 'Refused: the request does not match this election. '
                 + 'Reload the voting application and save a new request.');
    return;
  }
  show('status', 'Request loaded. Choose who signs, then consent.');
  ready();
};

$('persona').onchange = ready;

function dump(target, caption, value, filename) {
  const el = $(target);
  const pre = document.createElement('pre');
  pre.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  const cap = document.createElement('div');
  cap.style.cssText = 'font-size:12px;color:#777;margin-top:.5rem';
  cap.textContent = caption;
  el.append(cap, pre);
  if (filename) {
    const b = document.createElement('button');
    b.textContent = `Save ${filename}`;
    b.onclick = () => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([pre.textContent],
                                            { type: 'application/json' }));
      a.download = filename; a.click(); URL.revokeObjectURL(a.href);
    };
    el.append(b);
  }
}

$('persona').onchange = async () => {
  ready();
  $('keys').innerHTML = '';
  if (!$('persona').value) return;
  await fetch('/session', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ voter_id: $('persona').value }),
  });
  document.getElementById('title').textContent =
    `Digital Identity Wallet — ${$('persona').value}`;
  const keys = await (await fetch('/keys')).json();
  const box = document.createElement('div');
  box.className = 'secret';
  box.innerHTML = '<h4>never exists outside hardware in a deployment</h4>' +
    `<pre>k_p^(v) = ${keys['k_p^(v)']}</pre>` +
    `<pre>k_s^(v) = ${keys['k_s^(v)']}</pre>` +
    `<p>${keys._never_exposed_in_a_deployment}</p>`;
  $('keys').append(box);
};

$('sign').onclick = async () => {
  $('sign').disabled = true;
  show('status', 'Signing and transmitting…');
  const response = await fetch('/requests', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ blinded_key: request.blinded_key }),
  });
  const result = await response.json();
  show('outcome', result.outcome, result.outcome === 'ISSUED' ? 'ok' : 'warn');
  $('sent').innerHTML = '';
  dump('sent', 'hash([id, c]) — exactly the bytes signed', result.signed_bytes);
  dump('sent', '[id, c, s] — transmitted by the wallet to the office',
       result.transmitted, 'auth-request.json');
  show('status', result.outcome === 'ISSUED'
    ? 'Transmitted. Return to the voting application — it collects the reply itself.'
    : `The office refused: ${result.outcome}.`);
};

$('query-persona').onchange = () => {
  $('save-query').disabled = !$('query-persona').value;
};

$('save-query').onclick = async () => {
  await fetch('/session', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ voter_id: $('query-persona').value }),
  });
  const credentials = await (await fetch('/release-query-credentials', {
    method: 'POST' })).json();
  const blob = new Blob([JSON.stringify(credentials, null, 2)],
                        { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'release-query.json';
  a.click();
  URL.revokeObjectURL(a.href);
  show('status', 'Saved. Load it into the checker on 8005.');
};

(async () => {
  await loadConfig();
  await loadPersonas();
  show('status', 'Choose a request file.');
})();
