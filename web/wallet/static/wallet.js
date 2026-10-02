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

$('sign').onclick = async () => {
  $('sign').disabled = true;
  show('status', 'Signing and transmitting…');
  await fetch('/session', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ voter_id: $('persona').value }),
  });
  const response = await fetch('/requests', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ blinded_key: request.blinded_key }),
  });
  const outcome = (await response.json()).outcome;
  show('outcome', outcome, outcome === 'ISSUED' ? 'ok' : 'warn');
  show('status', outcome === 'ISSUED'
    ? 'Transmitted. Return to the voting application — it is collecting the reply.'
    : `The office refused: ${outcome}.`);
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
