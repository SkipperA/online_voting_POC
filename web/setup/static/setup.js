/** The setup console. Phase A, and nothing else. */
const $ = (id) => document.getElementById(id);

async function refresh() {
  const c = await (await fetch('/configuration')).json();
  $('fingerprint').textContent = c.token_key_fingerprint;
  $('election').textContent = c.election_id;
  $('digest').textContent = c.digest;
  const voters = (await (await fetch('/voters')).json()).voters;
  $('register').innerHTML = voters.length
    ? voters.map((v) => `<li>${v}</li>`).join('')
    : '<li style="color:#888">nobody yet — the wallet will offer no personas</li>';
  $('status').textContent = `${voters.length} on the register.`;
}

$('enrol').onclick = async () => {
  const voter_id = $('voter').value.trim();
  if (!voter_id) return;
  $('enrol').disabled = true;
  const response = await fetch('/voters', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ voter_id }),
  });
  $('voter').value = '';
  $('enrol').disabled = false;
  if (!response.ok) { $('status').textContent = 'Enrolment failed.'; return; }
  await refresh();
};

$('voter').onkeydown = (e) => { if (e.key === 'Enter') $('enrol').click(); };
refresh();
