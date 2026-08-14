# Anonymous Authenticated Ballot System — extended demonstration

`VRO modulus 2048 bits · RSABSSA-SHA384-PSS-Deterministic (RFC 9474) · Ed25519 wallet and ad-hoc keys`

Proof of concept. Private key material is printed deliberately and must never be reused.

Generating the VRO key pair…

> **72 checks performed, 0 failed.** Every claim below was computed in this run, not asserted by the narration.

*69 byte blocks are collapsed. Click any one to reproduce the arithmetic.*

---

<details>
<summary><b>Contents</b></summary>

- [PART 1 · SETUP — the VRO's one and only signing key](#part-1-setup--the-vros-one-and-only-signing-key)
- [PART 1 · STEPS 1–4 — Anna's device prepares the request](#part-1-steps-14--annas-device-prepares-the-request)
- [PART 1 · STEPS 5–7 — the VRO validates, logs, then signs blindly](#part-1-steps-57--the-vro-validates-logs-then-signs-blindly)
- [PART 1 · STEP 8 — Anna unblinds, and checks the office behaved](#part-1-step-8--anna-unblinds-and-checks-the-office-behaved)
- [PART 1 · STEPS 9–11 — the ballot, and what the box records](#part-1-steps-911--the-ballot-and-what-the-box-records)
- [PART 1 · STEPS 12–13 — the two checks from an independent device](#part-1-steps-1213--the-two-checks-from-an-independent-device)
- [PART 2 · THE ANONYMITY CLAIM, AS DATA](#part-2-the-anonymity-claim-as-data)
- [PART 3 · A BALLOT CAST WITH NO AUTHENTICATION](#part-3-a-ballot-cast-with-no-authentication)
- [PART 3 · A TOKEN INVENTED FROM NOTHING](#part-3-a-token-invented-from-nothing)
- [PART 3 · A GENUINE TOKEN, STOLEN FROM THE PUBLIC BOX](#part-3-a-genuine-token-stolen-from-the-public-box)
- [PART 3 · THE SELECTION CHANGED BETWEEN DEVICE AND BOX](#part-3-the-selection-changed-between-device-and-box)
- [PART 3 · A BALLOT AUTHENTICATED BY THE WRONG KEY](#part-3-a-ballot-authenticated-by-the-wrong-key)
- [PART 3 · CLAIMING SOMEONE ELSE'S IDENTIFIER](#part-3-claiming-someone-elses-identifier)
- [PART 3 · AN IDENTIFIER THAT IS NOT ON THE REGISTER](#part-3-an-identifier-that-is-not-on-the-register)
- [PART 3 · TRYING TO DRAW A SECOND TOKEN](#part-3-trying-to-draw-a-second-token)
- [PART 3 · THE OFFICE PRESENTS A DIFFERENT SIGNING KEY TO ONE VOTER](#part-3-the-office-presents-a-different-signing-key-to-one-voter)
- [PART 3 · THE OFFICE RETURNS A SIGNATURE UNDER ANOTHER KEY](#part-3-the-office-returns-a-signature-under-another-key)
- [PART 3 · MULTIPLICATIVE FORGERY, AND WHY THE PADDING DEFEATS IT](#part-3-multiplicative-forgery-and-why-the-padding-defeats-it)
- [PART 3 · WHO REGISTERED? — THE STEP-12 LOG UNDER ATTACK](#part-3-who-registered--the-step-12-log-under-attack)
- [PART 4 · RE-VOTING](#part-4-re-voting)
- [PART 4 · PROTEST BALLOTS](#part-4-protest-ballots)
- [PART 4 · WHY 'REJECTED' AND 'INVALID' MUST NOT BE CONFLATED](#part-4-why-rejected-and-invalid-must-not-be-conflated)
- [PART 5 · THE BALLOT BOX EDITS ITS OWN RECORD](#part-5-the-ballot-box-edits-its-own-record)
- [PART 6 · THE SAME PROOF SERVES AN ADJUDICATOR AND A VOTE BUYER](#part-6-the-same-proof-serves-an-adjudicator-and-a-vote-buyer)
- [PART 7 · INDEPENDENT VERIFICATION FROM THE PUBLIC LEDGER ALONE](#part-7-independent-verification-from-the-public-ledger-alone)
- [ · SELF-CHECK](#-self-check)

</details>

---


## PART 1 · SETUP — the VRO's one and only signing key

One key pair for the whole election, published before voting opens and pinned in every client. A VRO free to use a different key per voter would gain nothing from blinding: it could afterwards tell which of its keys verifies a given ballot and re-link it to the requester.

<details>
<summary><code>modulus  n_R — 2048 bits</code></summary>

```text
bc32bf60170e51ec599fa4d329b42a87bbeafe0e8850b95e52de610f1bddac33
6ff88d35316bafbf6eb0fcc379537eeca2bcbb81e245293ecf9b5bc552a6b3c9
22812470ffc9077e8cb34b340b286ec1fde1c8ba9ad45eb41d2ca297a12194db
5f1349e9bee41d1504dbff0dff5862a45b07adc9f081802cb876d6897a8dc9a1
5ac1cd99275d459d0709cb8c17d39562de8990dd1ad9506f93f75a83c03feec8
aa3bc208338197dfef4083673238a7815ee3d5e4d2a8e28f6e9410c49d2d8d03
954ee5b9c3667805484d54c4cb27d23c034527734eb025124233dfcc83c2e8b0
05c9b5163ed16fcea28c230dc63c6f7dc8841d32da45f0f0d0ab50e2dfec49f3
```

</details>

| | |
|---|---|
| `public exponent` | `e_R           65537` |

The private exponent and the primes follow. In a deployment they never leave a hardware module; they are printed here so that every exponentiation below can be reproduced by hand.

<details>
<summary><code>private exponent  d_R — 2045 bits</code></summary>

```text
137be986483cca4c7ee6e1489f5bb0bf86bc087b76af6cd19020c7c9a9a7e489
1ac18fd4fefdd81f28959845a08cfd6a005b2bca81a38966a055c445848e0fb4
f6268aa04c4b02c49e4a7db1b0aa09f579946394b62ce075234418bd3c085f01
eb30f309092352c3775253709e8c07025f0e4776cdb88a8d96b76ef4a2c48528
4ae60cf9b2e81a7a19195e12783fc150c3bb197954a6a9b756cf03839b89caa9
661ddb94afd3fd7cde48606ffe4df4a64d441e393f392e348c05951ec53cd659
f83979e4b6d1f0975c3e206f3d1dd8593a403aff22b2721d4ae198b1031bfda6
c53af2d85e90c31aa71bafccbf0222813e8391d87e8fe540d3324c42da8bd8f9
```

</details>

<details>
<summary><code>prime  p — 1024 bits</code></summary>

```text
e20d79a9f15ad76cf63becb9dd396963a6845278b471fb9fc13c74d77527e50d
455ad43363c19d3679e9a2003df4c4ecb60273a6020b7b7430faae4a619bb91b
fbda9b1d536e60d84c1df37eef755a8e38cf968eab7e53bf1fd8772769ab4fe5
a9ab09067235dcfd92089e831473cb138b338e440ba9ec9365debbeab5103995
```

</details>

<details>
<summary><code>prime  q — 1024 bits</code></summary>

```text
d52172d85029feb99220445262f7148bfd20ee15fde4176caf9700e40e858fbe
281f88f52b2ebe4c7fe50562056f3380a0ca4fe509a59c9e44f3a152a3def6c6
565a5dc5590aca0b2f5de038b50ee39f5af2ef347c7fc68b339a9f85003f2f57
e3ff47155e2a8bc87de18b8b143a009d0fbe57039e69c46c30c3eca61c7ee367
```

</details>

| | |
|---|---|
| `SHA-256 fingerprint` | `1c46be45b8bd14a0debab0358a0f523b829a4ca2ee3a5afcf3ebb81858398011` |

- ✅ p · q == n_R

- ✅ e_R · d_R ≡ 1  (mod λ(n_R))

### The electoral register

| | |
|---|---|
| `Anna` | `id = HU-WALLET-000` |

<details>
<summary><code>wallet public key  k_p^(v) — 32 bytes</code></summary>

```text
11ed3858bad3ee632158271eff2d215baa73e413947eb529c314f609948cc567
```

</details>

| | |
|---|---|
| `Béla` | `id = HU-WALLET-001` |

<details>
<summary><code>wallet public key  k_p^(v) — 32 bytes</code></summary>

```text
66efe6e2745a8427f9f091ce806321de0fdf36fd8282c083461afd8354d918a7
```

</details>

| | |
|---|---|
| `Csilla` | `id = HU-WALLET-002` |

<details>
<summary><code>wallet public key  k_p^(v) — 32 bytes</code></summary>

```text
4d8633680e6fe1115b090d21707417e1790bd7043b6db6c0e121f619c924da8b
```

</details>

The register holds an identifier and a wallet public key, and nothing else. It is never consulted again after a token is issued.


## PART 1 · STEPS 1–4 — Anna's device prepares the request


### Step 1/A — the ad-hoc key pair, generated fresh for this election

<details>
<summary><code>k_s^a  (private, never sent) — 32 bytes</code></summary>

```text
d70c3cd3771cd40421e4657f2d75edde925d878e4c08fcbb840dd0645519039c
```

</details>

<details>
<summary><code>k_p^a  (public, will be blind-signed) — 32 bytes</code></summary>

```text
f32a555d21899f2fb80987554c2883afcefa0e87fb3a4d2cc4a2bb679e7a65ae
```

</details>

This key pair is the voter's anonymous handle on their own ballot. It is generated on the device, and the registration office never sees it in the clear.


### Step 1/B and 2 — encoding, then blinding

<details>
<summary><code>enc(k_p^a)  EMSA-PSS, SHA-384 — 256 bytes</code></summary>

```text
602678c3962b70723dec49dd7ce1ead5bdc45d8c4c1c3a9b6a316bb3db0081f5
cb8694e5bb1f11f8b2f7734754661c03b28df65c8e06d549b07dd882b1274ef9
d011e060ac8df1ba47c77edc2ffe097b4c2ee1c8c141cda8daf85b20f7db04ba
63615e1f1aa0800a1b0cf2a22812e1fa8e3d4365f9f6128888dffce4fd921cd7
2d3161891a8eb84872e4cb60e7f24e4dd4a700bdf5e12712e2217b90b2753946
b57d957352e37bb28ee1e8b16376f29d6a5b67197624c616ebc2268b94f1715a
615e1ecc2e3cd1b60c5bf4b5b0b1b17a1c7704f24d636e3c7e17c88aad4d848e
d31c5598d8d43fd42e24ac4e2070f71a49dea3127e81fa380a5f60abcac457bc
```

</details>

The salt inside that encoding is drawn by Anna's device, not by the signer — RFC 9474 puts the encoding inside Blind(), so the VRO never sees an unencoded message and takes no part in choosing the salt.

<details>
<summary><code>blinding factor  r — 2047 bits</code></summary>

```text
4811966762a2a9181ceda542d52c4b9915fc5fe92537f339ae776b4627e56a66
c625915b3392172f46e7789fd5dee0ff76ce2f4392b4c8843f09d1829597a233
2d0dfbefba2c001321230255786134ecda5a365ed75991e1921d9ffc86a48ce8
5d6c0b3a087af9baea479c3ff1d4efb8935a431d68fbaf4bf399e36404cc1062
80938f9df6d0fb13c6facd4f40e6eba9531213d4d8a4d5e55518240dce26dfed
5f9b10be7f1bb0e9bf462a95621bca6ef3fa0393d423ecbd7a9cdbf6de9cd88e
7a1778229298ec2a6052ed664b34253994a561f864bdea0ad502a1a2ce242a8b
2f676a0a44231e9d14f6b802ab751881596ad6ec0d5473c9c08821b3b8c83f79
```

</details>

<details>
<summary><code>r^(-1) mod n_R — 2045 bits</code></summary>

```text
15f059c13d99620684fe019c1e7caf008229e1c633f06b83ae7516fb91f999c6
ede01577a4ff6878e6121e7731bddb3b7e76dacfdd03b8937ae0a0112bf1840f
9eb110705ae9884cc4bbe7552854e205ee38a976c18b38977a86acdc3324e8a0
ed1d8f1f97f1103966363f02db319cebcb46ad19e17f5a719096464f40305e40
1dea8b32b0626903024cab84c7cdaf5f76c8ed5444400b1a7a9355f62aa853d7
3192b5b46b035a44c9507b5903bb2e92dafbce9d8be944fbcbe8d4f3ee56bdb3
2de63db9c010588b11aa64c89ea7676b9667338bbeab505c0d85259b14a3465f
20a9c561b94829911698d3d7f343f98bb0e3d2a365fd66dfbc849a05048a2c6c
```

</details>

<details>
<summary><code>r^(e_R) mod n_R — 2047 bits</code></summary>

```text
43d4d1855b0d84406c1a024575b6440a949ffd5108c4070df7b74231b2589f0c
63aa23800b87c181d026c83d2abbcce64c97af8b2efd0f0a9145f1f8b4e87081
0cbbfa3f094da6e97bb66450fd58a0ffb01bd499c4d6f980a295ea35fc82a124
46d0f04971ae0107eb5f3048a23e22f9d7b22f236d9a6479a57432c51a0afc9f
621edede61a3f780267f32307b1eeba5001b3af24b6cb022e2ea8e07fa798429
0d2cb4d90e5396a182252e26ae42c9a175927cf5d0fd10267a13d750ab5e9bf7
c4615b4313c575ea8718e44ae8bf8ead9b09c20b5163a2cd7871f46eda668ff7
27e50f2bdf67ea6373ea5f55439fc3ce8a53eeed93a3a67544fdfc71a00ebb34
```

</details>

<details>
<summary><code>c = enc(k_p^a) · r^(e_R) mod n_R — 2047 bits</code></summary>

```text
5d4e7d40aca74e6463438f0b53e408d573d9cafc4a1855b785a8755f5c147a92
a95c1d3a92c5938d654a0f3f474a1bdbe91f892235518cec6b77bb07a89fb02a
d69bff73186edc95564f50e5aae7a47ffa88162c6233c7af53c8699c0891228a
c4fdfcbc858baf55044308f5509c0f8136a99ab0c3030fcc7c6e38314cdd6835
4f1ad8f9ea818c949485fc2a9e5b5da90837270f8752392ad1bc6bfc857e2ee4
24e81c08d7038b1fa8006da2809540d974aa156d5411266b2d6b92aaa225db49
f18dd6f21facefc7301e441655f84a1661ce18b39c492b23b115382c67b165b1
3958f326d0fbac5f85c1603d2299ccb479d6dcd29f312f73bc2c32fcd132c950
```

</details>

- ✅ c recomputed from enc(k_p^a) and r matches the value sent

- ✅ enc(k_p^a) < n_R  (the encoding is reduced)

- ✅ r is invertible mod n_R  (r · r^-1 ≡ 1)

### Steps 3–4 — the wallet signs the request package [id, c]

<details>
<summary><code>canonical JSON actually hashed — 387 bytes</code></summary>

```text
{"blinded_key":"XU59QKynTmRjQ48LU-QI1XPZyvxKGFW3hah1X1wUepKpXB06ksWTjW
VKDz9HShvb6R-JIjVRjOxrd7sHqJ-wKtab_3MYbtyVVk9Q5arnpH_6iBYsYjPHr1PIaZwI
kSKKxP38vIWLr1UEQwj1UJwPgTapmrDDAw_MfG44MUzdaDVPGtj56oGMlJSF_CqeW12pCD
cnD4dSOSrRvGv8hX4u5CToHAjXA4sfqABtooCVQNl0qhVtVBEmay1rkqqiJdtJ8Y3W8h-s
78cwHkQWVfhKFmHOGLOcSSsjsRU4LGexZbE5WPMm0PusX4XBYD0imcy0edbc0p8xL3O8LD
L80TLJUA","voter_id":"HU-WALLET-000"}
```

</details>

<details>
<summary><code>hash([id, c])  SHA-256 — 32 bytes</code></summary>

```text
1d14313608cd0cc7942461da69e6458188ab4fb95227a936f160a9382c0c8ea7
```

</details>

<details>
<summary><code>s = sig_{k_s^(v)}(hash([id,c])) — 64 bytes</code></summary>

```text
31bae1d8d5009536965106eb75b0f14ecd541a9f470abc33af00dea86d72c325
92722d77f2ea5bf9bc67e4570bacaced0a7c298d182eb11c6d2c4be5a224a60f
```

</details>

- ✅ the wallet signature verifies under k_p^(v)
Note what travels to the VRO: the identifier, the blinded value, and a signature. Nothing about the choice, and nothing that reveals k_p^a.


## PART 1 · STEPS 5–7 — the VRO validates, logs, then signs blindly


### Step 5 — the two checks, 5/1 and 5/2

| | |
|---|---|
| `5/1` | `id on the register?       True` |
| `5/2` | `signed by that id's wallet? True` |
| `token already released?` | `False` |


### Step 7 — the release is logged before the signature is returned

<details>
<summary><code>nonce (disclosed only on a signed step-12 query) — 32 bytes</code></summary>

```text
2a4d0e8e8057546334642c5cd5e2d2988f774a0f94ca69b17de9b077b75745b0
```

</details>

<details>
<summary><code>commitment  H(id ‖ nonce) — 32 bytes</code></summary>

```text
de8f81f26aee39743938db0f32ecea948e37e914da1455f354df1acdd5cc36e0
```

</details>

| | |
|---|---|
| `published log entry` | `{'commitment': '3o-B8mruOXQ5ONsPMuzqlI436RTaFFXzVN8azdXMNuA'}` |

<details>
<summary><code>previous entry hash — 32 bytes</code></summary>

```text
0000000000000000000000000000000000000000000000000000000000000000
```

</details>

<details>
<summary><code>this entry hash — 32 bytes</code></summary>

```text
73815deb0f6a823b10a237df8057a206403adf095789a2eaabc13d64e60fd58a
```

</details>

- ✅ the published entry contains no identifier

- ✅ entry hash recomputed independently

- ✅ logging happens before signing (a token cannot exist off-log)

### Step 6/A — the raw private-key operation  s_c = S(c) = c^(d_R) mod n_R

<details>
<summary><code>s_c — 2048 bits</code></summary>

```text
85fdb5f9c6273c280cd85e9fb0240932054939ee67bafb34eb1eb544402b3650
26a10b2832e28a9a1fac9a9386a6b4140f290edb63440b71a7b0af56b447a928
470275dff5328509dc874c3f7f10c8572a4227a6015eb4e7ae1e58ebc6b5376f
6faf187b81729b25d9ff0a57f4175676fe8d0a93677158f0ec7570a4923a8539
aef3e35ef9ee07c04548f6a76650671e7c0853e951f91ef5129f1fab2785e413
4d42f0681ebe80611c4c7fce8eb7100235c4fe8df19b56dd8ab8437441807b20
8fdac75568a3eb43b6eea2fafefb87b47714056d5a4e1524d8fce55af48f1139
a1627072ff4df27ecae81f3f10882f7ce4e89851aef0662689c2a5777a923ebe
```

</details>

- ✅ s_c recomputed as pow(c, d_R, n_R)

- ✅ s_c^(e_R) ≡ c  (mod n_R)  — the fault check of §5.3
That last line is the Boneh–DeMillo–Lipton countermeasure the article specifies in §5.3. It is performed here by the demonstration, not by `vro.py`, which does not yet implement it — see CLAUDE.md, open items.

What the office holds after this exchange: an identifier, the blinded value c, and s_c. What it does not hold: k_p^a, r, or anything that links either to c.


## PART 1 · STEP 8 — Anna unblinds, and checks the office behaved

<details>
<summary><code>s_{k_p^a} = s_c · r^(-1) mod n_R — 2046 bits</code></summary>

```text
2e960c1ed7438602492ee1b3c99c0dd78448a0b1ade8f29f1c32286c29b2db03
9fb1ebafe0ed298e3ddaf9bdf0c9ed1aebba2696ce97c7b65d2aab1aca149927
9a0b41fa63f75087e7ce930ed2ac0af19269486469aec227722c7d27d9680f41
7c160323a80f09abb2a85e4c49f8b2582060a40ce8e39cecc4d7d927f6aaeba3
98d36369eb92432ba21cd4d59a43212da712b3142988bceab2013ca2a3d0bf18
8db1f2d4db4041634a344fd7190a1d3221aaf5cf49966db05ccb9db966fb3797
2926f8299b520a5a40844909116e1939c15c49fe974a4262503bebdfde3732a6
1cd0009ff4ec1e83b3f60a439b22c61fd87a454ae4bedbca8ed80b39611ef18c
```

</details>

- ✅ token recomputed as (s_c · r^-1) mod n_R

- ✅ token^(e_R) mod n_R == enc(k_p^a)  — the encoding reappears exactly

- ✅ the token is an ordinary RSA-PSS signature over k_p^a
The blinding factor is transformed, not carried: Anna multiplied by r^(e_R) and divides by r, because (r^(e_R))^(d_R) = r. Blinding and unblinding therefore do not cancel — the exponentiation in between is what makes the construction work.

The result verifies under an unmodified RSA-PSS implementation. No election- specific cryptography is needed by anyone checking it later.


## PART 1 · STEPS 9–11 — the ballot, and what the box records


### Step 9 — Anna selects 'Option A'

<details>
<summary><code>canonical JSON actually signed — 80 bytes</code></summary>

```text
{"adhoc_public_key":"8ypVXSGJny-4CYdVTCiDr876Dof7Ok0sxKK7Z556Za4","sel
ection":1}
```

</details>

<details>
<summary><code>hash([i, k_p^a]) — 32 bytes</code></summary>

```text
b8232eb0d60ff74a2b3750c6871a66614b53cf47604bde682421f67b5611f096
```

</details>

<details>
<summary><code>s_vote = sig_{k_s^a}(hash([i, k_p^a])) — 64 bytes</code></summary>

```text
477e52c9624bce6d87954839035d4a7dd48031c608a2f3291d19b828f0c1da9c
5c6129c3adf17cc17cb1ae69b87a868253f2c7fea71346e23b7d0a44d197b709
```

</details>

The complete published ballot package [i, k_p^a, s_{k_p^a}, s_vote]:

| | |
|---|---|
| `i` | `(selection)                 1` |

<details>
<summary><code>k_p^a — 32 bytes</code></summary>

```text
f32a555d21899f2fb80987554c2883afcefa0e87fb3a4d2cc4a2bb679e7a65ae
```

</details>

<details>
<summary><code>s_{k_p^a}  (token) — 256 bytes</code></summary>

```text
2e960c1ed7438602492ee1b3c99c0dd78448a0b1ade8f29f1c32286c29b2db03
9fb1ebafe0ed298e3ddaf9bdf0c9ed1aebba2696ce97c7b65d2aab1aca149927
9a0b41fa63f75087e7ce930ed2ac0af19269486469aec227722c7d27d9680f41
7c160323a80f09abb2a85e4c49f8b2582060a40ce8e39cecc4d7d927f6aaeba3
98d36369eb92432ba21cd4d59a43212da712b3142988bceab2013ca2a3d0bf18
8db1f2d4db4041634a344fd7190a1d3221aaf5cf49966db05ccb9db966fb3797
2926f8299b520a5a40844909116e1939c15c49fe974a4262503bebdfde3732a6
1cd0009ff4ec1e83b3f60a439b22c61fd87a454ae4bedbca8ed80b39611ef18c
```

</details>

<details>
<summary><code>s_vote — 64 bytes</code></summary>

```text
477e52c9624bce6d87954839035d4a7dd48031c608a2f3291d19b828f0c1da9c
5c6129c3adf17cc17cb1ae69b87a868253f2c7fea71346e23b7d0a44d197b709
```

</details>

Nothing in that package identifies Anna. The only link to eligibility runs through the token, and the office cannot recognise it.


### Steps 10/1, 10/2 and 11/A — the ballot box decides

| | |
|---|---|
| `10/1` | `token signed by the VRO? True` |
| `10/2` | `selection authenticated by k_p^a? True` |
| `result` | `accepted=True  reason='accepted'` |

<details>
<summary><code>previous ledger head — 32 bytes</code></summary>

```text
0000000000000000000000000000000000000000000000000000000000000000
```

</details>

<details>
<summary><code>new ledger head — 32 bytes</code></summary>

```text
1c8061c73f43c15e12f2be7f516b2c73649f37b0bd9f0a807033df7587f29f63
```

</details>

- ✅ ledger entry hash recomputed independently
The head returned in the receipt is Anna's evidence of the state of the registry at the moment her ballot was accepted. If the published ledger later fails to reproduce it, the discrepancy is demonstrable.


## PART 1 · STEPS 12–13 — the two checks from an independent device


### Step 12 — was a token released in my name?

<details>
<summary><code>payload signed by the query — 32 bytes</code></summary>

```text
e707d1922fbc4c7cf2294bc08dca62dd79a4432abd2e45094ea976988bfec06b
```

</details>

<details>
<summary><code>sig(id) — 64 bytes</code></summary>

```text
7989846a8527c5198d7dc783b9c5558a9b7a9bacf0ab0b6835e4ee87f2967a19
08134354897d0fcc8b1e1e263eb9a5c42e9cecb1143696f81bb31fbe4a5fd80d
```

</details>

| | |
|---|---|
| `released` | `True` |
| `index in the published log` | `0` |

<details>
<summary><code>nonce disclosed to Anna alone — 32 bytes</code></summary>

```text
2a4d0e8e8057546334642c5cd5e2d2988f774a0f94ca69b17de9b077b75745b0
```

</details>

- ✅ the nonce opens the commitment at that index

- ✅ the same nonce does not open it for a different id
The query carries sig(id) because an unauthenticated lookup would turn the log into a public register of participation — and absence of an entry is conclusive proof of non-voting, which is exactly what a coercer demanding turnout needs.


### Step 13 — is the recorded selection the one I intended?

| | |
|---|---|
| `recorded selection` | `1` |

- ✅ cast-as-intended check passes

### The other voters (abbreviated — same protocol, different numbers)

| | |
|---|---|
| `Béla` | `selection 3  accepted=True  head 69c050b6f220010143b3412d52112937…` |
| `Csilla` | `selection 1  accepted=True  head a7a990bec877114a2a098b9a0d31744e…` |


## PART 2 · THE ANONYMITY CLAIM, AS DATA

Below are the two records side by side: what the registration office retained from Anna's exchange, and what the public ballot box shows. The value that connects them, r, exists only on Anna's device and was discarded after step 8.


### The office's view of Anna

| | |
|---|---|
| `id` | `HU-WALLET-000` |

<details>
<summary><code>c   (what it signed) — 2047 bits</code></summary>

```text
5d4e7d40aca74e6463438f0b53e408d573d9cafc4a1855b785a8755f5c147a92
a95c1d3a92c5938d654a0f3f474a1bdbe91f892235518cec6b77bb07a89fb02a
d69bff73186edc95564f50e5aae7a47ffa88162c6233c7af53c8699c0891228a
c4fdfcbc858baf55044308f5509c0f8136a99ab0c3030fcc7c6e38314cdd6835
4f1ad8f9ea818c949485fc2a9e5b5da90837270f8752392ad1bc6bfc857e2ee4
24e81c08d7038b1fa8006da2809540d974aa156d5411266b2d6b92aaa225db49
f18dd6f21facefc7301e441655f84a1661ce18b39c492b23b115382c67b165b1
3958f326d0fbac5f85c1603d2299ccb479d6dcd29f312f73bc2c32fcd132c950
```

</details>

<details>
<summary><code>s_c (what it returned) — 2048 bits</code></summary>

```text
85fdb5f9c6273c280cd85e9fb0240932054939ee67bafb34eb1eb544402b3650
26a10b2832e28a9a1fac9a9386a6b4140f290edb63440b71a7b0af56b447a928
470275dff5328509dc874c3f7f10c8572a4227a6015eb4e7ae1e58ebc6b5376f
6faf187b81729b25d9ff0a57f4175676fe8d0a93677158f0ec7570a4923a8539
aef3e35ef9ee07c04548f6a76650671e7c0853e951f91ef5129f1fab2785e413
4d42f0681ebe80611c4c7fce8eb7100235c4fe8df19b56dd8ab8437441807b20
8fdac75568a3eb43b6eea2fafefb87b47714056d5a4e1524d8fce55af48f1139
a1627072ff4df27ecae81f3f10882f7ce4e89851aef0662689c2a5777a923ebe
```

</details>


### The public ballot box, first entry

| | |
|---|---|
| `selection` | `1` |
| `adhoc_public_key` | `8ypVXSGJny-4CYdVTCiDr876Dof7Ok0sxKK7Z556Za4` |
| `token` | `LpYMHtdDhgJJLuGzyZwN14RIoLGt6PKfHDIobCmy2wOf…` |
| `vote_signature` | `R35SyWJLzm2HlUg5A11KfdSAMcYIovMpHRm4KPDB2pxc…` |


### The one value that links them, which nobody else ever had

<details>
<summary><code>r — 2047 bits</code></summary>

```text
4811966762a2a9181ceda542d52c4b9915fc5fe92537f339ae776b4627e56a66
c625915b3392172f46e7789fd5dee0ff76ce2f4392b4c8843f09d1829597a233
2d0dfbefba2c001321230255786134ecda5a365ed75991e1921d9ffc86a48ce8
5d6c0b3a087af9baea479c3ff1d4efb8935a431d68fbaf4bf399e36404cc1062
80938f9df6d0fb13c6facd4f40e6eba9531213d4d8a4d5e55518240dce26dfed
5f9b10be7f1bb0e9bf462a95621bca6ef3fa0393d423ecbd7a9cdbf6de9cd88e
7a1778229298ec2a6052ed664b34253994a561f864bdea0ad502a1a2ce242a8b
2f676a0a44231e9d14f6b802ab751881596ad6ec0d5473c9c08821b3b8c83f79
```

</details>

- ✅ c · (r^-1)^(e_R) ≡ enc(k_p^a)  — the link, only computable with r

- ✅ the office's transcript shares no byte string with the ballot
Without r, relating s_c to the published token is exactly the problem the blinding was chosen to make hard. What the office can still do is issue a token nobody asked for; that is bounded by the one-token-per-id rule and the public release count, not by cryptography.


## PART 3 · A BALLOT CAST WITH NO AUTHENTICATION

The naive attack: submit a selection with empty fields, as though the ballot box were a form on a website. This is what the ballot box is asked to accept.


### Submitted

| | |
|---|---|
| `selection` | `2` |

<details>
<summary><code>k_p^a — 0 bytes</code></summary>

```text
(empty)
```

</details>

<details>
<summary><code>token — 0 bytes</code></summary>

```text
(empty)
```

</details>

<details>
<summary><code>s_vote — 0 bytes</code></summary>

```text
(empty)
```

</details>


### Ballot box decision

| | |
|---|---|
| `accepted` | `False` |
| `reason` | `token not signed by VRO` |

- ✅ rejected at check 10/1, before the selection is even considered

- ✅ nothing entered the valid ledger

- ✅ the attempt is published in the rejected ledger

### The rejected-ledger entry (public, so the attempt is visible)

| | |
|---|---|
| `payload` | `{'selection': 2, 'adhoc_public_key': '', 'token': '', 'vote_signature': '', 'reason': 'token not signed by VRO'}` |


## PART 3 · A TOKEN INVENTED FROM NOTHING

A better-informed attacker generates an ad-hoc key of their own and fabricates a token of the correct length. The bytes are well-formed; they are simply not a signature under the VRO's key.


### Submitted

<details>
<summary><code>k_p^a  (a real key, generated by the attacker) — 32 bytes</code></summary>

```text
05cfb9ec0effe0946d162066fe5a1c19f3f4b9776bdeb19575213ea23f39cd13
```

</details>

<details>
<summary><code>token  (invented) — 256 bytes</code></summary>

```text
51448aece77265eb6d1ec3a66ee6400e0bcef17138b47547370df045860f8ab7
be6418e6247f38ea2f6312ad660d58b938c820a4e708a6f9b7c62b6be646cb3e
61e5a37a2447a0680adef8cde01145e6983b502a60ec11edf28dbc349d7384ac
5cc1dcfe19c221758a7d2be212145c3a81ea195be33fe2aeb2c2efe9bb194c60
0af529a39948ee513ad7727626da2df40ed9e7fe485e9fc89712bc04b0cac3d3
4d6a55fb15787c49ca9e055556853f6bd74e4ec1cad1adae8a5835023e0fdc44
41d868496ecd4a625528976c10083a346627a39ba0fc9fdcad804b34dbc3a75f
23a6125fd1221ec8ba94b1b5bf41e257fa7235e429cf9b065f4fe09f81700ed9
```

</details>

<details>
<summary><code>s_vote (genuine — signed with the matching private key) — 64 bytes</code></summary>

```text
d011f311c60a472e89a5090e92b761652034951c205d0db48d1083b6aac53a1e
551e697490e5e229117fbb584c56f633d041da8e687fe04eea316a554fbc4706
```

</details>

- ✅ the vote signature itself is perfectly valid

### Ballot box decision

| | |
|---|---|
| `accepted` | `False` |
| `reason` | `token not signed by VRO` |

- ✅ the token fails RSA-PSS verification under k_p^(R)

- ✅ rejected
Authenticating the selection is not the same as being entitled to cast it. The ad-hoc key proves who signed; only the token proves eligibility.


## PART 3 · A GENUINE TOKEN, STOLEN FROM THE PUBLIC BOX

Every token is published in clear. An attacker copies one and attaches it to a key of their own — the obvious consequence of publishing ballots, and the reason the token signs the key rather than accompanying it.


### Copied from the published ledger

<details>
<summary><code>victim's k_p^a — 32 bytes</code></summary>

```text
69b0fbf8cdcc65808f0915d4d9e62989f99ceafc065cac678c3e8f6fc0d881eb
```

</details>

<details>
<summary><code>victim's token — 256 bytes</code></summary>

```text
13a17fbc3d9abed2abcf0d4d3a5fc31cb93b01c89c7cfbff15adc14e9c5711b6
b38dbf71635d7a93579ae8daa61d6f816ef51042f262ff141de1c7ada6d6755e
db8ac7a765ba1b523ddf7aecf82f81a8e7a5bb26ae0662a905809c7e1dc47b38
0e584f7f0b766db961e1a98de4e239077e73b2ca85fc8d43722c1fbc97ad80fa
4122fa39e9d3bcd931d0993698b5c552094999e23225ae759ce0527739811046
b96e68770193bdc98c33f309919bf0e727556d7d3ada4ec774710b652806fab5
7c212e79e3691b2189b1ec0aa4834052be130f3b0eba1156d92532068f1e25a5
a99d289812cd037c4e4a451393efa1a8f0de7e02fcc343ad6cb67c30fe5be3b1
```

</details>

- ✅ the stolen token is genuine — for the victim's key

### Submitted with the thief's own key

<details>
<summary><code>thief's k_p^a — 32 bytes</code></summary>

```text
08d41c5db9f7ca37b0fefbd82b44b46ce7e2ed8d1b3a5c5deec31b8d158765f8
```

</details>

| | |
|---|---|
| `accepted` | `False` |
| `reason` | `token not signed by VRO` |

- ✅ the same token does not verify under the thief's key

- ✅ rejected

- ✅ the victim's ballot is untouched

## PART 3 · THE SELECTION CHANGED BETWEEN DEVICE AND BOX

A hostile network, proxy or relay rewrites the choice and forwards everything else unchanged. This is the objection that 'anything over the internet can be manipulated'.


### As signed by the voter

| | |
|---|---|
| `selection` | `1` |

<details>
<summary><code>hash([i, k_p^a]) that s_vote covers — 32 bytes</code></summary>

```text
d6dc5f7325e6a46d7859d8199e5801674d48e034f4bb2f5e1b0ede3eacbefbd9
```

</details>


### As it arrives at the ballot box

| | |
|---|---|
| `selection` | `2` |

<details>
<summary><code>hash([i, k_p^a]) of what arrived — 32 bytes</code></summary>

```text
365cc0955e24edbfe43166f1140ad950b81050fb2057380bcd9146e93caeba7c
```

</details>

<details>
<summary><code>s_vote (unchanged — the attacker cannot re-sign) — 64 bytes</code></summary>

```text
046bcf571f6732824bafbc3e633fc7becf60afe984144ac44c114e73fefd540b
17fdac4d788b7fb7b5608ce4f029bf90963984683d85063fe8d2ab9751581101
```

</details>

- ✅ the two digests differ

### Ballot box decision

| | |
|---|---|
| `accepted` | `False` |
| `reason` | `vote signature invalid` |

- ✅ rejected at check 10/2
The channel carries signed data, so it cannot forge or alter a vote undetectably. What it can still do is drop or delay ballots, and observe who contacts the box and when — availability and anonymity need separate measures.


## PART 3 · A BALLOT AUTHENTICATED BY THE WRONG KEY

The attacker presents the victim's certified key and token — both public — but can only sign with a private key of their own. This is the case a coercer or a compromised relay is in.


### Submitted

<details>
<summary><code>k_p^a  (the victim's, copied) — 32 bytes</code></summary>

```text
5460bc4928586f7ef81245a26db644bf13e6e5dc952d015dbe2f43799f03f565
```

</details>

<details>
<summary><code>s_vote (signed with the attacker's k_s^a) — 64 bytes</code></summary>

```text
3ef5c19ad181d50af9a47cc3ddba3e42b4a62c34a16178dab8d89f6a84f61bdc
60c8c2914bb95eaca64c53f73e658d686c15689ec5d98f288fcd16b67173eb0b
```

</details>

- ✅ the signature is valid — under the attacker's key

- ✅ but not under the key named in the ballot

### Ballot box decision

| | |
|---|---|
| `accepted` | `False` |
| `reason` | `vote signature invalid` |

- ✅ rejected

## PART 3 · CLAIMING SOMEONE ELSE'S IDENTIFIER

Wallet identifiers are not secret. The attacker builds a perfectly ordinary request, substitutes the victim's id, and re-signs with the only wallet key they hold.


### The request as it reaches the VRO

| | |
|---|---|
| `claimed id` | `HU-WALLET-001` |

<details>
<summary><code>hash([id, c]) — 32 bytes</code></summary>

```text
afc47713669d8b73865408c6d9316673642c863f251a0f196b2212dfd9fef9b5
```

</details>

<details>
<summary><code>s  (attacker's wallet) — 64 bytes</code></summary>

```text
0b8aca95fa7cc6ead4ab03748b7d3448c100a86b022c226978fb51355cb96ac5
fbc2e0e260738237f56d3c8d3757e7a1bfb021e7ed61c060990a64c71a54090c
```

</details>

<details>
<summary><code>k_p^(v) on the register for that id — 32 bytes</code></summary>

```text
b763f9a66032e76eab869118d43ba47b9410097f442d7e5a325ea64781aaed4c
```

</details>

<details>
<summary><code>k_p^(v) the attacker actually holds — 32 bytes</code></summary>

```text
925ac92bbc408c767ab2b837591fab010a712b6121aa4abffda8c3d5eea0dfac
```

</details>


### Step 5/2

| | |
|---|---|
| `RegistrationError` | `signature is not from the wallet belonging to this id` |

- ✅ refused: the signature is not from that id's wallet

- ✅ no token was released

## PART 3 · AN IDENTIFIER THAT IS NOT ON THE REGISTER


### The request

| | |
|---|---|
| `id` | `HU-WALLET-999` |
| `on the register` | `False` |
| `RegistrationError` | `id not valid or not eligible to vote` |

- ✅ refused at step 5/1

## PART 3 · TRYING TO DRAW A SECOND TOKEN

Equality rests here, not at the ballot box: a voter who held two tokens would hold two unlinkable ad-hoc keys and could cast two counted ballots. The box cannot detect that, because it cannot tell the keys apart.

<details>
<summary><code>first token — 256 bytes</code></summary>

```text
140be60b8d2d728710cab7036f95bbcdb7f3561805e68d2178234a0caf37e4a3
1b29e77b69b35ec7a4078a2a55419f67858440bcc4b9bc4b6ede5ccf80c3c4b5
4c4436b621cd4fdbb212c2ca1f7625ee0ef49376c77d9156bedf895d0766f314
7ee7a907758a5767d07142ddcab8d626a022e45d94559dd234a1464188ce9f52
2920153a88f203ff4d09cc2cec25cfa0e2a178e1c50e2f489faebf2861041b5c
93d6d3f91a9def969ba649e6cd9588486457d97dd4ec2c318fe6464320251e1d
fbb84b1889a3b7af53f6bdc8b257d6c62a59b3cbc21c96dd164e0f58d917e3ce
8bff46d6c866505efbd9fdbe0ec569710f30def5e278da8215374006c3fe58d1
```

</details>

| | |
|---|---|
| `release count` | `1` |
| `RegistrationError` | `a token has already been released for this id` |

- ✅ the second request is refused

- ✅ the release log did not grow

## PART 3 · THE OFFICE PRESENTS A DIFFERENT SIGNING KEY TO ONE VOTER

The subtlest attack here, and the one blinding does not prevent by itself. Blinding hides the ad-hoc key from the signer; it does not constrain which key the signer uses. An office that reserved a second key for one voter could afterwards tell which of its keys verifies a given ballot in the public box, and re-link it.


### Fingerprints

| | |
|---|---|
| `pinned in the voter app` | `1c46be45b8bd14a0debab0358a0f523b829a4ca2ee3a5afc…` |
| `offered to this voter` | `8fc22f428913ef4a43423461e1868757dd8d2def18de4789…` |
| `ValueError` | `VRO public key does not match the pinned fingerprint` |

- ✅ the voter app refuses to proceed on a fingerprint mismatch
The defence is entirely client-side and entirely procedural: one key, published before voting opens, pinned in every client, identical for every voter.


## PART 3 · THE OFFICE RETURNS A SIGNATURE UNDER ANOTHER KEY

The voter's entitlement to a token is consumed the moment the office logs the release. A response that does not verify must therefore be caught on the device, at the only moment r still exists.


### What the office returns

<details>
<summary><code>s_c (produced with a different private key) — 256 bytes</code></summary>

```text
1c19cc27164b57a4508c47bbbf9339566e26eb6c982fa30acb285a88a1269b4d
81c378e5c5decd6ecb968921551c76003a364ca214ea71e8fd4ea67093fc4587
9b3a5b7ba752845a681d3ad08309978a3e56bd9ab04fb17e59f931ed0e097179
a4eb696efc3692a51b815a306563b6d00e3724ad78e03d0b3a1a793e4b98c4ec
1f22f1d9895b6021424823e98a2968fe8f17656c9e274e535e59f271a839ffbd
0aa8b4afdefd132182b384a978bc57122cc5e2c9bd59534b551a75814be3077e
cca39e72f09e5bca731996d08ea0b5d2285e7e3ff302af330728d6a480320562
759d029483915f32c04965209cb518aa482bd93f670374789b24a9d576904e4f
```

</details>

| | |
|---|---|
| `BlindSignatureError` | `VRO returned a signature that does not verify` |

- ✅ the device verifies before accepting, and refuses

- ✅ no token was retained
RFC 9474 requires this check in Finalize(). The consequence is procedural rather than cryptographic: the entitlement is already spent, so a documented re-issuance path with an audit trail has to exist.


## PART 3 · MULTIPLICATIVE FORGERY, AND WHY THE PADDING DEFEATS IT

Raw RSA is multiplicative: S(m1)·S(m2) = S(m1·m2). A voter holding two legitimate tokens could therefore derive a third that the office never issued. This is why k_p^a is never signed directly.


### Two genuine signatures

<details>
<summary><code>m1 — 32 bytes</code></summary>

```text
cc0f6a80b60018e33e43920444441572ccd2d4947e68a86f0016262b650ba7be
```

</details>

<details>
<summary><code>sig1 — 256 bytes</code></summary>

```text
6b77a6a53c23064b4746e34eae18df1dc2c9d50d7108f16d1813d18e3f86e9b1
3ae5da6f9ee502e49de3f104f1a569280feb805c7f475dd7c4d1a32fecbade78
1584c4aeab4e02a03af92baebdfe5153336765e6d63bd75643e21910ee9e5e03
97e8798571089d34419ee802cfd03244a725d978110a1323164fe31eda6bc926
f49b36f686c8e86917fb59438d53665f2265a828a79209992d69bb3e0267de10
43d747437cc98a55266122e846eb2ea4c60472ae289e8c06b01c3c33b303b4bd
e0bfff49db1b469a65c2fdb94d16541d2f2b79010ea18b0b75363fed4170a1df
629904d7a48efa9d74c72165856a6299ee79260608867dfd8f10dc64dc31f85f
```

</details>

<details>
<summary><code>m2 — 32 bytes</code></summary>

```text
9c61c3c02e7e66a82b6f5f2c2544b6fd80b712820ef169ea864d1a1bc23f9177
```

</details>

<details>
<summary><code>sig2 — 256 bytes</code></summary>

```text
b98721172a6b4c075070c4a4be0a624b3367b215971063353424696420ed7faa
1d08bc8850f54dec6af5031a5a08789b824189af59e33a2b561c069b1d876fff
37d0631898660b80d7b56f1ea6fa6c76a246939f04a30cfd7ef663cd0ef818a4
168ca8ba41d1e59323637b068bc701183b0458b9e165def863bab3bb3b5213a0
8cc9f0ce1172bc90b392615d66f953001560635df3a4d85e44bacf2e3e5fa05e
ebe5629df8e61811ffe0b5641835f6699dfa16d8b677eeda6230de089864dfb2
f4b8d0213b5b3d35713a1b6240a9fbd3eb6a64ae9c82eddf724c0aabd715c43c
fc6b7b489c466caafe81503d6eb19fb696d4052fd26810157a258de11d1dc9b4
```

</details>


### Their product

<details>
<summary><code>sig1 · sig2 mod n_R — 2045 bits</code></summary>

```text
1ee834bff70d59375867e83cf3b20cd7aa7557ee139fbd3525dbacb2eeff1232
f7f5ca34b66f268dd5f8b0d5990471bd8cbbccb778e0223ddc0c57f564088a0c
8f560945220f20cdf4e8e224d61cecddb8978ec3be5bcce1a37ddf5e4a1c11db
9c0b3d869ef00c5b836da360d83f662d02674a92336dd34240e19f4528130756
f8936a015eea10083fb3a5db902c4f5ca4a25afd734ac5b6445526498fd51372
13b34155db0ba40204f26661c80c496540da50c80c1b9c9dbb27754f10ea0674
b30c42bc53f440a81a04ded69f3116e0871699bdff750144abdd05e0e1abea9a
95f7b523b7f854c91d8e96bdf1ad1c62e1791d6efda317e5ad71f8476523944d
```

</details>


### What that product is a signature of

<details>
<summary><code>forged^(e_R) mod n_R  — the 'encoding' it recovers — 256 bytes</code></summary>

```text
09e12f64bca33ac212f340574beb27be97e2fc317f2e0806de0a5c62e829f48c
4d6553463e6bb928bfafa93c82772824a8639fae73f5f00404eb33332effb3f8
80dd7027899600bb267ff29e2d7a1d52454a68dc06eeddcc158d355cefccd750
b970ade3e325ebfc198895b3cbc441a5317ffeead925edb7b7cf573bf80ac7fc
fa3671c2a2f8cf3c152e6ccb4cae3be785ece8bc707873468d70cc11971ad29d
215a53575cb1b66ce0c91faf212bf1322d9d362ff98fa49c41786bc02152cca0
ed747cb15ac18c976c833d9d86cb6b443632792ffd8741572333ece80a0360bc
a47a8738e7729189ae65337312c765b8b4178b0bed5e5956bf673f7d51736a6d
```

</details>

| | |
|---|---|
| `final byte` | `0x6d   (a well-formed EMSA-PSS encoding ends 0xbc)` |

- ✅ the product is a valid raw RSA signature: it recovers cleanly

- ✅ the forgery verifies against no message: m1

- ✅ the forgery verifies against no message: m2

- ✅ the forgery verifies against no message: m1‖m2

- ✅ the forgery verifies against no message: m1⊕m2
The product of two encodings is not, except with negligible probability, the encoding of anything. The forgery is a valid RSA operation and a worthless signature.


## PART 3 · WHO REGISTERED? — THE STEP-12 LOG UNDER ATTACK

A coercer who demands turnout rather than a particular choice needs only to learn whether a citizen registered at all. Absence of an entry is conclusive proof of non-voting.


### The published log, in full

| | |
|---|---|
| `entry 0` | `{'commitment': '5KL9cMIi_e0CuvtzGzPT8oyeQneRzOu8XVAG8C-2Wxk'}` |

- ✅ no identifier appears anywhere in the log

### The snoop queries the victim's id with their own wallet key

<details>
<summary><code>sig(id) offered — 64 bytes</code></summary>

```text
1076987876d83554d70e3952f988b6a25c4a7491fc7378b413477a5d14ccfc8a
fd843bbda67a6659993325ec1c6bec88085855517d968c4c14ee84f59020de0e
```

</details>

| | |
|---|---|
| `RegistrationError` | `query not signed by the wallet belonging to this id` |

- ✅ an unauthenticated query is refused

### A voter who did not register asks about themselves

| | |
|---|---|
| `released` | `False` |

<details>
<summary><code>signed denial — 256 bytes</code></summary>

```text
b3e54454fd6a31a9ea0c940b6918b53bf47ddf8466319c6ecefbad7763a62be5
df4d168fa3353e73952f2ef0c993b4cb6a9aeaa92d4332ae876729a9523ba308
d9a305b10190e7202d94ffaa6c1c2d87edeb5b2899c743c4c8e6857b24e63d99
ecd73cc02ee6c83888bdb935a91bb305775cb779d702d464044a2201ef92f56e
074cdc20e3287cf0b62276666c5ab8548a1130ab8881ba38cd53aea502069e41
67af07ef3d25e1a774bc7c72aa1731f542279afc099ae7ef968ed35d216c6345
53db5b8444cd82dba911b1b35d9c9e3cda777a4fa239f7f6250ec8a6576b3037
a22548e80bc09c6e4b2b9e28683d31b7a629f0481f509edcb8cacd85391e0a24
```

</details>

- ✅ the denial is signed by the office, so a false 'no' is attributable
This does not prevent a dishonest office from denying a token it minted. It leaves evidence of the denial. That distinction is deliberate and should not be described as prevention.


## PART 4 · RE-VOTING

A voter may recast at any time, and only the last accepted ballot counts. This is what makes casual pressure survivable — though not a coercer who controls the final moment before the close of voting.

| | |
|---|---|
| `cast 1 → accepted=True` | `head 5a95df9aaabc9bb639f562771aff3225…` |
| `cast 3 → accepted=True` | `head 4d6b77367a8c588c8796cd101512cd13…` |
| `cast 2 → accepted=True` | `head 1b7ec38a36c684e5cb016dd819af63f0…` |


### The public ledger keeps all three

| | |
|---|---|
| `entry 0` | `selection 1  key km5WYhLonJ0Au4DezaGgOnV9…` |
| `entry 1` | `selection 3  key km5WYhLonJ0Au4DezaGgOnV9…` |
| `entry 2` | `selection 2  key km5WYhLonJ0Au4DezaGgOnV9…` |

- ✅ three submissions retained

- ✅ one effective ballot

- ✅ the last one counts
Supersession is applied when counting, not by overwriting, so the whole submission history stays auditable.


## PART 4 · PROTEST BALLOTS

An out-of-range selection that is properly authenticated is an invalid vote, not a rejected submission: cryptographically valid, politically invalid, and it does supersede an earlier ballot. Distinct codes stay distinct in the tally, and the system never interprets what any of them means.

| | |
|---|---|
| `Anna` | `selection -1   accepted=True` |
| `Béla` | `selection -2   accepted=True` |
| `Csilla` | `selection -1   accepted=True` |


### Tally

| | |
|---|---|
| `counts` | `{1: 0, 2: 0, 3: 0}` |
| `invalid` | `3` |
| `protest_codes` | `{-1: 2, -2: 1}` |

- ✅ all three were accepted, not rejected

- ✅ none was counted for a listed option

- ✅ the distinct codes are not merged

## PART 4 · WHY 'REJECTED' AND 'INVALID' MUST NOT BE CONFLATED

Submitting to the ballot box requires no secret, and both k_p^a and the token are public. If a rejected ballot superseded an earlier one, any reader of the ledger could copy those two values, attach a meaningless signature, and annul someone's genuine vote.


### What an attacker copies from the ledger

| | |
|---|---|
| `k_p^a` | `zuVrghpdTG-MxrISInXrheW7Vvlj35EH3mLuMx4qvuE…` |
| `token` | `Qc-QwqrtYU031AkeaTriNTeleZ9Ok9uP0zYqK9S7_2M7…` |


### Result

| | |
|---|---|
| `accepted` | `False` |
| `reason` | `vote signature invalid` |

- ✅ the annulment attempt is rejected

- ✅ the genuine vote survives

- ✅ the attempt is nonetheless published

## PART 5 · THE BALLOT BOX EDITS ITS OWN RECORD

Publication is not immutability. A box could delete a ballot it had already acknowledged, or change one. The hash chain makes both demonstrable rather than merely alleged.


### The intact chain

| | |
|---|---|
| `0` | `prev 000000000000000000000000…  hash b3785d946a74bc94ff068562…` |
| `1` | `prev b3785d946a74bc94ff068562…  hash 7bfba488a8feb603c7e9bc36…` |
| `2` | `prev 7bfba488a8feb603c7e9bc36…  hash 1fc4b4f9c2838cdadbd84873…` |

- ✅ chain verifies

### Case 1 — a ballot is altered in place

| | |
|---|---|
| `first mismatching entry` | `0` |

<details>
<summary><code>hash the payload now implies — 32 bytes</code></summary>

```text
9519a2211d44f0193bfb7d6a34d9db61dabcd7ff2b4dc7f8348c48f1a6e3526c
```

</details>

<details>
<summary><code>hash that was published — 32 bytes</code></summary>

```text
b3785d946a74bc94ff0685621fdaa8698eb26c28c3e4933e22f132c45d8adfe4
```

</details>

- ✅ chain verification fails

- ✅ chain verifies again once the edit is undone

### Case 2 — a ballot is deleted

| | |
|---|---|
| `removed entry` | `index 1, selection 2` |

- ✅ chain verification fails
A voter who recorded the head returned in their receipt can show that the published ledger no longer reproduces it. Equivocation — showing different chains to different people — needs the head published somewhere the operator does not control.


## PART 6 · THE SAME PROOF SERVES AN ADJUDICATOR AND A VOTE BUYER

In the implemented variant the voter's handle is the ad-hoc key they control. That is what lets them substantiate a complaint. It is also, and unavoidably, what lets them prove their choice to somebody paying for it.


### A challenge from a third party, and the voter's answer

<details>
<summary><code>challenge (chosen by the coercer) — 25 bytes</code></summary>

```text
70726f76652d69742d49fa2b118d2010b9e3c4fe9d33fc59f7
```

</details>

<details>
<summary><code>proof = sig_{k_s^a}(challenge) — 64 bytes</code></summary>

```text
bb4d5d7a5d1ccccdedab0c173ed108aa5fb6e613ae102babd5f56e7c3adc2801
2a6812b0595f9b8db7c49884605d2e2bd1ece57b810a4e19f08419d6d0503b06
```

</details>

- ✅ the proof verifies against the k_p^a in the published ballot
| | |
|---|---|
| `the selection thereby proved` | `1` |

- ✅ the handle is transferable, by construction
Note what does not help: giving the voter an anonymous lookup number instead. The published ballot still carries k_p^a and the voter still holds k_s^a, so the coercer simply demands a signature. Provability lives in the ballot's structure, not in the index the voter uses. A genuine variant A needs encrypted ballots and a trapdoor tracker — a different system, not a different handle.

Where to place that balance is the legislative question the papers hand over. It is not settled by the code, and cannot be.


## PART 7 · INDEPENDENT VERIFICATION FROM THE PUBLIC LEDGER ALONE

Everything below uses only the published ledger and the VRO's public key. No privileged access, and no election-specific cryptography — an ordinary RSA- PSS verify and an ordinary Ed25519 verify.


### Every published ballot, verified one at a time

| | |
|---|---|
| `entry 0` | `selection 1  token ✓  s_vote ✓  chain ✓` |

- ✅ entry 0 fully verifies
| | |
|---|---|
| `entry 1` | `selection 3  token ✓  s_vote ✓  chain ✓` |

- ✅ entry 1 fully verifies
| | |
|---|---|
| `entry 2` | `selection 1  token ✓  s_vote ✓  chain ✓` |

- ✅ entry 2 fully verifies

### Aggregate checks

| | |
|---|---|
| `published ballots` | `3` |
| `distinct ad-hoc keys` | `3` |

tokens released (public count) 3

- ✅ hash chain intact end to end

- ✅ distinct ballots ≤ tokens released
That inequality is what a third party can check without learning who anyone is. It catches an office minting tokens it did not log. It does not catch one that logs a release for a citizen who never voted — that is indistinguishable from a citizen who took a token and abstained, and is why the issuing power belongs with several mutually distrusting bodies.


### The result, computed twice

| | |
|---|---|
| `Option A` | `outsider 2    box 2` |
| `Option B` | `outsider 0    box 0` |
| `Option C` | `outsider 1    box 1` |

- ✅ the outsider's count matches the announced tally
| | |
|---|---|
| `invalid (protest) ballots` | `0` |
| `protest codes` | `{}` |
| `rejected submissions` | `0` |
| `final ledger head` | `a7a990bec877114a2a098b9a0d31744ec463526ecdb0ada2b7dda36b3d78b159` |


##  · SELF-CHECK

72 checks performed, 0 failed.

Every claim above was computed in this run, not asserted by the narration.
