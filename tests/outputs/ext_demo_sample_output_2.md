# Anonymous Authenticated Ballot System — extended demonstration

`VRO modulus 3072 bits · RSABSSA-SHA384-PSS-Deterministic (RFC 9474) · Ed25519 wallet and ad-hoc keys`

Proof of concept. Private key material is printed deliberately and must never be reused.

Generating the VRO key pair…

> **85 checks performed, 0 failed.** Every claim below was computed in this run, not asserted by the narration.

*71 byte blocks are collapsed. Click any one to reproduce the arithmetic.*

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
- [PART 5b · WHILE VOTING IS OPEN, AND FROM THE CLOSE](#part-5b-while-voting-is-open-and-from-the-close)
- [PART 6 · THE SAME PROOF SERVES AN ADJUDICATOR AND A VOTE BUYER](#part-6-the-same-proof-serves-an-adjudicator-and-a-vote-buyer)
- [PART 7 · INDEPENDENT VERIFICATION FROM THE PUBLIC LEDGER ALONE](#part-7-independent-verification-from-the-public-ledger-alone)
- [ · SELF-CHECK](#-self-check)

</details>

---


## PART 1 · SETUP — the VRO's one and only signing key

One key pair for the whole election, published before voting opens and pinned in every client. A VRO free to use a different key per voter would gain nothing from blinding: it could afterwards tell which of its keys verifies a given ballot and re-link it to the requester.

<details>
<summary><code>modulus  n_R — 3072 bits</code></summary>

```text
d163eae8b9e523462f0ebdc810fd9b106f050cb1b3a55de3630d23e51e6eaed8
302eabc560f5d46b7d84a75493643a00ff96bf1c758b28419624eb26984cbb13
084e01ba8bc8b15b5028e6e29358a01f5ce3719254778a31dc2677dc869303d0
426fc331ce44de03fc11b4f255f2aa379a9dfc36687178b1b251644dfb55aabf
507fa144578d98e03c6a0724c80ba821239c41caffe0dcc9010dc7fcda6acb46
5f4072a49a118f5fdda21fce7408ef57a8d094874ab9eda663d41da74bd33ef9
d52485682ac95f3d96ac20c0cb9fd1e1f1b18dfede69ae392ff59a3920239928
43447c6c1e03faeb28e58ada84cf032d16022cc27fc726b8bbb1528d751c15ab
3965be16bace8442629e74b3959102c1cae1c7f258cad35ffaa937d18cd122a6
a166e2dc040e1aeba64ed190adaf3d63cf069cf3c0c9d091f5c85d6fe9c91434
4ec0f46090c9d1670874a0e799a945a2ccc0b4efdd33161dcd134c4b96ef1ebc
40da28911b386550b9df3c48be3ae1bb565970d43287cbfd035bca8b4ab81c61
```

</details>

| | |
|---|---|
| `public exponent` | `e_R           65537` |

The private exponent and the primes follow. In a deployment they never leave a hardware module; they are printed here so that every exponentiation below can be reproduced by hand.

<details>
<summary><code>private exponent  d_R — 3065 bits</code></summary>

```text
0146c2265407c50cc6f9a887812f02947990c6d0887f5010b4485eb92553d866
01f92edbdfa8eff80dc652bccdbf35294f658c59b08fbe1994403a5cbc5def60
00d374e83db4e5fbe003b7d096c45a0986e7ee07cdd302b92615e7f224b1ddba
95c517a404955fe31754c64d19e006509b752e15e8d21441c50c00f806b9b176
4417db144f125265bf8887ed9df890384f7ec2d9e97065f825b4ff4c97ca41dd
f673ae9f393f352808f2558e4d1fc6d1ba7a3705921b8b0ad21df7664f2c84fc
3f10e470dd594977997216b303a495e3b077ee2d2cc98908df7407f5f4d5f097
1cacc31dcb238554f2111dc0a5abc96860b4dc0d08933fadba1aff3f46020ed2
eace9bae16bb8e9b0a8dc364324f85ac7cb17e8736f4984f14cae7337cd0e2ed
5ac5f88661509a749d25e0e7c032522ce9b8622d979401bfe30147d273f235bd
350050aae30e8125409aac6a71441dd68748000734fb8b845e1d5f0714aaa487
8f220783a3a9af74b71e7ef67dabf1dfe5f0702d5e52e09c1250450442e780b7
```

</details>

<details>
<summary><code>prime  p — 1536 bits</code></summary>

```text
ef09f35fe1a7ebcd6fb430985ba946268b85750ea6d7c3f3b4d4c166de450116
bbb94b02e5a56b21ddf67d8e9033344afc02d993dd46f094620cde7aa66c7285
8b596a2048ef9930848e0adbef9cc9f1434220908843ec44b9a2babc354cbc46
6d8300887d7dcb50b38788365c653383a9abd2451e1099e76b83e8bd19807242
7851395d4a575cfddf29be3ae94436c2d140be12bf693b34b83694793de4b99f
a4da8bcc5565e8707449f7b319073d3179f6192161f5a674420b769c4dcbac73
```

</details>

<details>
<summary><code>prime  q — 1536 bits</code></summary>

```text
e03f697f49fea52c487d73c6d0fb02beb1b5c6d92be69d6f240a795998c3ba51
708e35dc66a0433b6b933675a813445d61ef75da9be975ead1021ad42a6dbe13
a74db2accf038c2b13b24037518c6c129e104af90dd86f7bf32d94dcf0bfd6ae
92852cc1348d410c4dc6ee98baf9b337ae9dd21127a0552c23a1cd9ec6e34470
e1f4e8b35a0fa44e68757c647b7da98913d4fe19aa4869dd766e68b6ab3d888c
0130380e07efe377c5eda55a9afd772469ca1dd474c7603341e56c439fd692db
```

</details>

| | |
|---|---|
| `SHA-256 fingerprint` | `4f6898c48af37053018689f6e0cc0eec93ea10c1745ad8d6e22cb061119202a2` |

- ✅ p · q == n_R

- ✅ e_R · d_R ≡ 1  (mod λ(n_R))

### Two registers, held by different parties

| | |
|---|---|
| `Anna` | `id = HU-WALLET-000` |

<details>
<summary><code>k_p^(v) in the qualified certificate — 32 bytes</code></summary>

```text
d7a43c00cced5118e2b5e2592fc7929c5f4caebc6afee9ba0fee7335d28cfe59
```

</details>

| | |
|---|---|
| `Béla` | `id = HU-WALLET-001` |

<details>
<summary><code>k_p^(v) in the qualified certificate — 32 bytes</code></summary>

```text
6fe5693b114559c799871bac31dc32c62d8b4ff5a31278b0ddc4cd103266748d
```

</details>

| | |
|---|---|
| `Csilla` | `id = HU-WALLET-002` |

<details>
<summary><code>k_p^(v) in the qualified certificate — 32 bytes</code></summary>

```text
3d747db67382903115627a981959224fcdea1eb58c06dae05697e374adf8e4d3
```

</details>

The electoral register holds identifiers and nothing else: the VRO administers who may vote. The signing keys above are not its copy — they live in qualified certificates maintained by a certification authority, which the office looks up per request and does not store. Under eIDAS that certificate already binds the key to a named person, so a second election- specific binding step would be redundant.

- ✅ the electoral register holds ids alone

## PART 1 · STEPS 1–4 — Anna's device prepares the request


### Step 1/A — the ad-hoc key pair, generated fresh for this election

<details>
<summary><code>k_s^a  (private, never sent) — 32 bytes</code></summary>

```text
ed19397dafca91ece83c16a56d8c1cc708eb2cde22fdc657d819996fb62799df
```

</details>

<details>
<summary><code>k_p^a  (public, will be blind-signed) — 32 bytes</code></summary>

```text
43a49490476d89c6ec61c225c9556d8b367742c7f34df60245c3620fcdc02d53
```

</details>

This key pair is the voter's anonymous handle on their own ballot. It is generated on the device, and the registration office never sees it in the clear.


### Step 1/B and 2 — encoding, then blinding

<details>
<summary><code>enc(k_p^a)  EMSA-PSS, SHA-384 — 384 bytes</code></summary>

```text
0911c719d484cb970fc9bfb9ff8fd63f4234e2498e752c25c6a3274089df3832
d9c8a35a6efa489f038006ab1b61b5443021efe3be199175fe08e753777b15aa
2337b52e1e68fad3b099e14422977619cd78163b8fe3afcd381592683b4def97
30f27d04a596b2ce9697641393766a709c318de32a52f6c015437646fc62d317
7f68f00753dad6a64647ccc3f54382d57f1154fa2a05d2da1fc5eacaaef5d3c5
3b61075009edb941694bab40f04b2a6b19361ac11449333ef0aa1562bffc1336
8f8be90b94b4cb5aee49fd0daf91a306d5ee493cdecc6088b6781fbc296e6d93
423d3f7cfe70fec17620e59e4a72758761ffb5f53bcecbabae0d50b569d7cc67
e11dad70b06b83d05c6708e3efa42d2007d3031e728f9e6897c2de7f6ee70500
e5e771371d0a2dbebe5383afb8962572771397258446dc3e47fcc777e3a674ce
8d813b3d27ef0cfd2bb73d6408199a4038bb03602f5f83f3d3475cbb13ad5905
1c615c96a51ebd661fb8682a6727ae059fdfdad7584e42a9a8ebe96f0fc145bc
```

</details>

The salt inside that encoding is drawn by Anna's device, not by the signer — RFC 9474 puts the encoding inside Blind(), so the VRO never sees an unencoded message and takes no part in choosing the salt.

<details>
<summary><code>blinding factor  r — 3070 bits</code></summary>

```text
256ab28fc5e7824e6a2b969beeca5e169793e01dfb97673375c5ec05e3801e95
5f6961f4963341bffb92047e4aef0a825c38ca7f5be75836a38827dce0bf94e5
1016cf8770dcd17c18de95f4a1517c1fda701bac70d1289d8d6b55bbc5c1a831
08b530eb1cff126ab7144b07769f1d09509dcd53173660cd7523ff67a5814107
c73a7426f1167959cc48534f3fcc8de799d017bfd235c40da78dc2842e4fa770
ecc3145dc4f5c3877c0183977d8965a54a8bb7a45163be7d6d2b6c6bcedd0b24
8481fa1c9b746030fbeae56ed0bb57185543d793a5959ad74a7098834d3f3723
3e97dcbc03631595849d24c6ed1b28cd0a52e0df8f10af17536567ebf6f688d4
394f7f03b06ebf153f869fd07252f9c8f20a5d8f5cbc439d67b0ea43c9692612
453c8bc00df366dba523092f85efa5b22469bd097831ddb11c884b302f9d149a
e556802011b555ab2ab4a762e91ca50f4583dfccc236a1661d5c068b08c09cba
50b5c909906000452c6d80c6cea0a24af3f81fd4f3754657c350dd3228a04f08
```

</details>

<details>
<summary><code>r^(-1) mod n_R — 3070 bits</code></summary>

```text
244dbc7cafed0e999340f5bf692f50c70b0ea02339e3cabcaccddabb1feaefda
15934b0fcce2a3fc9c2893aad9e4769478d0cbecd2a8f201984d6da71bc397c1
23265f2d7641f31bd07fefe5063d223a4759740b320532b448e4ee38404cc0b3
82a05a88cd04f5fd05975bff7db56391e58d601cd95de40d5a2c4a09c7dc011f
3fc5abe726b6f11020678c6c90c14eb64d49fd9d4b64fa74cd036b3b562cb682
2711b77a14a3e2f4942e9de9c50b10e0d278e5236842ebd9a88be55dbc7df439
97e47e2a0dd15401639b25b077dfb4ac03f80fd05e02c5d60a5fdade69ecc90d
eeb13a1e796d2b96f81050c3cd9df777d8675c7cf9fa8773d3a166a199b52e39
82de279fa3f6aa2618007bed0dfc1ed9b9794c6115fd585c0699285187cb05bf
fe5e2f1f6e14d0380150431d46f4b5c3c165f76e3fed26c1f90565ca92d0e871
0b79ff16e02bca1d46dc09c11516e67420ca97c12188cfd25f33196cd4256e76
d621b4e3a86da2c7cfd1ada3b82769b8aac2f14d95c31397a3a8323d94c91b59
```

</details>

<details>
<summary><code>r^(e_R) mod n_R — 3072 bits</code></summary>

```text
a239eaf78103330e47502a5decd67a313ab11588a60a98cea9308cae7547d06f
e6af27a700f8e5f3a4cb59e90ae7866384706b321968cba50704c05bcc589487
354b62e341c58a5cfda15a33fb312768917abe453efa5d5e6a1c4d5ddc42bbc5
5a82db1f914fe3b28e1cf837229b830d49c6d84148c071738954f0c05b0a09ee
5562cdb432ff83424edede462e665c515dd898c0f32846e1a44aed7a7936dd43
9d3a59a6b7bc644baa381edebf33d300d9b52a64689a5c8f8bcd0c9300d719e3
eaf6e9aaeeee50d469f59364d881e37b4af8a3f3fdb55d64d01f66dea0a7285d
5b35c061d71a91b0602c8071bbd60a2beeaf34ab79b8f0085202942dfa9dee39
c7c18f70c5577884f1cdc4843f768fa8eb9e16f58300ce978ae2731f6d914818
5aa0baa9beeb3a2798216643f7f6128cd8e05c27f2166b7e4b9f2bdaa9cc13f6
bf59e446384da402a2f1bfcd4ba49e254387dc91199d11337207492833d0ebc3
3a17ffdd31ba35d990dd0a26f2dc6537839c565554fd15f1dd01faa729629189
```

</details>

<details>
<summary><code>c = enc(k_p^a) · r^(e_R) mod n_R — 3072 bits</code></summary>

```text
b7334255bbacdbbd699de59137de5e0b4e921c362968fa13ffe101391e9ccc75
4268691cd32bbb055196719b655565d5af37803747b2a6f9b258503f6e12540e
17bf0666ce5ba14d8c707a27a3a4d0e6b8758792fef6c668d257d2968536c92b
ee60ff19339ee5fae1a41e1d1e8947b10a19ed4fa3b6ae801bd47966fc1c33a2
d2d01b913300ea76cefe479d8601fbc4aeb8f7962cceef6366e60d60a8e9b866
3163549811b066debbbd56ad0b0f67ab70023fd479f4a81a4703d94fc68ef9a0
6f083ba0d92c599cd5d835753d709bb8a4ad047e8d222771125dcadbeea333f7
6c0e8d161f0d00703b85767c766cb01fc960581598b2c96b0dc20b39df5c3276
2a649fe7d2836e195d87419972cba0f9660b0983a1eafabd5e30b0244c663670
88b17282c2a2c2f45454f051834994ee7bcf7701334314e051282b56c42ad0f4
62995a47262e35225e93f1dc8493c130aa75cdb14fcea8fcdb2dace4a34de24b
c939dc9d0e097605389055ea73908c80bcef8af2bad3f8d206f7b603b5445553
```

</details>

- ✅ c recomputed from enc(k_p^a) and r matches the value sent

- ✅ enc(k_p^a) < n_R  (the encoding is reduced)

- ✅ r is invertible mod n_R  (r · r^-1 ≡ 1)

### Steps 3–4 — the wallet signs the request package [id, c]

<details>
<summary><code>canonical JSON actually hashed — 557 bytes</code></summary>

```text
{"blinded_key":"tzNCVbus271pneWRN95eC06SHDYpaPoT_-EBOR6czHVCaGkc0yu7BV
GWcZtlVWXVrzeAN0eypvmyWFA_bhJUDhe_BmbOW6FNjHB6J6Ok0Oa4dYeS_vbGaNJX0paF
Nskr7mD_GTOe5frhpB4dHolHsQoZ7U-jtq6AG9R5ZvwcM6LS0BuRMwDqds7-R52GAfvErr
j3lizO72Nm5g1gqOm4ZjFjVJgRsGbeu71WrQsPZ6twAj_UefSoGkcD2U_Gjvmgbwg7oNks
WZzV2DV1PXCbuKStBH6NIidxEl3K2-6jM_dsDo0WHw0AcDuFdnx2bLAfyWBYFZiyyWsNwg
s531wydipkn-fSg24ZXYdBmXLLoPlmCwmDoer6vV4wsCRMZjZwiLFygsKiwvRUVPBRg0mU
7nvPdwEzQxTgUSgrVsQq0PRimVpHJi41Il6T8dyEk8EwqnXNsU_OqPzbLazko03iS8k53J
0OCXYFOJBV6nOQjIC874ryutP40gb3tgO1RFVT","voter_id":"HU-WALLET-000"}
```

</details>

<details>
<summary><code>hash([id, c])  SHA-256 — 32 bytes</code></summary>

```text
87bb7d4b914a826701355c5033344f8c15b294d6d63fe88f65fc18cb672c24e2
```

</details>

<details>
<summary><code>s = sig_{k_s^(v)}(hash([id,c])) — 64 bytes</code></summary>

```text
a211f9f1ed7db67c88a6295c21ac2965ee07ae714c6f520b77674f272102e2e6
62b60b7b93efae7b806eae031b7d5364060c81c842e8941368caa7f1629a1207
```

</details>

- ✅ the wallet signature verifies under k_p^(v)
Note what travels to the VRO: the identifier, the blinded value, and a signature. Nothing about the choice, and nothing that reveals k_p^a.


## PART 1 · STEPS 5–7 — the VRO validates, logs, then signs blindly


### Step 5 — the checks, in the order that keeps the roll private

| | |
|---|---|
| `5/1` | `certificate found for this id? True` |
| `5/2` | `signature verifies under the certified key? True` |

Those two are all that may be answered before identity is established, and both failures return one opaque result, NOT_IDENTIFIED. Otherwise the token endpoint would let anybody who can spell an identifier discover whether that citizen holds a certificate or appears on the electoral roll.

— identity established; specific reasons permitted below —

| | |
|---|---|
| `certificate revoked?` | `False` |
| `certificate expired?` | `False` |

on the electoral register? True

| | |
|---|---|
| `token already released?` | `False` |

Revocation sits below the boundary deliberately: a revoked certificate still verifies mathematically, so by the time the office can see revocation it already knows who it is speaking to.

| | |
|---|---|
| `outcome` | `ISSUED` |


### Step 7 — the release is logged before the signature is returned

<details>
<summary><code>nonce (disclosed only on a signed step-12 query) — 32 bytes</code></summary>

```text
60247809dd9c727618e86afeaef8d5699ff0887f908fc2855484fceba6bd20aa
```

</details>

<details>
<summary><code>commitment  H(id ‖ nonce) — 32 bytes</code></summary>

```text
1c935a812aab167e0c64da2a55f475445c59a42907a7e0a2e80ee585ead1c268
```

</details>

| | |
|---|---|
| `published log entry` | `{'commitment': 'HJNagSqrFn4MZNoqVfR1RFxZpCkHp-Ci6A7lherRwmg'}` |

<details>
<summary><code>previous entry hash — 32 bytes</code></summary>

```text
0000000000000000000000000000000000000000000000000000000000000000
```

</details>

<details>
<summary><code>this entry hash — 32 bytes</code></summary>

```text
4d2775f659cbfd76f0a88c2a3f49002d93710dcf56845c7645fa282e51aeeaf0
```

</details>

- ✅ the published entry contains no identifier

- ✅ entry hash recomputed independently

- ✅ logging happens before signing (a token cannot exist off-log)

### Step 6/A — the raw private-key operation  s_c = S(c) = c^(d_R) mod n_R

<details>
<summary><code>s_c — 3071 bits</code></summary>

```text
5ce5cc0f12ead93a56f3da59cba96e0e30d5406758c172287282c9e1e4c6ee92
38db14f2a42dc8126eb20b04d8711a35761e0b5728fde93f16a06e0ddbd33b5f
a5b1f29420a83a52472e4d058e85ca1595a91d0d79a3da44cc9f23d43cb05260
6fdccee618d9fa36bf0067c661a51c3eb456fe7c9f49485ed2885d201e1673be
1ad3c39a5b3ba6ad83df96c30b932fb897b1ebd9a2c52bceaa95178e03946e66
006e821aa20bbc17500cbf65ea18032270fffd1d9295d65611421706cc8a2380
85191c4692d7d33738d3d2744d67209d9035e3388295fe2a68eb1d976a01f815
670ecb61a9c7624b6f52c70fb26e37a9810c9525751740bfe751e77a283dd3be
2d7b67967fa01830400092004eb7d87a64ed62a479b94aa72f8dbfaedbb6927d
6611358bab92cd98cae7e8a4d7d4c6d0cfc8bdccf902224cbdd9bc89fd0aab30
5545a9e9a965216d681068e5ef6773553b1f0f5f89495124863f7a4d7a7c8902
987a911aed6e067b66f1a4b10169f796eef56c80d3e262f39e4d2b02cacbbb29
```

</details>

- ✅ s_c recomputed as pow(c, d_R, n_R)

- ✅ s_c^(e_R) ≡ c  (mod n_R)  — the fault check of §5.3
That last line is the Boneh–DeMillo–Lipton countermeasure the article specifies in §5.3. It is performed here by the demonstration, not by `vro.py`, which does not yet implement it — see CLAUDE.md, open items.

What the office holds after this exchange: an identifier, the blinded value c, and s_c. What it does not hold: k_p^a, r, or anything that links either to c.


## PART 1 · STEP 8 — Anna unblinds, and checks the office behaved

<details>
<summary><code>s_{k_p^a} = s_c · r^(-1) mod n_R — 3072 bits</code></summary>

```text
b51f8909e8fe0aa36ae48d3c49fa5c24bc90ebf195f5f3e6c4a4215f2f6d93e6
0287bd4233059ea3cadb2a1bd5b2dfa4ecc9391ab6055ef3baa9c5f3a860f0c7
9cb4b392ccb3f3e41f15c0d11649dff3366547f2c2938008162d7da63c71e6e7
eef4c48f6586730359525d733b46445de85ecb23dd13eabb5ad5a237e9479f8f
b316af884184894c23f3be9628627a925103e21928037d1e3793488e8b5a6f82
fe411ba0966db7d85d998df97695f59524a6434ddfd77862859a1df490697252
f2c55ec987475ff0152539652e0dfa48aef88519a3c87b0a0523d208c390d524
d0ec32a0e0b5b9fe35b26a5323892fc3724b7d0f8c1ecbe611b8a1d47425b877
990feeda17ce2bba29fba45a9111a7a11b11d4e60ee2037609f3657ff094d980
1a805ef640d0d91836009da8072357ae7525ce2ced24fa5a3c66b32c158d2618
fedc548effa7d3c83ce035749956ca7b98fd7cd17a279d81cb0f340ae6360328
c7136552cf85baf2c8e7182f4dc6b90c46fe3254ca53daf1d50505ee1a284367
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
{"adhoc_public_key":"Q6SUkEdticbsYcIlyVVtizZ3QsfzTfYCRcNiD83ALVM","sel
ection":1}
```

</details>

<details>
<summary><code>hash([i, k_p^a]) — 32 bytes</code></summary>

```text
97df03a96e7ca45d336ea0b7acb3ddc0f4bcc6c879c318cf1b709e74a293d205
```

</details>

<details>
<summary><code>s_vote = sig_{k_s^a}(hash([i, k_p^a])) — 64 bytes</code></summary>

```text
65b115cbb44bae68827eb320d3285bfdd832412801410a30b444091eafe41c60
379b61a12338eec7d0f73516c3a217e16c53084e2fee8e3753222e3270c01001
```

</details>

The complete published ballot package [i, k_p^a, s_{k_p^a}, s_vote]:

| | |
|---|---|
| `i` | `(selection)                 1` |

<details>
<summary><code>k_p^a — 32 bytes</code></summary>

```text
43a49490476d89c6ec61c225c9556d8b367742c7f34df60245c3620fcdc02d53
```

</details>

<details>
<summary><code>s_{k_p^a}  (token) — 384 bytes</code></summary>

```text
b51f8909e8fe0aa36ae48d3c49fa5c24bc90ebf195f5f3e6c4a4215f2f6d93e6
0287bd4233059ea3cadb2a1bd5b2dfa4ecc9391ab6055ef3baa9c5f3a860f0c7
9cb4b392ccb3f3e41f15c0d11649dff3366547f2c2938008162d7da63c71e6e7
eef4c48f6586730359525d733b46445de85ecb23dd13eabb5ad5a237e9479f8f
b316af884184894c23f3be9628627a925103e21928037d1e3793488e8b5a6f82
fe411ba0966db7d85d998df97695f59524a6434ddfd77862859a1df490697252
f2c55ec987475ff0152539652e0dfa48aef88519a3c87b0a0523d208c390d524
d0ec32a0e0b5b9fe35b26a5323892fc3724b7d0f8c1ecbe611b8a1d47425b877
990feeda17ce2bba29fba45a9111a7a11b11d4e60ee2037609f3657ff094d980
1a805ef640d0d91836009da8072357ae7525ce2ced24fa5a3c66b32c158d2618
fedc548effa7d3c83ce035749956ca7b98fd7cd17a279d81cb0f340ae6360328
c7136552cf85baf2c8e7182f4dc6b90c46fe3254ca53daf1d50505ee1a284367
```

</details>

<details>
<summary><code>s_vote — 64 bytes</code></summary>

```text
65b115cbb44bae68827eb320d3285bfdd832412801410a30b444091eafe41c60
379b61a12338eec7d0f73516c3a217e16c53084e2fee8e3753222e3270c01001
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
fe4527a00efc3f0d4192a6a5387699ec64bc3394030c12e76387756d006075fd
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
a2c155df954bb3b4e4d389b931cbe477f525167328555bbe4fd90a559c4a73e5
0e809e78973c8e3478886f20216a81aac405e10ce8c3d4a3300c3e33063eec0b
```

</details>

| | |
|---|---|
| `released` | `True` |
| `index in the published log` | `0` |

<details>
<summary><code>nonce disclosed to Anna alone — 32 bytes</code></summary>

```text
60247809dd9c727618e86afeaef8d5699ff0887f908fc2855484fceba6bd20aa
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
| `Béla` | `selection 3  accepted=True  head aa808283c9ec265d4e946af18a239d29…` |
| `Csilla` | `selection 1  accepted=True  head 5c2cca0667bfffc15d0a5c4c16e3866b…` |


## PART 2 · THE ANONYMITY CLAIM, AS DATA

Below are the two records side by side: what the registration office retained from Anna's exchange, and what the public ballot box shows. The value that connects them, r, exists only on Anna's device and was discarded after step 8.


### The office's view of Anna

| | |
|---|---|
| `id` | `HU-WALLET-000` |

<details>
<summary><code>c   (what it signed) — 3072 bits</code></summary>

```text
b7334255bbacdbbd699de59137de5e0b4e921c362968fa13ffe101391e9ccc75
4268691cd32bbb055196719b655565d5af37803747b2a6f9b258503f6e12540e
17bf0666ce5ba14d8c707a27a3a4d0e6b8758792fef6c668d257d2968536c92b
ee60ff19339ee5fae1a41e1d1e8947b10a19ed4fa3b6ae801bd47966fc1c33a2
d2d01b913300ea76cefe479d8601fbc4aeb8f7962cceef6366e60d60a8e9b866
3163549811b066debbbd56ad0b0f67ab70023fd479f4a81a4703d94fc68ef9a0
6f083ba0d92c599cd5d835753d709bb8a4ad047e8d222771125dcadbeea333f7
6c0e8d161f0d00703b85767c766cb01fc960581598b2c96b0dc20b39df5c3276
2a649fe7d2836e195d87419972cba0f9660b0983a1eafabd5e30b0244c663670
88b17282c2a2c2f45454f051834994ee7bcf7701334314e051282b56c42ad0f4
62995a47262e35225e93f1dc8493c130aa75cdb14fcea8fcdb2dace4a34de24b
c939dc9d0e097605389055ea73908c80bcef8af2bad3f8d206f7b603b5445553
```

</details>

<details>
<summary><code>s_c (what it returned) — 3071 bits</code></summary>

```text
5ce5cc0f12ead93a56f3da59cba96e0e30d5406758c172287282c9e1e4c6ee92
38db14f2a42dc8126eb20b04d8711a35761e0b5728fde93f16a06e0ddbd33b5f
a5b1f29420a83a52472e4d058e85ca1595a91d0d79a3da44cc9f23d43cb05260
6fdccee618d9fa36bf0067c661a51c3eb456fe7c9f49485ed2885d201e1673be
1ad3c39a5b3ba6ad83df96c30b932fb897b1ebd9a2c52bceaa95178e03946e66
006e821aa20bbc17500cbf65ea18032270fffd1d9295d65611421706cc8a2380
85191c4692d7d33738d3d2744d67209d9035e3388295fe2a68eb1d976a01f815
670ecb61a9c7624b6f52c70fb26e37a9810c9525751740bfe751e77a283dd3be
2d7b67967fa01830400092004eb7d87a64ed62a479b94aa72f8dbfaedbb6927d
6611358bab92cd98cae7e8a4d7d4c6d0cfc8bdccf902224cbdd9bc89fd0aab30
5545a9e9a965216d681068e5ef6773553b1f0f5f89495124863f7a4d7a7c8902
987a911aed6e067b66f1a4b10169f796eef56c80d3e262f39e4d2b02cacbbb29
```

</details>


### The public ballot box, first entry

| | |
|---|---|
| `selection` | `1` |
| `adhoc_public_key` | `Q6SUkEdticbsYcIlyVVtizZ3QsfzTfYCRcNiD83ALVM` |
| `token` | `tR-JCej-CqNq5I08SfpcJLyQ6_GV9fPmxKQhXy9tk-YC…` |
| `vote_signature` | `ZbEVy7RLrmiCfrMg0yhb_dgyQSgBQQowtEQJHq_kHGA3…` |


### The one value that links them, which nobody else ever had

<details>
<summary><code>r — 3070 bits</code></summary>

```text
256ab28fc5e7824e6a2b969beeca5e169793e01dfb97673375c5ec05e3801e95
5f6961f4963341bffb92047e4aef0a825c38ca7f5be75836a38827dce0bf94e5
1016cf8770dcd17c18de95f4a1517c1fda701bac70d1289d8d6b55bbc5c1a831
08b530eb1cff126ab7144b07769f1d09509dcd53173660cd7523ff67a5814107
c73a7426f1167959cc48534f3fcc8de799d017bfd235c40da78dc2842e4fa770
ecc3145dc4f5c3877c0183977d8965a54a8bb7a45163be7d6d2b6c6bcedd0b24
8481fa1c9b746030fbeae56ed0bb57185543d793a5959ad74a7098834d3f3723
3e97dcbc03631595849d24c6ed1b28cd0a52e0df8f10af17536567ebf6f688d4
394f7f03b06ebf153f869fd07252f9c8f20a5d8f5cbc439d67b0ea43c9692612
453c8bc00df366dba523092f85efa5b22469bd097831ddb11c884b302f9d149a
e556802011b555ab2ab4a762e91ca50f4583dfccc236a1661d5c068b08c09cba
50b5c909906000452c6d80c6cea0a24af3f81fd4f3754657c350dd3228a04f08
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

- ✅ nothing entered the accepted ledger

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
f8909a98890409e68c137ee216ee88debc68164a50b871a5b0d42b5943789b62
```

</details>

<details>
<summary><code>token  (invented) — 384 bytes</code></summary>

```text
258b64071393f932b12aa412ffb95606ebb4ae2b7a515927e1160b0c8b8a79cc
a1071f0270c1315fbb66a8b5258cf6d85b63f6ce03860b7eb220086cc3832ac4
53030105c151f0371e9aa1cceac00991e6672290c1d0c3fb8fba3ce24fccd968
8e18c7f4266bb32e95ec22c1f8cd2ccb3bf46edeaf42d75fbf3fbeeea3588e30
9242b98090035caea8da56f0cef4699615a4cecead78da94fb51a857dfae35d1
fe8dff67897ed27129cdc920372ec397eb85ea4b112b7b2292bbd38449c9aac1
a8223e4b29c5a9bb3ebf2669e67cdf923ade13ea9af668f3c33fa9e2c8c7aebe
564f5a0a7f624a9f48c75e6a1039688f3bd8c04b091940e682c83a2bc3b3dbd3
39fda0b5acf4fc1ab60106c1011e62e7ddc1febae6b196a447352bed31c959fc
710caff31a80bcf566888a4ccabbac3988a7cab276c2f768e4b88d334a7486c9
449754a739186b5e9b0d02a4a29b7c07cbda903b6aab37f6d5a1ef3bbc08b19c
605c8d7bd631cf40da4e398bd4ccf907762f7876f48a37eaa66ffe4bddfe7506
```

</details>

<details>
<summary><code>s_vote (genuine — signed with the matching private key) — 64 bytes</code></summary>

```text
534f506e6b5c2dc5cd37e29edff7215b41a7848d61c079051d60d8e7d2e56f98
9373bb6b42471ac7715d47b1e193249998fbc2714acb7439c4c2c72df68b4604
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
93da1019ebc73cf67eea66986142543e94493b0a7848cd244b8523e0650e9fac
```

</details>

<details>
<summary><code>victim's token — 384 bytes</code></summary>

```text
1fdb6457a848c0010c9dd029e6e15aed91506c12a48efc8556466f9c06bcdbd1
7fc120a63450dee6e404a027dfa434ff9cd3a56a263ffa14f56e0a74fe58cfd4
1bf0b40deda4515c9588e03521ec5e25079b8fb946438de109f53a1d1aeed981
f3fd32cb50c800f80b321ceeb5b3db313e7fa7d2402241d064de0e5a424f642f
26d9a071274bcf94140bcdca9af2f92be7cbfd5bba54b7307b15efcd3c8c0008
7a30486248b391f79aa69a976dd37bef729142bc55771239614fd61f53860113
7422151046e5b20083a38721d9445a4b2b172e728728b4d04d223a86c2885e59
520a56d1424c334e961468bf18caecf8bcfcefe62f5dd7d2a3b2420b3957c955
b856a8bf9466edb1877674278b361ff084e996112b36b2978acc750127c33243
1cae1fedf1ed1eba2d2c3a32260ec247f6e7920ee0c661d9cafa94efab7af2ce
d7e01b5f531e8a94df835d7763c81f2c727e0a44b635f1e7c0c7c885e05e1090
58b38a47e968f5a2b1fb758aa4e1f065d2b9a7519c9de6e10f860174651eb3b4
```

</details>

- ✅ the stolen token is genuine — for the victim's key

### Submitted with the thief's own key

<details>
<summary><code>thief's k_p^a — 32 bytes</code></summary>

```text
35c0f31dd6d25fb7821e4c51c69dbc51038df2b6e766a85b404d567af679d2b4
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
353f779b26ab881fc8ed1fadb632c90cf82b72114d7a4b4bd7ee0fef23c44cb0
```

</details>


### As it arrives at the ballot box

| | |
|---|---|
| `selection` | `2` |

<details>
<summary><code>hash([i, k_p^a]) of what arrived — 32 bytes</code></summary>

```text
259d730794a78e73bbed83dbd97028ef6ab6b94fc703aa5df342251e4a2a1ed0
```

</details>

<details>
<summary><code>s_vote (unchanged — the attacker cannot re-sign) — 64 bytes</code></summary>

```text
b21703841aed2f23706d80344288867e761f04d2e85c5840c677a9ffd483754f
f0dedb810786b38da40f2033d7ecb4e49e1dcee78d301898cfdccd4e53174104
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
792fc08b5584e92e45ceb8ec8999e4f7501a3d8674df14e7caf6125ffe53557a
```

</details>

<details>
<summary><code>s_vote (signed with the attacker's k_s^a) — 64 bytes</code></summary>

```text
13a044b9a82c72fc08a4636985a9f437f6354b23d4ef6da664e7d748849138a7
668a264944ce9044b6b22200d07a5ed8d7e5a78be749d44bf501827457ffd608
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
518ce57df95e3c419361334bccdf69c8575842985189458c1ac84ac1423ada35
```

</details>

<details>
<summary><code>s  (attacker's wallet) — 64 bytes</code></summary>

```text
4710a8f6061ebbaa442a3688e153c0b98559fc8e7da4a008f9e5349ee206e3a9
75126489a239e682618c58609455226726410fd391e37622120e3c2e3ef0940a
```

</details>

<details>
<summary><code>k_p^(v) certified for that id — 32 bytes</code></summary>

```text
a10c4a87c6d417a7ffac455454ba8c93a98a57d399537b48ddac058f2754c196
```

</details>

<details>
<summary><code>k_p^(v) the attacker actually holds — 32 bytes</code></summary>

```text
1a1bb62f4f7f6b57dae756795b3a6da4c305d7f7147a0f3205fd7fade523e453
```

</details>


### Step 5/2

| | |
|---|---|
| `outcome returned` | `NOT_IDENTIFIED` |
| `blind signature returned` | `None` |

- ✅ refused: the signature does not verify under the certified key

- ✅ no token was released

### What the office wrote down, and did not say

| | |
|---|---|
| `audit outcome` | `NOT_IDENTIFIED` |
| `audit reason` | `request signature does not verify under the certified key` |

The requester learns only NOT_IDENTIFIED. The office's private log records which of the pre-boundary situations actually occurred, which is what an investigation needs and what an attacker must not have.


## PART 3 · AN IDENTIFIER THAT IS NOT ON THE REGISTER


### The request

| | |
|---|---|
| `id` | `HU-WALLET-999` |
| `certificate found?` | `False` |
| `on the electoral register?` | `False` |
| `outcome` | `NOT_IDENTIFIED` |

- ✅ refused before the identity boundary

### Now a citizen who *is* identifiable but is not entitled to vote

The distinction the state machine turns on. This person holds a valid certificate and signs correctly, so the office knows who it is talking to and may give the real reason. The previous case could not be told anything, because nobody had proved to be anybody.

| | |
|---|---|
| `certificate found?` | `True` |
| `on the electoral register?` | `False` |
| `outcome` | `NOT_ELIGIBLE` |

- ✅ refused with a reason, past the boundary

### The two answers side by side

An unauthenticated party sees NOT_IDENTIFIED in both of the first two cases and cannot distinguish a citizen who does not exist from one who exists and is eligible. That is the privacy property: the token endpoint is not an electoral-roll lookup service.


## PART 3 · TRYING TO DRAW A SECOND TOKEN

Equality rests here, not at the ballot box: a voter who held two tokens would hold two unlinkable ad-hoc keys and could cast two counted ballots. The box cannot detect that, because it cannot tell the keys apart.

<details>
<summary><code>first token — 384 bytes</code></summary>

```text
40d924fab1645023b439dba18f424dd52ad56cc9f1980070462a39aa01268646
d80207933852e51ecc1f35b35f141f35a24f91805ca0250f9e2cc73142c6e7c0
18139faafaafee0f8561583f5f3971d9a7333d35645d7dc6c9645747220fbf87
0727adb68ad725f2d0aaf5744785a30ac6cf45b9f54faebf051c8c1ecc706b38
a2bc26d8fbb77ef6bb45c972ca8b28b5162044dad920065643c3fec5879b8e46
a7cef9f249a8dfd2171f048ee368abc4621afe0cd522a6ceac1c6fba35acd8ed
6e7098046ece161567c57f4a2c6f0aaafeb6d842964de1481036c314cec83c88
6b193eca30a7dfa9184223dad8a2947fa607392917104296446b30502c3c09f3
bc02111177263eb9e67c7f58582144f2598724de7a5baf9f201b7e8cb54ff08c
d739b294d7a06a502b8427d5636b2928a56cf7c503d3c7c0dc358e4f35b79941
8f771e27a0fcf20365b657603a1dcedb2130c0e0b1a4d1acfb7924f3e23710c5
a43156c991cecf8130dc6d0470d8f28175311b5ee0627ecfc99765f3e7efd277
```

</details>

| | |
|---|---|
| `release count` | `1` |
| `outcome` | `TOKEN_ALREADY_ISSUED` |

- ✅ the second request is refused

- ✅ the release log did not grow

## PART 3 · THE OFFICE PRESENTS A DIFFERENT SIGNING KEY TO ONE VOTER

The subtlest attack here, and the one blinding does not prevent by itself. Blinding hides the ad-hoc key from the signer; it does not constrain which key the signer uses. An office that reserved a second key for one voter could afterwards tell which of its keys verifies a given ballot in the public box, and re-link it.


### Fingerprints

| | |
|---|---|
| `pinned in the voter app` | `4f6898c48af37053018689f6e0cc0eec93ea10c1745ad8d6…` |
| `offered to this voter` | `6dc57aa7f8f80dc2147fb4d2273fb9cbc930c5a11c13b475…` |
| `ValueError` | `VRO public key does not match the pinned fingerprint` |

- ✅ the voter app refuses to proceed on a fingerprint mismatch
The defence is entirely client-side and entirely procedural: one key, published before voting opens, pinned in every client, identical for every voter.


## PART 3 · THE OFFICE RETURNS A SIGNATURE UNDER ANOTHER KEY

The voter's entitlement to a token is consumed the moment the office logs the release. A response that does not verify must therefore be caught on the device, at the only moment r still exists.


### What the office returns

<details>
<summary><code>s_c (produced with a different private key) — 384 bytes</code></summary>

```text
2f85effc105680c05f5cb20713557213d117a819fd05c17aabc78f807f0d9275
5adfec6e20c94822c6ae00e70f3619280b201af63a13abd92e27b69020a3e7b0
c52bb95fd5525ab1801036b2db5b5c0eda944ab90a64195e37add502e701f73f
14c392418b7c72c3e11694b362132cfedf3b3eda05d0a0e84f7df6a0b4508e36
b187f44867a292523d322836af9b07c54a268a889e892ccc1a33e824173dcc11
678263ad6ba3714b517f68d2cf388533d2ffcb40ae710f11887b03cc9796329f
092bb295abdaec33c38eaac9fc71f5dd393e4c812a59628a93404ae26be7f697
5a16867a3761123d1e72969b2f7eec78e633d0a37d6157090573cd0c723f4561
f7f7ebca5d7b98719300898c436b6a905295582c27c63de6ff3275e453a1a5a0
2e08df6bd4e5d2c3b19f599cebcc2fa69e61e7702cdc7e243c50363dbbffd803
6bdd5ae596f489bb8eb2d0c9185964997a2d82f525a6361ecec558f9c13473ae
99e0e946ddd60e3080df5b7c56930163dc77009f87268b21cf32d39d3e9058c7
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
79780b9132ddd21374d698e3908424cbfc7576c34b475c9045f23520526252ad
```

</details>

<details>
<summary><code>sig1 — 384 bytes</code></summary>

```text
96a90227b84291f4bc69b571968143bfaf15f985c9f5c5861b9a96f89b52f08c
8c41875a62797b958c3bd13d1ca2970d5c95e90dc0bfda30527ab672da334434
cf52a01786ea68d3223fa3e6648c091a67346061fd87873c599a75bdc60ee821
b0cfadaf301581e2437ac555422e30073c7834688ce7512a68744f6eec8b0093
0eef6e39357d0bc4404c0c12eeedcf572c2b8bb76ca8934a1e023741ae973a13
112afbf25c3193563337f5c3fc084ac9f55d356e36a4533cbe381a31b1a42cbf
0dfd2a235e9f6d937bd28e09cf6219f4c0fe10fe82d40d44ef44f099968d8fa4
184db42ca66a14be70728694b87f90749f0d071540b45bb40b77c3d1acb72a1b
d511aace3fb9ab5dd38de22145f6ece9b0266664b3776c031c3e2d94861f7b96
559c79ad385c65b0ad454916078f84cc3dc882f111e63d2b70502a6c899151ff
261d48f1354faac054ea5e1929c2c44a26526a647f25f25fde614892e73996b1
312271c7eec88e65b503b4f259b71bb261d2ff00a27e32b2e63c96e550304a25
```

</details>

<details>
<summary><code>m2 — 32 bytes</code></summary>

```text
356f45b402ab5632ab1f93c0636f3519074f3de96c3ee2d4e678d247dde771bf
```

</details>

<details>
<summary><code>sig2 — 384 bytes</code></summary>

```text
a3b72b83a266a556a7e03a4c774ca657842bf1b885d4d735dcb8807e0e9ffc49
02815a495aee0815e200180278584aadb3a57aba637be4cf90b9fc6e1955a55e
14b5ee44808f71aa914c0df5d45734862851536232bd6fb5b0048e36a6090a2a
a44287514f6eaaef7e01905426b6686987a9e4b83660b0c952a69b51f6a715e0
0922855dba35086ebf4e06365d97b52a30173b6551c678a2286a12a94a07ac27
50f6b4d8b4d7bb068768ec6b4d5b2b156f8066da0b0c1c2f31a407eee1e41a98
aa0d539c05be36f3ac10587a153d3bd07711cffc6ae637ad6de7b05a4eb339e1
9f404ddcbfcda67f913197e6617896796f57bf994d0ca6ed86c006d4e7533fee
9fd665ecf7fd3c1712de8ed771c404ee835f5acc0f16e9101552cbbc729e472d
76d29ec3417969a96e85611a630f3ed484412047dae7a8f4499ecf31b4bb4822
675c38a5d623f252e0485d9352ca65275ad56eb887eb0c1166815befc9ad3f35
ab663d2981a9ea04ccadeb5b6f5c6da25d61279fcfdd500dd55e41770eacef67
```

</details>


### Their product

<details>
<summary><code>sig1 · sig2 mod n_R — 3068 bits</code></summary>

```text
09b6e853ff274f5165736894d4699590f41f276bfbddcb7a55a137507da6696d
c58217f3f5e03a6b8a11cf9e971d49c7dd3b1ee2197e421a8b67a75f2b3c1678
34ed7c7db02ce136d9ad17d8e76416f46306ea146f25860b1bbacbe763b52316
64447dcf5b2424e616c0a9d17b6cb6df71df87380712f4185835889ce689eab1
b694fd37082b1f84d80ea6dbd82e13fc265e5756f0a98293668fc93292b1cabf
45c80989bdcd80f7f9419719924c3c1aefc888d65a0e98c6fbc973bab1be96f0
8da1ceb2849c2b6f4644aba57ca07e5804fc3661f9cdbe1f90d095e6aa62a489
8b1a863d2a5fdfe4d27305348a08545a3a87d34e99f1e8b857cd8ac017dc3d87
d9cd86ee80e166368dc3bc618d55016fd3e351bcc73c1f74a524fc70f15b04be
bfbb1a0cc67c162a569ee3c7e3af42a8b011d74b1647cb6669e0a91e74f4a54e
aa56e9795ac36feae51ac28d58cd6682a2a84772354639f01b2a89a075757ed2
08225bf237a56e7c82d36ad8a9a7c980c693316079271ba64ad225d04e455864
```

</details>


### What that product is a signature of

<details>
<summary><code>forged^(e_R) mod n_R  — the 'encoding' it recovers — 384 bytes</code></summary>

```text
06f1a8954381edc0d7226877a1759c13c6e414b6c2f7c7ff8a8c13f9e71ac62e
d024afe25870468693bc6856782d977d5c9c14bf8c8e11854de2fbc4d61947b2
eb98ba3c3d1939f65943aa1d75bdf3c6891f32b617d316c62b2b4b90c62ddfde
71d6496498e13b29b066030576f33fc11b03289335243e0772de177aea574925
9ffe11397549dbf50eae037835ff071e67a6b20621808a0d83d1725a13c60da3
64522a54637d4404881cc5ceccd1909e5afff858ca9bd094ecb527a967f7e538
16fb36974731130d10832af6b960626af6fc4bfda28de8e930383632338e14f2
4a8fed6cf97f972ddcc35c9df98419a47bc72eac187a27f54a546b8b175c8139
c9fd9b5a9587397cef062367b97e5ca58510cc00fad065b54e6d9fa9a5499433
8bfe022dcce2f628080129fe9fdc21ecaa0c31fb6bc970e06a9a1db3f69b7f57
2971505d6c3f117ab47877ce6b8cc60db69cd88359917b4470030a4fd31ad94c
980e4b632380db9bb43c03faf4c508fd536789a8ff89dfb5c69d841053952cf5
```

</details>

| | |
|---|---|
| `final byte` | `0xf5   (a well-formed EMSA-PSS encoding ends 0xbc)` |

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
| `entry 0` | `{'commitment': 'xHuJ4sPFv2UN30gRIeDaOK5g13ka_zvXMtBa97HLVu0'}` |

- ✅ no identifier appears anywhere in the log

### The snoop queries the victim's id with their own wallet key

<details>
<summary><code>sig(id) offered — 64 bytes</code></summary>

```text
409087a34362a63bb9604514bb8dc9dcbce1b3c42250778d61e63456141a6d52
c2f3e15bff88a662c2993e553b609dfb984937378f5ef92de2b963dd8c28840d
```

</details>

| | |
|---|---|
| `outcome` | `NOT_IDENTIFIED` |
| `nonce disclosed` | `None` |

- ✅ an unauthenticated query is refused

### And an identifier nobody holds a certificate for

| | |
|---|---|
| `outcome` | `NOT_IDENTIFIED` |

- ✅ answered identically, so neither register can be probed here

### A voter who did not register asks about themselves

| | |
|---|---|
| `outcome` | `NOT_RELEASED` |

<details>
<summary><code>signed denial — 64 bytes</code></summary>

```text
8c5230ba57fc4623286f958711fe507ef7999dbbf74207ebeae1776aa3177c0a
e70ea513c7bcad2827eb393d9e3f6589c5acc1c067983d78ccd6072bb8c14202
```

</details>

- ✅ the denial is signed by the office, so a false 'no' is attributable

- ✅ and it does not transfer to another citizen's statement
This does not prevent a dishonest office from denying a token it minted. It leaves evidence of the denial. That distinction is deliberate and should not be described as prevention.


### Why the denial is not signed with the token key

A blind signer applies its private key to values it cannot inspect, so an ordinary token request is a signing oracle. Any registered voter can drive it over a message of their choosing — including the office's own denial about somebody else.

<details>
<summary><code>statement the snoop wanted signed — 32 bytes</code></summary>

```text
5c3b1cfafbabe39ea7c1702ee851627aa2730ab3b86c4b89b6534ebb02bfb0ee
```

</details>

<details>
<summary><code>forged signature over it, under k_p^(R) — 384 bytes</code></summary>

```text
b3dc3a8ab42533c6f9b8c88575224eea5f3391b4f9a21cf33e8ea03f3e821908
0a48676d62190a6639523085a672b4654b3af8550ab99a886a5508adf798f427
8000472f9f8643dcd73de237750323934bdd3614a712447a6a94656ff6ff2172
3c58e3391f33404adfdf1ff82504f63f2fa8004e542c07d92c37d764db3147ce
f3c48333f8e37e9248dd0316525ef271c24ebeb2b448c0af689d95d20e10bd54
20b2a1e4eb0a840f679be4329d8dc7ded62443de52d5761d1f9d26eaa1a2da7a
c6dcbb91192987439a0ff316fae76d66c56d0036f740266b2200e9f1e3f6557d
65be97f0fc6a57eb4f4d7a8787ff548182a70957b9d2313947ac06f800cbd825
ee5a6b4df779886f9e216ce8cc7bd8ff895bccfc8cea483589de0c18b6ed0e29
3a7d0a011b59e4fbca747925c30ccd13d3a81981fb0381f743d71d0c35eec5e7
aa63bcdd80cf16c15574cdf3e2c69be5c3d9259c032d08c1695a332863a4a6ac
9ef26503c3f81c1d650d64d4acff1e4b6468367789f1c23b1e2d9d6fcaab7906
```

</details>

- ✅ an ordinary token request forges an office statement under the token key

- ✅ but the real denial verifies under the separate office key, not that one
Hence the office holds a second, ordinary signing key for statements, and the token key signs nothing but tokens — for one election.


## PART 4 · RE-VOTING

A voter may recast at any time, and only the last accepted ballot counts. This is what makes casual pressure survivable — though not a coercer who controls the final moment before the close of voting.

| | |
|---|---|
| `cast 1 → accepted=True` | `head f3840396e2de8cd330a9af0383b5009f…` |
| `cast 3 → accepted=True` | `head 80c4b1a249209078e2077ab39fdf4e20…` |
| `cast 2 → accepted=True` | `head d0fdca2c5c2dfad9e64286939a6e933f…` |


### The public ledger keeps all three

| | |
|---|---|
| `entry 0` | `selection 1  key -LoRIBL4RcJwViphhyYLnfTw…` |
| `entry 1` | `selection 3  key -LoRIBL4RcJwViphhyYLnfTw…` |
| `entry 2` | `selection 2  key -LoRIBL4RcJwViphhyYLnfTw…` |

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
| `k_p^a` | `WXvIiPicm_e1ouuJyqcIYTSqqRYWn_7DhcaSysdAa80…` |
| `token` | `D6QjJZR63zOsleKrxFokyPbmii_q5TQVc5u2kPs09a9V…` |


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
| `0` | `prev 000000000000000000000000…  hash 957efc667f2db2ecc5b60cb2…` |
| `1` | `prev 957efc667f2db2ecc5b60cb2…  hash 6918f3c327e0acbf8326dc08…` |
| `2` | `prev 6918f3c327e0acbf8326dc08…  hash cce235ff378490d0ee2cd972…` |

- ✅ chain verifies

### Case 1 — a ballot is altered in place

| | |
|---|---|
| `first mismatching entry` | `0` |

<details>
<summary><code>hash the payload now implies — 32 bytes</code></summary>

```text
bcbd27021d99c4f97a97c02c04091a3b7fefc196b97240ead099e186f5e65b13
```

</details>

<details>
<summary><code>hash that was published — 32 bytes</code></summary>

```text
957efc667f2db2ecc5b60cb242fb17d915b09917c4abf73c12188b7273d541d8
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


## PART 5b · WHILE VOTING IS OPEN, AND FROM THE CLOSE

Publishing selections as they arrive would broadcast a running result for the whole poll. Worse, because a later ballot supersedes an earlier one, an observer watching the totals move learns that somebody reversed a choice — and in a small enough population that approaches learning who. So the box publishes commitments while it is open, and the records themselves only at the close.


### The open view, in full

| | |
|---|---|
| `phase` | `open` |
| `accepted commitments` | `12` |
| `chain head` | `6ed223cc8ce4983cdf8ca3dea1622f5d…` |
| `counts` | `{'accepted': 12, 'rejected': 0}` |
| `records present?` | `False` |

- ✅ no record is published while voting is open

- ✅ no selection appears anywhere in the open view

### The running tally, one snapshot every 10 accepted ballots

| | |
|---|---|
| `after 10 accepted` | `{1: 4, 2: 3, 3: 3}` |

- ✅ one snapshot at ten ballots, none at twelve
Whether to publish a running tally at all, and at what resolution, is the administering body's decision rather than the design's — the article gives fifteen minutes as its example. Left unset, no tally exists for anybody, the operator included, until the box closes. This POC counts ballots rather than minutes: a fake clock would demonstrate nothing.


### A voter's own check, available throughout

- ✅ the voter finds their own ballot while the records are withheld
k_p^a is a lookup secret as well as a locating handle: before the close it is known to the voter's application and to the box and to nobody else. Presenting it is therefore sufficient authentication for retrieval, and no private key need leave the voter's device.


### The close

| | |
|---|---|
| `phase` | `closed` |
| `records released` | `12` |

- ✅ the commitments published earlier are unchanged

- ✅ every released record hashes to the commitment published for it
No row moves backwards: nothing available while voting was open is withdrawn at the close, and what changes does so only by disclosing more.


### And a ballot arriving after the close

| | |
|---|---|
| `accepted` | `False` |
| `reason` | `voting has closed` |

- ✅ it is not recorded at all — it is not a ballot

## PART 6 · THE SAME PROOF SERVES AN ADJUDICATOR AND A VOTE BUYER

In the implemented variant the voter's handle is the ad-hoc key they control. That is what lets them substantiate a complaint. It is also, and unavoidably, what lets them prove their choice to somebody paying for it.


### A challenge from a third party, and the voter's answer

<details>
<summary><code>challenge (chosen by the coercer) — 25 bytes</code></summary>

```text
70726f76652d69742db5845b201b50b41e3ebd32335fb039f7
```

</details>

<details>
<summary><code>proof = sig_{k_s^a}(challenge) — 64 bytes</code></summary>

```text
14d7d24f1fc8eab4ec51a92053b007dfa12b6ef42e40b47db69ffe49b23772bd
87917ac27225715709351c9014f6c15ae80b1348628ebd5a3be885a3442a0207
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

Everything below uses only the published ledger and the VRO's public key. No privileged access, and no election-specific cryptography — an ordinary RSA- PSS verify and an ordinary Ed25519 verify. The poll is closed first: ballot-by-ballot verification of eligibility and authentication needs the tokens and signatures themselves, which are released only at the close.


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
| `final ledger head` | `5c2cca0667bfffc15d0a5c4c16e3866b69a71a65f63fe0b0703263ca204027d0` |


##  · SELF-CHECK

85 checks performed, 0 failed.

Every claim above was computed in this run, not asserted by the narration.
