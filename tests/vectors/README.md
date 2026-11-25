# Construction parent qualification vectors

The mixed distributed construction-parent qualification pins four vectors:

- `construction_parent_sha256_accepted.wit4` is the deterministic public
  witness for an accepted two-anchor construction;
- `construction_parent_sha256_nondeciding.wit4` has identical public inputs
  and a distinct final root that is recursively valid but fails native
  accumulation decision;
- `construction_parent_sha256_accepted.proof` is the matching accepted Nova
  proof; and
- `construction_parent_sha256_nondeciding.proof` is the matching recursive
  proof for the nondeciding root.

Both Wit4 fixtures are 17,587 bytes and both proofs are 15,076 bytes. Normal
C++ tests regenerate and byte-compare the Wit4 fixtures. Rust tests parse the
same checked bytes. The artifact-backed release gate verifies both proofs and
requires the nondeciding proof to fail only at the native decision boundary.

The qualified fixture contains three setup leaves and two anchor leaves, for
five recursive steps. The prover CLI bounds Wit4 to 200 total leaves and a
676,297-byte frame. Char Formation V3 separately caps setup and anchor entries
at 100 each before this boundary. This qualification does not claim a
200-step performance measurement.

Reusable setup was qualified from the tagged predecessor's strict Wit3
fixture. Production accepts Wit4 only. Wit4 removes the already
descriptor-and-statement-bound 66-byte setup prefix and 96-byte anchor prefix
from each record. Exact projection checks covered descriptors, public points,
transcript inputs, proof reductions, ordered steps, and final roots. The Nova
relation, PK1, VK2, and 15,076-byte proof format are unchanged.

| Vector | SHA256 |
| --- | --- |
| Accepted Wit4 | `22584834f5ddb7763d05bdc631a117bed313eba1d9478a72db8f898774aec507` |
| Nondeciding Wit4 | `cba7ab049fd92e36579bbe74d0c2963bacd8879991321fc3071303a92e90f10f` |
| Accepted proof | `dc507ce5580d85a58fd5ec7694b5942b57a35338d1c67fa91571d7f95c80835d` |
| Nondeciding proof | `fe47397b2f939ab62f24436767f6bf8568b44d8b932935cd568f882d6efd9b96` |

The two Wit4 fixtures were regenerated for construction payload version 5,
which carries each child proof's raw commitment instead of its precommitment.
They differ from the payload-version-4 fixtures only in bytes 16 through 47,
the construction statement digest: every descriptor, public point, proof
transcript, reduction, step and final root is unchanged. The relation, PK1 and
VK2 are unchanged as well.

Both checked proofs were regenerated for these Wit4 fixtures with the prover
CLI and the unchanged PK1, one fixture per run. The CLI verified each proof
against the unchanged VK2 before writing it, and both pass the artifact-backed
release gate: the accepted proof is accepted, and the nondeciding proof fails
only at the native decision boundary. The timing and memory figures below
describe the original release gate, not these two runs.

The 693,708,278-byte VK2 verifier artifact and 693,582,375-byte PK1 prover
artifact remain external. Their authenticated identities and all vector
hashes are recorded in
[`release/construction-parent-sha256.json`](../../release/construction-parent-sha256.json).

The final gate produced distinct randomized setup and installed-CLI proofs.
Both passed recursive verification, exact-state checking, the C++ receipt
boundary, and native accumulation decision. The installed CLI completed in
6,749.73 seconds with 4,722,769,920-byte maximum RSS and an
8,447,794,208-byte peak footprint. Setup completed successfully, but the
sandbox denied its extended `/usr/bin/time -l` metrics after the test passed;
the manifest therefore records setup memory as unavailable rather than zero.

Full vector requalification is an explicit native-resource release operation.
Every output path must not exist before running:

```sh
cd rust/construction-parent
PURIFY_CONSTRUCTION_PARENT_PROVER_FIXTURE=/path/to/accepted.wit4 \
PURIFY_CONSTRUCTION_PARENT_NONDECIDING_PROVER_FIXTURE=/path/to/nondeciding.wit4 \
PURIFY_CONSTRUCTION_PARENT_PROOF_OUT=/new/path/accepted.proof \
PURIFY_CONSTRUCTION_PARENT_NONDECIDING_PROOF_OUT=/new/path/nondeciding.proof \
PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT_OUT=/new/path/sha256-parent-verifier.nvk.zst \
cargo test --release --package purify-construction-prover \
  native_profile_sha_parent_qualification_is_exact -- --ignored --nocapture
```

Select and persist reusable prover state with the frozen accepted Wit4 and an
independently selected VK2:

```sh
cd rust/construction-parent
PURIFY_CONSTRUCTION_PARENT_PROVER_FIXTURE=/path/to/accepted.wit4 \
PURIFY_CONSTRUCTION_PARENT_PROVER_ARTIFACT_OUT=/new/path/sha256-parent-prover.pk1.zst \
PURIFY_CONSTRUCTION_PARENT_FRESH_PROOF_OUT=/new/path/fresh-accepted.proof \
PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT=/path/to/sha256-parent-verifier.nvk.zst \
cargo test --release --package purify-construction-prover \
  setup_only_qualification_persists_a_usable_prover -- --ignored --nocapture
```

That test authenticates the reloaded PK1, consumes it to produce one fresh
proof, independently reloads VK2, and verifies the exact recursive final
state. It does not accept the construction receipt. Pass the fresh proof
through the same C++ verifier and native accumulation decision used by the
release gate:

```sh
PURIFY_CONSTRUCTION_PARENT_QUALIFICATION_PROOF=/path/to/fresh-accepted.proof \
ctest --test-dir build-parent --output-on-failure \
  -R '^purify.tests.slashability_e2e$'
```

The override is test-only, must name an exact 15,076-byte proof for the
checked accepted Wit4, and does not change the compiled qualified proof used
by normal tests. A missing override retains the frozen vector path.
