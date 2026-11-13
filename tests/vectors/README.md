# Construction parent qualification vectors

The mixed distributed construction-parent qualification pins four vectors:

- `construction_parent_sha256_accepted.wit3` is the deterministic public
  witness for an accepted two-anchor construction;
- `construction_parent_sha256_nondeciding.wit3` has identical public inputs
  and a distinct final root that is recursively valid but fails native
  accumulation decision;
- `construction_parent_sha256_accepted.proof` is the matching accepted Nova
  proof; and
- `construction_parent_sha256_nondeciding.proof` is the matching recursive
  proof for the nondeciding root.

Both Wit3 fixtures are 17,977 bytes and both proofs are 15,076 bytes. Normal
C++ tests regenerate and byte-compare the Wit3 fixtures. Rust tests parse the
same checked bytes. The artifact-backed release gate verifies both proofs and
requires the nondeciding proof to fail only at the native decision boundary.

| Vector | SHA256 |
| --- | --- |
| Accepted Wit3 | `b39168a9e4fb6a5a893a9a4a9479ff55abe4fa3b50708a8c874a08bcd0bbe9f5` |
| Nondeciding Wit3 | `46a89f4401eb0d34325912ad59c12ac5f9e54d4a57f2ac810ddba6af647d2db7` |
| Accepted proof | `74b66a779134a39560185472708d94e9a1532240f7fcf9c66a88d91728e8d779` |
| Nondeciding proof | `a869016dea8d439f579b8c7be6c3613bc3e5f5e9f18f6177ee27c6050038b072` |

The 693,708,278-byte VK2 verifier artifact and 693,582,375-byte PK1 prover
artifact remain external. Their authenticated identities and all vector
hashes are recorded in
[`release/construction-parent-sha256.json`](../../release/construction-parent-sha256.json).

Full vector requalification is an explicit native-resource release operation.
Every output path must not exist before running:

```sh
cd rust/construction-parent
PURIFY_CONSTRUCTION_PARENT_PROVER_FIXTURE=/path/to/accepted.wit3 \
PURIFY_CONSTRUCTION_PARENT_NONDECIDING_PROVER_FIXTURE=/path/to/nondeciding.wit3 \
PURIFY_CONSTRUCTION_PARENT_PROOF_OUT=/new/path/accepted.proof \
PURIFY_CONSTRUCTION_PARENT_NONDECIDING_PROOF_OUT=/new/path/nondeciding.proof \
PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT_OUT=/new/path/sha256-parent-verifier.nvk.zst \
cargo test --release \
  native_profile_sha_parent_qualification_is_exact -- --ignored --nocapture
```

Select and persist reusable prover state with the frozen accepted Wit3 and an
independently selected VK2:

```sh
cd rust/construction-parent
PURIFY_CONSTRUCTION_PARENT_PROVER_FIXTURE=/path/to/accepted.wit3 \
PURIFY_CONSTRUCTION_PARENT_PROVER_ARTIFACT_OUT=/new/path/sha256-parent-prover.pk1.zst \
PURIFY_CONSTRUCTION_PARENT_FRESH_PROOF_OUT=/new/path/fresh-accepted.proof \
PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT=/path/to/sha256-parent-verifier.nvk.zst \
cargo test --release \
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
checked accepted Wit3, and does not change the compiled qualified proof used
by normal tests. A missing override retains the frozen vector path.
