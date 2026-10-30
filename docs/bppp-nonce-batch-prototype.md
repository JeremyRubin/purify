# Experimental BP++ nonce batches

The batch prototype combines ordered `NonceBatchGroup` statements into one
experimental BP++ artifact. A group with one host represents one independent
Purify statement; the corresponding public output point occupies the same
position in the artifact. The prover supplies every member's assignment.
This is a centralized integration prototype, not a distributed prover or a
production proof system.

The caller must supply fresh, unique prover randomness for each proof. Each
output must be representable as a finite compressed point; an output at
infinity is rejected. The versioned frame contains output points and proof
data, but not the groups or application binding. The verifier must obtain
those public inputs separately in their intended order.

For example, after constructing `groups` and matching `assignments`:

```cpp
#include <purify/nonce_batch.hpp>

purify::Result<bool> prove_and_verify_for_integration(
    std::span<const purify::NonceBatchGroup> groups,
    std::span<const std::vector<purify::BulletproofAssignmentData>> assignments,
    const purify::bppp::ScalarBytes& fresh_nonce,
    purify_secp_context* context,
    std::span<const unsigned char> binding) {
    PURIFY_ASSIGN_OR_RETURN(auto artifact,
        purify::prove_experimental_nonce_batch_bppp(
            groups, assignments, fresh_nonce, context, binding), "prove");
    PURIFY_ASSIGN_OR_RETURN(auto frame, artifact.serialize(), "serialize");

    // The frame may be transported to a verifier with the public groups and
    // application binding supplied through the surrounding protocol.
    PURIFY_ASSIGN_OR_RETURN(auto parsed,
        purify::ExperimentalNonceBatchBpppProof::deserialize(frame), "parse");
    return purify::verify_experimental_nonce_batch_bppp(
        groups, parsed, context, binding);
}
```

The v1 format allows up to 4,096 output points and 65,536 inner proof bytes.
The parser enforces these bounds and rejects truncated or trailing bytes.
