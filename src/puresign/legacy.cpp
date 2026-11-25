// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file puresign/legacy.cpp
 * @brief The legacy Bulletproof backend of PureSign: its proof operations and wire formats.
 *
 * Everything that does not depend on the proof system lives in `core.cpp` and
 * `detail/core_impl.hpp`.
 */

#include "purify/puresign/legacy.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <limits>
#include <optional>

#include "bppp_public_commitments.hpp"
#include "bulletproof_internal.hpp"
#include "byte_io.hpp"
#include "checked_size.hpp"
#include "detail/core_impl.hpp"
#include "purify/bppp.hpp"
#include "purify/secp_bridge.h"

namespace purify::puresign {

using ::purify::detail::append_u32_le;
using ::purify::detail::read_u32_le;

struct Backend::Ops {
    static constexpr std::string_view kMessageProofTag = "PureSign/Proof/Message/V1";
    static constexpr std::string_view kTopicProofTag = "PureSign/Proof/Topic/V1";

    /** Proofs are produced, and cached verification runs, over the packed circuit form. */
    static Result<NativeBulletproofCircuit::PackedWithSlack> instantiate(
        const NativeBulletproofCircuitTemplate& circuit_template, const UInt512& purify_pubkey) {
        return circuit_template.instantiate_packed(purify_pubkey);
    }

    static constexpr std::string_view kExactPointTag = "PureSign/Proof/ExactNonce/V1";

    /**
     * The Fiat-Shamir context of the exact-point proof: the whole circuit statement and the
     * commitment the Bulletproof is about.
     */
    template <typename CircuitLike>
    static Result<Bytes> exact_point_context(const CircuitLike& circuit,
                                             std::span<const unsigned char> statement_binding,
                                             const bppp::PointBytes& commitment) {
        static const TaggedHash hash(kExactPointTag);
        PURIFY_ASSIGN_OR_RETURN(const auto& circuit_digest,
                                experimental_circuit_binding_digest(circuit, statement_binding));
        const auto digest = hash.digest_many<2>({circuit_digest, commitment});
        return Bytes(digest.begin(), digest.end());
    }

    /** True when the exact-point fields are canonical: an x-only point and a nonzero scalar. */
    static Result<bool> exact_point_encoding_valid(const NonceProof& nonce_proof,
                                                   purify_secp_context* secp_context) {
        PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
        if (purify_bip340_validate_xonly_pubkey(secp_context, nonce_proof.exact_point_nonce.data()) == 0) {
            return false;
        }
        const auto response = FieldElement::try_from_bytes32(nonce_proof.exact_point_response);
        return response.has_value() && !response->is_zero();
    }

    /**
     * Checks that the proof's single commitment is `v*G` for a known `v`.
     *
     * The Bulletproof accepts a commitment `o*G + b*H` for any blind `b`. Together with this
     * check `b` must be zero, so the commitment is the unique point `o*G`.
     */
    template <typename CircuitLike>
    static Result<bool> verify_exact_point(const CircuitLike& circuit, const NonceProof& nonce_proof,
                                           std::span<const unsigned char> statement_binding,
                                           purify_secp_context* secp_context) {
        if (nonce_proof.proof.commitments.size() != 1) {
            return unexpected_error(ErrorCode::SizeMismatch);
        }
        PURIFY_ASSIGN_OR_RETURN(const bool canonical, exact_point_encoding_valid(nonce_proof, secp_context));
        if (!canonical) {
            return false;
        }
        const std::span<const bppp::PointBytes> commitments(nonce_proof.proof.commitments);
        PURIFY_ASSIGN_OR_RETURN(const auto& context,
                                exact_point_context(circuit, statement_binding, commitments.front()));
        PURIFY_ASSIGN_OR_RETURN(const auto& batched,
                                bppp::detail::batch_public_commitments(commitments, context, secp_context));
        const bppp::detail::PublicCommitmentDlogProof dlog{nonce_proof.exact_point_nonce,
                                                           nonce_proof.exact_point_response};
        return bppp::detail::verify_public_commitment_dlog(batched, context, dlog, secp_context);
    }

    /** The nonce point is public, so the nonce scalar is committed with a zero blind. */
    static Result<NonceProof> prove(const NativeBulletproofCircuit::PackedWithSlack& circuit,
                                    const BulletproofAssignmentData& assignment, const Scalar32& prover_seed,
                                    const Nonce& nonce, std::span<const unsigned char> statement_binding,
                                    purify_secp_context* secp_context, CircuitCache* circuit_cache) {
        PURIFY_ASSIGN_OR_RETURN(auto proof,
                                prove_experimental_circuit_assume_valid(circuit, assignment, prover_seed,
                                                                        bppp::base_generator(secp_context),
                                                                        secp_context, statement_binding, {},
                                                                        circuit_cache));
        if (proof.commitments.size() != 1 || assignment.commitments.size() != 1) {
            return unexpected_error(ErrorCode::SizeMismatch);
        }
        const std::span<const bppp::PointBytes> commitments(proof.commitments);
        PURIFY_ASSIGN_OR_RETURN(const auto& context,
                                exact_point_context(circuit, statement_binding, commitments.front()));
        PURIFY_ASSIGN_OR_RETURN(const auto& batched,
                                bppp::detail::batch_public_commitments(commitments, context, secp_context));
        // The Schnorr nonce is derived from the prover seed, the committed scalar and this
        // context, so one statement always yields one nonce and one challenge.
        PURIFY_ASSIGN_OR_RETURN(const auto& dlog,
                                bppp::detail::prove_public_commitment_dlog(batched, assignment.commitments,
                                                                           context, prover_seed, secp_context));
        NonceProof out{nonce, std::move(proof), dlog.nonce_xonly, dlog.response};
        PURIFY_ASSIGN_OR_RETURN(const bool exact, verify_exact_point(circuit, out, statement_binding, secp_context));
        if (!exact) {
            return unexpected_error(ErrorCode::InternalMismatch);
        }
        return out;
    }

    /** `CircuitLike` is the packed form under a proof cache and the plain form otherwise. */
    template <typename CircuitLike>
    static Result<bool> verify(const CircuitLike& circuit, const NonceProof& nonce_proof,
                               std::span<const unsigned char> statement_binding,
                               purify_secp_context* secp_context, CircuitCache* circuit_cache) {
        PURIFY_ASSIGN_OR_RETURN(const bool exact,
                                verify_exact_point(circuit, nonce_proof, statement_binding, secp_context));
        if (!exact) {
            return false;
        }
        return verify_experimental_circuit(circuit, nonce_proof.proof, bppp::base_generator(secp_context),
                                           secp_context, statement_binding, circuit_cache);
    }

    /** The proof's single commitment is the nonce point. */
    static Result<bool> matches_nonce(const NonceProof& nonce_proof, purify_secp_context* secp_context) {
        PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
        if (nonce_proof.proof.commitments.size() != 1) {
            return unexpected_error(ErrorCode::SizeMismatch);
        }
        return puresign_core::detail::nonce_matches_point(nonce_proof.nonce, nonce_proof.proof.commitments.front(),
                                                          secp_context);
    }
};

namespace {

// Version 3 added the exact-point proof. Version 2 proofs carried only the Bulletproof and
// are rejected: they do not pin a unique nonce.
constexpr unsigned char kNonceProofVersion = 3;
// version || u32 proof size || nonce x || exact-point nonce x || exact-point response
constexpr std::size_t kNonceProofHeaderSize = 1 + 4 + 32 + 32 + 32;

}  // namespace

Result<Bytes> NonceProof::serialize(purify_secp_context* secp_context) const {
    PURIFY_ASSIGN_OR_RETURN(auto match, Backend::Ops::matches_nonce(*this, secp_context));
    if (!match) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    PURIFY_ASSIGN_OR_RETURN(const bool canonical, Backend::Ops::exact_point_encoding_valid(*this, secp_context));
    if (!canonical) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    PURIFY_ASSIGN_OR_RETURN(const auto& proof_bytes, proof.serialize());
    if (proof_bytes.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        return unexpected_error(ErrorCode::UnexpectedSize);
    }
    std::size_t serialized_size = 0;
    if (!(::purify::detail::CheckedSize(kNonceProofHeaderSize) + proof_bytes.size()).store(serialized_size)) {
        return unexpected_error(ErrorCode::Overflow);
    }

    Bytes out;
    out.reserve(serialized_size);
    out.push_back(kNonceProofVersion);
    append_u32_le(out, static_cast<std::uint32_t>(proof_bytes.size()));
    out.insert(out.end(), nonce.xonly.begin(), nonce.xonly.end());
    out.insert(out.end(), exact_point_nonce.begin(), exact_point_nonce.end());
    out.insert(out.end(), exact_point_response.begin(), exact_point_response.end());
    out.insert(out.end(), proof_bytes.begin(), proof_bytes.end());
    return out;
}

Result<NonceProof> NonceProof::deserialize(std::span<const unsigned char> serialized,
                                           purify_secp_context* secp_context) {
    if (serialized.size() < kNonceProofHeaderSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    if (serialized[0] != kNonceProofVersion) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    std::optional<std::uint32_t> proof_size = read_u32_le(serialized, 1);
    assert(proof_size.has_value() && "header length check should guarantee a u32 proof size");
    if (*proof_size != serialized.size() - kNonceProofHeaderSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }

    NonceProof out{};
    std::copy_n(serialized.begin() + 5, 32, out.nonce.xonly.begin());
    std::copy_n(serialized.begin() + 37, 32, out.exact_point_nonce.begin());
    std::copy_n(serialized.begin() + 69, 32, out.exact_point_response.begin());
    PURIFY_ASSIGN_OR_RETURN(const bool canonical, Backend::Ops::exact_point_encoding_valid(out, secp_context));
    if (!canonical) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto proof_value,
        ExperimentalBulletproofProof::deserialize(serialized.subspan(kNonceProofHeaderSize, *proof_size)));
    out.proof = std::move(proof_value);
    PURIFY_ASSIGN_OR_RETURN(auto match, Backend::Ops::matches_nonce(out, secp_context));
    if (!match) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    return out;
}

Result<Bytes> ProvenSignature::serialize(purify_secp_context* secp_context) const {
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_proof_bytes, nonce_proof.serialize(secp_context));
    if (nonce_proof_bytes.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        return unexpected_error(ErrorCode::UnexpectedSize);
    }
    std::size_t serialized_size = 0;
    if (!(::purify::detail::CheckedSize(69) + nonce_proof_bytes.size()).store(serialized_size)) {
        return unexpected_error(ErrorCode::Overflow);
    }

    Bytes out;
    out.reserve(serialized_size);
    out.push_back(static_cast<unsigned char>(1));
    append_u32_le(out, static_cast<std::uint32_t>(nonce_proof_bytes.size()));
    out.insert(out.end(), nonce_proof_bytes.begin(), nonce_proof_bytes.end());
    out.insert(out.end(), signature.bytes.begin(), signature.bytes.end());
    return out;
}

Result<ProvenSignature> ProvenSignature::deserialize(std::span<const unsigned char> serialized,
                                                     purify_secp_context* secp_context) {
    if (serialized.size() < 69) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    if (serialized[0] != 1) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    std::optional<std::uint32_t> nonce_proof_size = read_u32_le(serialized, 1);
    assert(nonce_proof_size.has_value() && "header length check should guarantee a u32 nonce proof size");
    const std::size_t payload_size = serialized.size() - 5;
    if (*nonce_proof_size > payload_size || payload_size - *nonce_proof_size != 64) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }

    PURIFY_ASSIGN_OR_RETURN(auto nonce_proof_value,
                            NonceProof::deserialize(serialized.subspan(5, *nonce_proof_size), secp_context));
    PURIFY_ASSIGN_OR_RETURN(auto signature_value,
                            Signature::deserialize(serialized.subspan(5 + *nonce_proof_size, 64), secp_context));
    return ProvenSignature{signature_value, nonce_proof_value};
}

}  // namespace purify::puresign

namespace purify::puresign_core {

template struct PublicKey<puresign::Backend>;
template struct MessageProofCache<puresign::Backend>;
template struct TopicProofCache<puresign::Backend>;
template class PreparedNonceWithProof<puresign::Backend>;
template class KeyPair<puresign::Backend>;

}  // namespace purify::puresign_core
