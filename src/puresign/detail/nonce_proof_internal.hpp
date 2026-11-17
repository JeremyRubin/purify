// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include "purify/puresign/bppp.hpp"

#include "../../protocol/algebraic_circuit_proof.hpp"

#include <utility>

namespace purify::puresign_plusplus::nonce_proof_detail {

/** Internal bridge between the public nonce-proof type and its backend. */
struct Access {
    [[nodiscard]] static NonceProof create(
        Nonce nonce, bppp::PointBytes full_nonce_point,
        bppp::candidate::CircuitZkNormArgProofV4 proof)
    {
        NonceProof out;
        out.nonce_ = nonce;
        out.full_nonce_point_ = full_nonce_point;
        out.raw_commitment_ = proof.raw_commitment;
        out.mask_commitment_ = proof.mask_commitment;
        out.t2_ = proof.t2;
        out.public_commitment_dlog_nonce_ =
            proof.public_commitment_dlog_nonce;
        out.public_commitment_dlog_response_ =
            proof.public_commitment_dlog_response;
        out.norm_proof_ = std::move(proof.norm_proof);
        return out;
    }

    [[nodiscard]] static bppp::candidate::CircuitZkNormArgProofV4 proof(
        const NonceProof& nonce_proof)
    {
        return {
            nonce_proof.raw_commitment_,
            nonce_proof.mask_commitment_,
            nonce_proof.t2_,
            nonce_proof.public_commitment_dlog_nonce_,
            nonce_proof.public_commitment_dlog_response_,
            nonce_proof.norm_proof_,
        };
    }
};

}  // namespace purify::puresign_plusplus::nonce_proof_detail
