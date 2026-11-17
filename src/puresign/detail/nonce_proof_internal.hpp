// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include "purify/puresign/bppp.hpp"

#include <utility>

namespace purify::puresign_plusplus::nonce_proof_detail {

/** Internal bridge between the public nonce-proof type and its backend. */
struct Access {
    [[nodiscard]] static NonceProof create(
        Nonce nonce, bppp::PointBytes full_nonce_point,
        bppp::ExperimentalCircuitZkNormArgProof proof)
    {
        NonceProof out;
        out.nonce_ = nonce;
        out.full_nonce_point_ = full_nonce_point;
        out.proof_ = std::move(proof);
        return out;
    }

    [[nodiscard]] static const bppp::ExperimentalCircuitZkNormArgProof&
    proof(const NonceProof& nonce_proof)
    {
        return nonce_proof.proof_;
    }
};

}  // namespace purify::puresign_plusplus::nonce_proof_detail
