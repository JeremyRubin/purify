// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <span>
#include <vector>

#include "purify/bulletproof.hpp"
#include "purify/bppp.hpp"

namespace purify {

/**
 * @brief One ordered coalition/topic relation with its own summed nonce output.
 *
 * evaluation_input is the exact existing Purify input, not a batch-dependent
 * derivation. Hosts must be distinct within a group; a host may occur in other
 * groups. Application coalition identities and signing-slot labels must be
 * authenticated by the caller alongside these public inputs.
 */
struct NonceBatchGroup {
    Bytes evaluation_input;
    std::vector<UInt512> hosts;
};

/**
 * @brief Builds a public verifier circuit with one output commitment per group.
 *
 * Group and host order are retained. Each group uses the existing summed-host
 * relation, including its padding; the combined circuit is padded once more
 * to a power of two. To combine independent statements, supply one host per
 * group; each statement retains its own output in group order. No witnesses
 * or completed proofs are needed here.
 * This builds a relation, not a public compression of completed group proofs.
 */
Result<NativeBulletproofCircuit> nonce_batch_circuit(
    std::span<const NonceBatchGroup> groups);

/**
 * @brief Validates and combines member assignments for nonce_batch_circuit.
 *
 * assignments[g][i] belongs to groups[g].hosts[i] for that group's exact
 * evaluation input. The caller receives all private witnesses and summed
 * output scalars; this is a centralized prover helper, not an MPC interface
 * or an operation for a public certificate assembler.
 */
Result<BulletproofAssignmentData> nonce_batch_assignments(
    std::span<const NonceBatchGroup> groups,
    std::span<const std::vector<BulletproofAssignmentData>> assignments);

/**
 * @brief Experimental BP++ batch artifact with ordered public outputs.
 *
 * This prototype uses the existing experimental BP++ circuit wrapper and
 * is intended for integration testing only. It is not a production proof
 * system. The application supplies the ordered groups separately.
 *
 * The v1 frame contains a version byte, little-endian 32-bit output count
 * and inner proof size, the ordered 33-byte outputs, two 33-byte outer
 * commitments, a 32-byte scalar, and the inner proof. Parsing checks the
 * frame size; point and scalar validation occurs during verification.
 */
struct ExperimentalNonceBatchBpppProof {
    static constexpr unsigned char kSerializationVersion = 1;
    static constexpr std::size_t kMaxOutputs = 4096;
    static constexpr std::size_t kMaxProofBytes = 65536;

    std::vector<bppp::PointBytes> outputs;
    bppp::ExperimentalCircuitZkNormArgProof proof;

    Result<Bytes> serialize() const;
    static Result<ExperimentalNonceBatchBpppProof> deserialize(std::span<const unsigned char> bytes);
};

/**
 * @brief Centrally build one experimental BP++ proof for the ordered groups.
 *
 * The caller supplies every member's witness assignment. Each output is
 * represented by its compressed secp256k1 point in group order.
 */
Result<ExperimentalNonceBatchBpppProof> prove_experimental_nonce_batch_bppp(
    std::span<const NonceBatchGroup> groups,
    std::span<const std::vector<BulletproofAssignmentData>> assignments,
    const bppp::ScalarBytes& nonce, purify_secp_context* secp_context,
    std::span<const unsigned char> statement_binding = {},
    bppp::ExperimentalCircuitBackend* cache = nullptr);

/** @brief Verify an experimental BP++ batch artifact using only public groups. */
Result<bool> verify_experimental_nonce_batch_bppp(
    std::span<const NonceBatchGroup> groups,
    const ExperimentalNonceBatchBpppProof& proof,
    purify_secp_context* secp_context,
    std::span<const unsigned char> statement_binding = {},
    bppp::ExperimentalCircuitBackend* cache = nullptr);

} // namespace purify
