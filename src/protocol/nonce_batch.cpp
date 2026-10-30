// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/nonce_batch.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <utility>

namespace purify {
namespace {

Result<std::size_t> checked_sum(std::size_t lhs, std::size_t rhs) {
    if (rhs > std::numeric_limits<std::size_t>::max() - lhs) {
        return unexpected_error(ErrorCode::Overflow, "nonce_batch:dimension_sum");
    }
    return lhs + rhs;
}

Result<std::size_t> padded_gates(std::size_t gates) {
    constexpr std::size_t max_power =
        std::size_t{1} << (std::numeric_limits<std::size_t>::digits - 1);
    if (gates == 0 || gates > max_power) {
        return unexpected_error(ErrorCode::Overflow, "nonce_batch:padded_gates");
    }
    return std::bit_ceil(gates);
}

void append_rows(std::vector<NativeBulletproofCircuitRow>& destination,
                 std::vector<NativeBulletproofCircuitRow>& source,
                 std::size_t constraint_offset) {
    for (auto& row : source) {
        for (auto& term : row.entries) {
            term.idx += constraint_offset;
        }
        destination.push_back(std::move(row));
    }
}

} // namespace

Result<NativeBulletproofCircuit> nonce_batch_circuit(
    std::span<const NonceBatchGroup> groups) {
    if (groups.empty()) {
        return unexpected_error(ErrorCode::InvalidDimensions, "nonce_batch_circuit:empty");
    }

    NativeBulletproofCircuit result(0, groups.size(), 0);
    std::size_t group_index = 0;
    for (const auto& group : groups) {
        PURIFY_ASSIGN_OR_RETURN(auto circuit_template, verifier_circuit_template(group.evaluation_input),
                                "nonce_batch_circuit:template");
        PURIFY_ASSIGN_OR_RETURN(auto circuit, circuit_template.instantiate_sum(group.hosts),
                                "nonce_batch_circuit:group");
        PURIFY_ASSIGN_OR_RETURN(const auto next_gates, checked_sum(result.n_gates, circuit.n_gates),
                                "nonce_batch_circuit:gates");
        PURIFY_RETURN_IF_ERROR(checked_sum(result.c.size(), circuit.c.size()),
                               "nonce_batch_circuit:constraints");
        const std::size_t constraint_offset = result.c.size();
        result.c.insert(result.c.end(), circuit.c.begin(), circuit.c.end());
        append_rows(result.wl, circuit.wl, constraint_offset);
        append_rows(result.wr, circuit.wr, constraint_offset);
        append_rows(result.wo, circuit.wo, constraint_offset);
        for (const auto& term : circuit.wv[0].entries) {
            result.wv[group_index].add(constraint_offset + term.idx, term.scalar);
        }
        result.n_gates = next_gates;
        ++group_index;
    }

    PURIFY_ASSIGN_OR_RETURN(const auto gates, padded_gates(result.n_gates),
                            "nonce_batch_circuit:padding");
    result.n_gates = gates;
    result.wl.resize(gates);
    result.wr.resize(gates);
    result.wo.resize(gates);
    return result;
}

Result<BulletproofAssignmentData> nonce_batch_assignments(
    std::span<const NonceBatchGroup> groups,
    std::span<const std::vector<BulletproofAssignmentData>> assignments) {
    if (groups.empty()) {
        return unexpected_error(ErrorCode::InvalidDimensions, "nonce_batch_assignments:empty");
    }
    if (groups.size() != assignments.size()) {
        return unexpected_error(ErrorCode::SizeMismatch, "nonce_batch_assignments:groups");
    }

    BulletproofAssignmentData result;
    result.commitments.reserve(groups.size());
    for (std::size_t group_index = 0; group_index < groups.size(); ++group_index) {
        const auto& group = groups[group_index];
        PURIFY_ASSIGN_OR_RETURN(auto circuit_template, verifier_circuit_template(group.evaluation_input),
                                "nonce_batch_assignments:template");
        PURIFY_ASSIGN_OR_RETURN(auto assignment,
                                circuit_template.sum_assignments(group.hosts, assignments[group_index]),
                                "nonce_batch_assignments:group");
        PURIFY_RETURN_IF_ERROR(checked_sum(result.left.size(), assignment.left.size()),
                               "nonce_batch_assignments:gates");
        result.left.insert(result.left.end(), assignment.left.begin(), assignment.left.end());
        result.right.insert(result.right.end(), assignment.right.begin(), assignment.right.end());
        result.output.insert(result.output.end(), assignment.output.begin(), assignment.output.end());
        result.commitments.push_back(assignment.commitments[0]);
    }

    PURIFY_ASSIGN_OR_RETURN(const auto gates, padded_gates(result.left.size()),
                            "nonce_batch_assignments:padding");
    result.left.resize(gates, FieldElement::zero());
    result.right.resize(gates, FieldElement::zero());
    result.output.resize(gates, FieldElement::zero());
    return result;
}

Result<Bytes> ExperimentalNonceBatchBpppProof::serialize() const {
    if (outputs.empty() || outputs.size() > kMaxOutputs ||
        proof.proof.empty() || proof.proof.size() > kMaxProofBytes) {
        return unexpected_error(ErrorCode::UnexpectedSize, "nonce_batch_bppp:serialize_size");
    }
    Bytes out;
    out.reserve(9 + outputs.size() * 33 + 98 + proof.proof.size());
    out.push_back(kSerializationVersion);
    const auto append_u32 = [&out](std::uint32_t value) {
        for (unsigned int i = 0; i < 4; ++i) out.push_back(static_cast<unsigned char>(value >> (8 * i)));
    };
    append_u32(static_cast<std::uint32_t>(outputs.size()));
    append_u32(static_cast<std::uint32_t>(proof.proof.size()));
    for (const auto& point : outputs) out.insert(out.end(), point.begin(), point.end());
    out.insert(out.end(), proof.a_commitment.begin(), proof.a_commitment.end());
    out.insert(out.end(), proof.s_commitment.begin(), proof.s_commitment.end());
    out.insert(out.end(), proof.t2.begin(), proof.t2.end());
    out.insert(out.end(), proof.proof.begin(), proof.proof.end());
    return out;
}

Result<ExperimentalNonceBatchBpppProof> ExperimentalNonceBatchBpppProof::deserialize(
    std::span<const unsigned char> bytes) {
    constexpr std::size_t header_size = 9;
    constexpr std::size_t outer_size = 33 + 33 + 32;
    if (bytes.size() < header_size || bytes[0] != kSerializationVersion) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "nonce_batch_bppp:header");
    }
    const auto read_u32 = [&bytes](std::size_t offset) {
        std::uint32_t value = 0;
        for (unsigned int i = 0; i < 4; ++i) value |= std::uint32_t{bytes[offset + i]} << (8 * i);
        return value;
    };
    const std::size_t count = read_u32(1);
    const std::size_t proof_size = read_u32(5);
    if (count == 0 || count > kMaxOutputs || proof_size == 0 || proof_size > kMaxProofBytes ||
        bytes.size() != header_size + count * 33 + outer_size + proof_size) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "nonce_batch_bppp:frame_size");
    }
    ExperimentalNonceBatchBpppProof out;
    out.outputs.resize(count);
    std::size_t offset = header_size;
    for (auto& point : out.outputs) {
        std::copy_n(bytes.begin() + offset, point.size(), point.begin());
        offset += point.size();
    }
    std::copy_n(bytes.begin() + offset, out.proof.a_commitment.size(), out.proof.a_commitment.begin());
    offset += out.proof.a_commitment.size();
    std::copy_n(bytes.begin() + offset, out.proof.s_commitment.size(), out.proof.s_commitment.begin());
    offset += out.proof.s_commitment.size();
    std::copy_n(bytes.begin() + offset, out.proof.t2.size(), out.proof.t2.begin());
    offset += out.proof.t2.size();
    out.proof.proof.assign(bytes.begin() + offset, bytes.end());
    return out;
}

Result<ExperimentalNonceBatchBpppProof> prove_experimental_nonce_batch_bppp(
    std::span<const NonceBatchGroup> groups,
    std::span<const std::vector<BulletproofAssignmentData>> assignments,
    const bppp::ScalarBytes& nonce, purify_secp_context* secp_context,
    std::span<const unsigned char> statement_binding, bppp::ExperimentalCircuitBackend* cache) {
    if (groups.empty() || groups.size() > ExperimentalNonceBatchBpppProof::kMaxOutputs) {
        return unexpected_error(ErrorCode::InvalidDimensions, "nonce_batch_bppp:groups");
    }
    if (groups.size() != assignments.size()) {
        return unexpected_error(ErrorCode::SizeMismatch, "nonce_batch_bppp:assignments");
    }
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "nonce_batch_bppp:context"),
                           "nonce_batch_bppp:context");
    PURIFY_ASSIGN_OR_RETURN(auto circuit, nonce_batch_circuit(groups), "nonce_batch_bppp:circuit");
    PURIFY_ASSIGN_OR_RETURN(auto assignment, nonce_batch_assignments(groups, assignments), "nonce_batch_bppp:assignment");
    ExperimentalNonceBatchBpppProof out;
    out.outputs.reserve(assignment.commitments.size());
    const auto generator = bppp::base_generator(secp_context);
    const bppp::ScalarBytes zero{};
    for (const auto& value : assignment.commitments) {
        PURIFY_ASSIGN_OR_RETURN(auto point,
            bppp::pedersen_commit_char(zero, bppp::scalar_bytes(value), secp_context, generator, generator),
            "nonce_batch_bppp:output");
        out.outputs.push_back(point);
    }
    PURIFY_ASSIGN_OR_RETURN(out.proof,
        bppp::prove_experimental_circuit_zk_norm_arg_with_public_commitments(
            circuit, assignment, nonce, out.outputs, secp_context, statement_binding, cache),
        "nonce_batch_bppp:prove");
    if (out.proof.proof.size() > ExperimentalNonceBatchBpppProof::kMaxProofBytes) {
        return unexpected_error(ErrorCode::UnexpectedSize, "nonce_batch_bppp:proof_size");
    }
    return out;
}

Result<bool> verify_experimental_nonce_batch_bppp(
    std::span<const NonceBatchGroup> groups, const ExperimentalNonceBatchBpppProof& proof,
    purify_secp_context* secp_context, std::span<const unsigned char> statement_binding,
    bppp::ExperimentalCircuitBackend* cache) {
    if (groups.empty() || groups.size() > ExperimentalNonceBatchBpppProof::kMaxOutputs ||
        proof.outputs.size() != groups.size() || proof.proof.proof.empty() ||
        proof.proof.proof.size() > ExperimentalNonceBatchBpppProof::kMaxProofBytes) {
        return unexpected_error(ErrorCode::InvalidDimensions, "nonce_batch_bppp:proof_shape");
    }
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "nonce_batch_bppp:context"),
                           "nonce_batch_bppp:context");
    PURIFY_ASSIGN_OR_RETURN(auto circuit, nonce_batch_circuit(groups), "nonce_batch_bppp:circuit");
    return bppp::verify_experimental_circuit_zk_norm_arg_with_public_commitments(
        circuit, proof.proof, proof.outputs, secp_context, statement_binding, cache);
}

} // namespace purify
