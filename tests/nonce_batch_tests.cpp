// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <bit>
#include <vector>

#include "purify.hpp"
#include "purify/nonce_batch.hpp"
#include "purify_test_helpers.hpp"

namespace {

using purify_test::TestContext;
using purify_test::expect_error;
using purify_test::expect_ok;

struct BatchFixture {
    std::vector<purify::NonceBatchGroup> groups;
    std::vector<std::vector<purify::BulletproofAssignmentData>> assignments;
    std::vector<purify::FieldElement> totals;
};

bool prepare_batch(TestContext& ctx, BatchFixture& fixture) {
    // Two coalitions share one member; both evaluate two distinct topics.
    const std::array<std::array<unsigned char, 2>, 2> rosters{{{0, 1}, {1, 2}}};
    for (const auto& roster : rosters) {
        for (unsigned char topic = 0; topic < 2; ++topic) {
            purify::NonceBatchGroup group{purify::Bytes{0xb4, topic}, {}};
            std::vector<purify::BulletproofAssignmentData> assignments;
            auto total = purify::FieldElement::zero();
            for (const auto member : roster) {
                std::array<unsigned char, 32> seed{};
                seed[0] = 0xb3;
                seed[31] = member;
                auto key = purify::generate_key(std::span<const unsigned char>{seed});
                expect_ok(ctx, key, "batch member key generates");
                if (!key.has_value()) return false;
                auto witness = purify::prove_assignment_data(group.evaluation_input, key->secret);
                expect_ok(ctx, witness, "batch member witness builds locally");
                if (!witness.has_value()) return false;
                group.hosts.push_back(witness->public_key);
                total = total + witness->output;
                assignments.push_back(std::move(witness->assignment));
            }
            fixture.groups.push_back(std::move(group));
            fixture.assignments.push_back(std::move(assignments));
            fixture.totals.push_back(total);
        }
    }
    return true;
}

void test_batch_relation(TestContext& ctx) {
    BatchFixture fixture;
    if (!prepare_batch(ctx, fixture)) return;
    auto circuit = purify::nonce_batch_circuit(fixture.groups);
    auto assignment = purify::nonce_batch_assignments(fixture.groups, fixture.assignments);
    expect_ok(ctx, circuit, "multi-topic multi-coalition public circuit builds");
    expect_ok(ctx, assignment, "centralized batch witnesses compose");
    if (!circuit.has_value() || !assignment.has_value()) return;

    ctx.expect(circuit->n_commitments == fixture.groups.size(),
               "each coalition/topic retains a distinct output commitment");
    ctx.expect(assignment->commitments == fixture.totals,
               "each batch output equals only its own coalition/topic sum");
    ctx.expect(circuit->evaluate(*assignment), "multi-topic multi-coalition witness satisfies relation");

    // A singleton host in each group represents independent statements rather
    // than a sum of several hosts under one statement.
    std::array<purify::NonceBatchGroup, 2> individual_groups{{
        {fixture.groups[0].evaluation_input, {fixture.groups[0].hosts[0]}},
        {fixture.groups[1].evaluation_input, {fixture.groups[1].hosts[1]}},
    }};
    std::array<std::vector<purify::BulletproofAssignmentData>, 2> individual_assignments{{
        {fixture.assignments[0][0]},
        {fixture.assignments[1][1]},
    }};
    auto individual_circuit = purify::nonce_batch_circuit(individual_groups);
    auto individual_assignment = purify::nonce_batch_assignments(individual_groups, individual_assignments);
    expect_ok(ctx, individual_circuit, "independent-statement circuit builds");
    expect_ok(ctx, individual_assignment, "independent-statement witnesses compose");
    if (individual_circuit.has_value() && individual_assignment.has_value()) {
        const std::vector<purify::FieldElement> expected_outputs{
            fixture.assignments[0][0].commitments[0],
            fixture.assignments[1][1].commitments[0],
        };
        ctx.expect(individual_circuit->n_commitments == individual_groups.size(),
                   "independent statements retain one output each");
        ctx.expect(individual_assignment->commitments == expected_outputs,
                   "independent outputs retain statement order");
        ctx.expect(individual_circuit->evaluate(*individual_assignment),
                   "independent witnesses satisfy the combined circuit");
    }

    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "batch BP++ context creates");
    if (secp != nullptr) {
        purify::bppp::ScalarBytes nonce{};
        nonce[0] = 0xb8;
        const auto binding = purify::bytes_from_ascii("batch-bppp-prototype-v1");
        auto proof = purify::prove_experimental_nonce_batch_bppp(
            individual_groups, individual_assignments, nonce, secp.get(), binding);
        expect_ok(ctx, proof, "independent statements produce one experimental BP++ proof");
        if (proof.has_value()) {
            ctx.expect(proof->outputs.size() == individual_groups.size(), "batch proof retains ordered outputs");
            auto encoded = proof->serialize();
            expect_ok(ctx, encoded, "batch BP++ artifact serializes");
            if (encoded.has_value()) {
                auto decoded = purify::ExperimentalNonceBatchBpppProof::deserialize(*encoded);
                expect_ok(ctx, decoded, "batch BP++ artifact parses");
                if (decoded.has_value()) {
                    ctx.expect(decoded->outputs == proof->outputs && decoded->proof.proof == proof->proof.proof &&
                                   decoded->proof.a_commitment == proof->proof.a_commitment &&
                                   decoded->proof.s_commitment == proof->proof.s_commitment && decoded->proof.t2 == proof->proof.t2,
                               "batch proof frame retains outputs and proof");
                    auto verified = purify::verify_experimental_nonce_batch_bppp(
                        individual_groups, *decoded, secp.get(), binding);
                    ctx.expect(verified.has_value() && *verified, "public inputs verify the parsed batch artifact");
                    auto reversed_outputs = *decoded;
                    std::swap(reversed_outputs.outputs[0], reversed_outputs.outputs[1]);
                    auto reversed_result = purify::verify_experimental_nonce_batch_bppp(
                        individual_groups, reversed_outputs, secp.get(), binding);
                    ctx.expect(!reversed_result.has_value() || !*reversed_result,
                               "ordered batch outputs cannot be exchanged");
                }
                auto truncated = *encoded;
                truncated.pop_back();
                ctx.expect(!purify::ExperimentalNonceBatchBpppProof::deserialize(truncated).has_value(),
                           "truncated batch artifact rejects");
                auto extra = *encoded;
                extra.push_back(0);
                ctx.expect(!purify::ExperimentalNonceBatchBpppProof::deserialize(extra).has_value(),
                           "trailing batch artifact bytes reject");
                auto wrong_version = *encoded;
                wrong_version[0]++;
                ctx.expect(!purify::ExperimentalNonceBatchBpppProof::deserialize(wrong_version).has_value(),
                           "unknown batch artifact version rejects");
            }
        }
    }

    auto changed = *assignment;
    changed.commitments[0] = changed.commitments[0] + purify::FieldElement::one();
    changed.commitments[1] = changed.commitments[1] - purify::FieldElement::one();
    ctx.expect(!circuit->evaluate(changed),
               "equal and opposite changes cannot cancel between nonce outputs");
    changed = *assignment;
    std::swap(changed.commitments[0], changed.commitments[1]);
    ctx.expect(!circuit->evaluate(changed), "outputs bind the ordered topic groups");
    changed = *assignment;
    changed.commitments.pop_back();
    ctx.expect(!circuit->evaluate(changed), "batch rejects missing output commitment");

    auto reordered = fixture.groups;
    std::swap(reordered[0], reordered[1]);
    auto reordered_circuit = purify::nonce_batch_circuit(reordered);
    expect_ok(ctx, reordered_circuit, "reordered topic circuit builds");
    if (reordered_circuit.has_value()) {
        ctx.expect(!reordered_circuit->evaluate(*assignment),
                   "public topic order is bound by the batch circuit");
    }
    ctx.expect(!purify::nonce_batch_assignments(reordered, fixture.assignments).has_value(),
               "composition rejects assignments attached to another topic");

    auto swapped_members = fixture.assignments;
    std::swap(swapped_members[2][0], swapped_members[2][1]);
    ctx.expect(!purify::nonce_batch_assignments(fixture.groups, swapped_members).has_value(),
               "composition rejects witnesses attached to another coalition member");

    // Batch membership is not an input to Purify: proving just this group
    // must preserve the nonce produced when it belongs to the larger batch.
    auto singleton = purify::nonce_batch_assignments(
        std::span<const purify::NonceBatchGroup>{fixture.groups}.subspan(2, 1),
        std::span<const std::vector<purify::BulletproofAssignmentData>>{fixture.assignments}.subspan(2, 1));
    expect_ok(ctx, singleton, "a group can be prepared in a separate batch");
    if (singleton.has_value()) {
        ctx.expect(singleton->commitments[0] == assignment->commitments[2],
                   "repacking preserves the exact coalition/topic nonce");
    }

    fixture.groups.pop_back();
    fixture.assignments.pop_back();
    auto padded_circuit = purify::nonce_batch_circuit(fixture.groups);
    auto padded_assignment = purify::nonce_batch_assignments(fixture.groups, fixture.assignments);
    expect_ok(ctx, padded_circuit, "three-group circuit builds with final padding");
    expect_ok(ctx, padded_assignment, "three-group witness builds with final padding");
    if (padded_circuit.has_value() && padded_assignment.has_value()) {
        const auto group_gates = 2 * fixture.assignments[0][0].left.size();
        ctx.expect(padded_circuit->n_gates == std::bit_ceil(3 * group_gates),
                   "combined circuit pads the sum of group gate counts");
        ctx.expect(padded_circuit->evaluate(*padded_assignment),
                   "final padding preserves batch satisfaction");
    }
}

void test_batch_inputs(TestContext& ctx) {
    expect_error(ctx, purify::nonce_batch_circuit({}), purify::ErrorCode::InvalidDimensions,
                 "empty public batch rejects");
    expect_error(ctx, purify::nonce_batch_assignments({}, {}), purify::ErrorCode::InvalidDimensions,
                 "empty witness batch rejects");

    BatchFixture fixture;
    if (!prepare_batch(ctx, fixture)) return;
    auto missing_group = fixture.assignments;
    missing_group.pop_back();
    expect_error(ctx, purify::nonce_batch_assignments(fixture.groups, missing_group),
                 purify::ErrorCode::SizeMismatch, "missing witness group rejects");
    auto malformed = fixture.assignments;
    malformed[3][1].right.pop_back();
    ctx.expect(!purify::nonce_batch_assignments(fixture.groups, malformed).has_value(),
               "malformed member assignment rejects before composition");

    auto empty_roster = fixture.groups;
    empty_roster[1].hosts.clear();
    ctx.expect(!purify::nonce_batch_circuit(empty_roster).has_value(), "empty coalition roster rejects");
    auto duplicate_host = fixture.groups;
    duplicate_host[0].hosts[1] = duplicate_host[0].hosts[0];
    expect_error(ctx, purify::nonce_batch_circuit(duplicate_host), purify::ErrorCode::BindingMismatch,
                 "duplicate members within a coalition reject");
}

} // namespace

void run_nonce_batch_tests(TestContext& ctx) {
    // All witness columns are held by this process; no MPC is exercised.
    test_batch_relation(ctx);
    test_batch_inputs(ctx);
}
