// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <string>
#include <vector>

#include "purify.hpp"
#include "purify_test_helpers.hpp"

namespace {

using purify_test::TestContext;
using purify_test::expect_error;
using purify_test::expect_ok;

struct Members {
    std::vector<purify::UInt512> hosts;
    std::vector<purify::BulletproofAssignmentData> assignments;
    purify::FieldElement total = purify::FieldElement::zero();
};

bool prepare_members(TestContext& ctx, const purify::Bytes& input,
                     std::size_t count, Members& members) {
    for (std::size_t i = 0; i < count; ++i) {
        std::array<unsigned char, 32> seed{};
        seed[0] = 0xa7;
        seed[30] = static_cast<unsigned char>(i >> 8);
        seed[31] = static_cast<unsigned char>(i);
        auto key = purify::generate_key(std::span<const unsigned char>{seed});
        expect_ok(ctx, key, "aggregate member key generation succeeds");
        if (!key.has_value()) return false;
        auto witness = purify::prove_assignment_data(input, key->secret);
        expect_ok(ctx, witness, "each member independently builds its witness");
        if (!witness.has_value()) return false;
        members.hosts.push_back(witness->public_key);
        members.total = members.total + witness->output;
        members.assignments.push_back(std::move(witness->assignment));
    }
    return true;
}

void test_sum_circuit(TestContext& ctx, std::size_t count) {
    const purify::Bytes input = purify::bytes_from_ascii("Purify/AggregateCircuit/Test/V1");
    auto circuit_template = purify::verifier_circuit_template(input);
    expect_ok(ctx, circuit_template, "aggregate circuit template builds");
    if (!circuit_template.has_value()) return;
    Members members;
    if (!prepare_members(ctx, input, count, members)) return;
    auto circuit = circuit_template->instantiate_sum(members.hosts);
    auto assignment = circuit_template->sum_assignments(members.hosts, members.assignments);
    expect_ok(ctx, circuit, "ordered aggregate circuit instantiates");
    expect_ok(ctx, assignment, "valid member assignments compose");
    if (!circuit.has_value() || !assignment.has_value()) return;

    ctx.expect(circuit->n_commitments == 1, "aggregate has exactly one public commitment");
    ctx.expect(circuit->n_bits == 0, "aggregate retains explicit local bit constraints");
    ctx.expect(circuit->n_gates == std::bit_ceil(count * members.assignments[0].left.size()),
               "aggregate pads the combined gate count only once");
    ctx.expect(assignment->commitments.size() == 1 && assignment->commitments[0] == members.total,
               "aggregate commitment is the field sum of all member outputs");
    ctx.expect(circuit->evaluate(*assignment), "aggregate witness satisfies the circuit");

    assignment->commitments[0] = assignment->commitments[0] + purify::FieldElement::one();
    ctx.expect(!circuit->evaluate(*assignment), "circuit rejects a different aggregate nonce");
    assignment->commitments[0] = members.total;
    assignment->left[0] = assignment->left[0] + purify::FieldElement::one();
    ctx.expect(!circuit->evaluate(*assignment), "circuit rejects a changed member witness");
    assignment->left[0] = assignment->left[0] - purify::FieldElement::one();
    const std::size_t last_member = (count - 1) * members.assignments[0].left.size();
    assignment->left[last_member] = assignment->left[last_member] + purify::FieldElement::one();
    ctx.expect(!circuit->evaluate(*assignment), "circuit rejects a changed last member witness");
}

void test_sum_bindings(TestContext& ctx) {
    const purify::Bytes input = purify::bytes_from_ascii("Purify/AggregateCircuit/Bindings/V1");
    auto circuit_template = purify::verifier_circuit_template(input);
    expect_ok(ctx, circuit_template, "binding test template builds");
    if (!circuit_template.has_value()) return;
    Members members;
    if (!prepare_members(ctx, input, 3, members)) return;
    auto assignment = circuit_template->sum_assignments(members.hosts, members.assignments);
    expect_ok(ctx, assignment, "binding test assignment composes");
    if (!assignment.has_value()) return;

    auto reversed_hosts = members.hosts;
    std::reverse(reversed_hosts.begin(), reversed_hosts.end());
    auto reordered = circuit_template->instantiate_sum(reversed_hosts);
    expect_ok(ctx, reordered, "a different ordered roster instantiates");
    if (reordered.has_value()) {
        ctx.expect(!reordered->evaluate(*assignment), "member witnesses bind their ordered hosts");
        auto reversed_assignments = members.assignments;
        std::reverse(reversed_assignments.begin(), reversed_assignments.end());
        auto reversed = circuit_template->sum_assignments(reversed_hosts, reversed_assignments);
        expect_ok(ctx, reversed, "reordering hosts and witnesses together composes");
        if (reversed.has_value()) {
            ctx.expect(reordered->evaluate(*reversed), "consistently reordered aggregate satisfies the circuit");
            ctx.expect(reversed->commitments == assignment->commitments,
                       "consistent reordering preserves the commutative output sum");
        }
    }
    ctx.expect(!circuit_template->sum_assignments(reversed_hosts, members.assignments).has_value(),
               "composition rejects witnesses for a different ordered roster");

    auto other_template = purify::verifier_circuit_template(purify::Bytes{0x99});
    expect_ok(ctx, other_template, "different input template builds");
    if (other_template.has_value()) {
        auto other_circuit = other_template->instantiate_sum(members.hosts);
        expect_ok(ctx, other_circuit, "different input aggregate instantiates");
        if (other_circuit.has_value()) {
            ctx.expect(!other_circuit->evaluate(*assignment), "aggregate witness binds the evaluation input");
        }
    }

    ctx.expect(!circuit_template->instantiate_sum({}).has_value(), "empty roster rejects");
    ctx.expect(!circuit_template->sum_assignments({}, {}).has_value(), "empty witness aggregate rejects");
    auto duplicates = members.hosts;
    duplicates[1] = duplicates[0];
    expect_error(ctx, circuit_template->instantiate_sum(duplicates), purify::ErrorCode::BindingMismatch,
                 "duplicate hosts reject");
    auto invalid_hosts = members.hosts;
    invalid_hosts[0] = purify::UInt512::from_hex(std::string(128, 'f'));
    ctx.expect(!circuit_template->instantiate_sum(invalid_hosts).has_value(), "invalid packed host rejects");

    auto malformed = members.assignments;
    malformed[1].left.pop_back();
    ctx.expect(!circuit_template->sum_assignments(members.hosts, malformed).has_value(),
               "composition rejects malformed member dimensions");
    malformed = members.assignments;
    malformed[1].commitments[0] = malformed[1].commitments[0] + purify::FieldElement::one();
    ctx.expect(!circuit_template->sum_assignments(members.hosts, malformed).has_value(),
               "composition validates each member output before summing");
    malformed.pop_back();
    ctx.expect(!circuit_template->sum_assignments(members.hosts, malformed).has_value(),
               "composition rejects a missing member");
}

} // namespace

void run_aggregate_nonce_tests(TestContext& ctx) {
    test_sum_circuit(ctx, 1);
    test_sum_circuit(ctx, 3);
    test_sum_bindings(ctx);
}

void run_aggregate_nonce_100_tests(TestContext& ctx) {
    // Centralized arithmetic validation only: these witnesses are all visible
    // to this test process. This does not exercise an MPC protocol.
    test_sum_circuit(ctx, 100);
}
