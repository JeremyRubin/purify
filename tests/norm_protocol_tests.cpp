// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <memory>
#include <vector>

#include "../src/bridge/bppp_bridge.h"
#include "purify/bppp.hpp"
#include "test_harness.hpp"

namespace {

using purify::FieldElement;
using purify_test::TestContext;
using purify_test::expect_ok;

void check_initial_point_boundary(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "norm boundary context creates");
    if (!secp) return;
    auto generators = purify::bppp::create_generators(2, secp.get());
    expect_ok(ctx, generators, "norm boundary generators create");
    if (!generators) return;
    purify::bppp::NormArgInputs inputs{
        FieldElement::from_int(3).to_bytes_be(), *generators,
        {FieldElement::from_int(5).to_bytes_be()},
        {FieldElement::from_int(7).to_bytes_be()},
        {FieldElement::from_int(11).to_bytes_be()}};
    auto commitment = purify::bppp::commit_norm_arg(inputs, secp.get());
    expect_ok(ctx, commitment, "finite terminal norm commitment creates");
    if (!commitment) return;

    // With one coordinate in each family there are no folding rounds. The
    // encoding consists only of these two public fixture witness scalars.
    purify::Bytes terminal(inputs.n_vec[0].begin(), inputs.n_vec[0].end());
    terminal.insert(terminal.end(), inputs.l_vec[0].begin(), inputs.l_vec[0].end());
    purify::bppp::NormArgProof proof{
        inputs.rho, *generators, inputs.c_vec, 1, *commitment, terminal};
    ctx.expect(purify::bppp::verify_norm_arg(proof, secp.get()),
               "finite terminal norm statement verifies");

    purify::Bytes generator_bytes;
    for (const auto& generator : *generators) {
        generator_bytes.insert(generator_bytes.end(), generator.begin(), generator.end());
    }
    using Resources = std::unique_ptr<purify_bppp_backend_resources,
        decltype(&purify_bppp_backend_resources_destroy)>;
    Resources resources(purify_bppp_backend_resources_create(
        secp.get(), generator_bytes.data(), generators->size()),
        purify_bppp_backend_resources_destroy);
    ctx.expect(resources != nullptr, "cached norm boundary resources create");
    if (!resources) return;
    const auto cached_verify = [&](const purify::bppp::NormArgProof& candidate) {
        return purify_bppp_verify_norm_arg_with_resources(
            resources.get(), candidate.rho.data(), candidate.c_vec[0].data(), 1, 1,
            candidate.commitment.data(), candidate.proof.data(), candidate.proof.size());
    };
    ctx.expect(cached_verify(proof) != 0, "cached finite terminal statement verifies");

    // The all-zero opening is mathematically an identity commitment. This
    // bridge rejects initial infinity, consistently with its commit/prove
    // encoding. It must not hash an unwritten serialization buffer.
    proof.commitment.fill(0);
    std::fill(proof.proof.begin(), proof.proof.end(), 0);
    ctx.expect(!purify::bppp::verify_norm_arg(proof, secp.get()),
               "initial infinity is rejected before transcript use");
    ctx.expect(cached_verify(proof) == 0,
               "cached verification rejects initial infinity too");
    inputs.n_vec[0].fill(0);
    inputs.l_vec[0].fill(0);
    ctx.expect(!purify::bppp::commit_norm_arg(inputs, secp.get()),
               "norm commitment creation also rejects initial infinity");
}

} // namespace

void run_norm_protocol_tests(TestContext& ctx) {
    check_initial_point_boundary(ctx);
}
