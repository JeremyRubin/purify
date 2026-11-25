// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_support.cpp
 * @brief Byte views, generator-backend resolution and challenge-scalar derivation for BPPP.
 */

#include "purify/bppp.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

#include "bppp_support.hpp"
#include "secure_cleanup.hpp"

namespace purify::bppp::detail {
namespace {

using U64Le = std::array<unsigned char, sizeof(std::uint64_t)>;

U64Le u64_le(std::uint64_t value) {
  U64Le out{};
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<unsigned char>((value >> (8 * i)) & 0xffU);
  }
  return out;
}

/**
 * Parses `tag(seed || labels...)` as one secret scalar candidate.
 *
 * The seed was absorbed once into `seed_hash` and is neither copied nor
 * hashed again here.
 */
template <typename... Labels>
Result<FieldElement> secret_scalar_candidate(const SeedHash &seed_hash,
                                             const Labels &...labels) {
  static_assert(sizeof...(Labels) <= 4,
                "SeedHash::digest accepts at most four labels");
  SecretScalarBytes candidate_bytes;
  const std::array<std::span<const unsigned char>, sizeof...(Labels)>
      label_spans{std::span<const unsigned char>(labels)...};
  ScalarBytes digest = seed_hash.digest(label_spans);
  candidate_bytes.value = digest;
  ::purify::detail::secure_clear_bytes(digest.data(), digest.size());
  return FieldElement::try_from_bytes32(candidate_bytes.value);
}

} // namespace

ResolvedBpppGeneratorBackend resolve_bppp_generator_backend(
    ExperimentalCircuitBackend *cache,
    const std::vector<PointBytes> &serialized_generators,
    purify_secp_context *secp_context) {
  ResolvedBpppGeneratorBackend out;
  out.serialized_bytes = byte_span(serialized_generators);
  out.generator_count = serialized_generators.size();

  if (cache == nullptr || serialized_generators.empty()) {
    return out;
  }
  out.backend_resources =
      detail::ExperimentalCircuitBackendAccess::get_or_create_backend_resources(
          cache, serialized_generators, secp_context);
  return out;
}

Result<std::size_t> round_up_power_of_two(std::size_t value) {
  if (value == 0) {
    return unexpected_error(ErrorCode::Overflow);
  }
  std::size_t out = 1;
  while (out < value) {
    if (out > std::numeric_limits<std::size_t>::max() / 2) {
      return unexpected_error(ErrorCode::Overflow);
    }
    out <<= 1;
  }
  return out;
}

Result<FieldElement> derive_nonzero_scalar(std::span<const unsigned char> seed,
                                           const TaggedHash& tag,
                                           std::size_t index) {
  PURIFY_ASSIGN_OR_RETURN(const auto &encoded_index, narrow_size_to_u64(index));
  const U64Le index_le = u64_le(encoded_index);
  for (std::uint64_t counter = 0; counter < 256; ++counter) {
    const U64Le counter_le = u64_le(counter);
    const ScalarBytes candidate_bytes =
        tag.digest_many<3>({seed, index_le, counter_le});
    Result<FieldElement> candidate =
        FieldElement::try_from_bytes32(candidate_bytes);
    if (candidate.has_value() && !candidate->is_zero()) {
      return candidate;
    }
  }
  return unexpected_error(ErrorCode::InternalMismatch);
}

SeedHash::SeedHash(const TaggedHash &tag,
                   std::span<const unsigned char> seed) {
  const auto &tag_digest = tag.tag_digest();
  const std::array<const unsigned char *, 3> items{
      tag_digest.data(), tag_digest.data(),
      seed.empty() ? nullptr : seed.data()};
  const std::array<std::size_t, 3> item_lens{tag_digest.size(),
                                             tag_digest.size(), seed.size()};
  const int ok = purify_sha256_prefix_init(&prefix_, items.data(),
                                           item_lens.data(), items.size());
  assert(ok != 0 && "SeedHash requires well-formed segments");
  (void)ok;
}

SeedHash::~SeedHash() { purify_sha256_prefix_clear(&prefix_); }

ScalarBytes SeedHash::digest(
    std::span<const std::span<const unsigned char>> labels) const {
  // Scalar derivations use at most three labels: index, attempt, counter.
  static constexpr std::size_t kMaxLabels = 4;
  assert(labels.size() <= kMaxLabels && "SeedHash::digest label count");
  std::array<const unsigned char *, kMaxLabels> items{};
  std::array<std::size_t, kMaxLabels> item_lens{};
  const std::size_t count = std::min(labels.size(), kMaxLabels);
  for (std::size_t i = 0; i < count; ++i) {
    items[i] = labels[i].empty() ? nullptr : labels[i].data();
    item_lens[i] = labels[i].size();
  }
  ScalarBytes out{};
  const int ok = purify_sha256_prefix_finish(&prefix_, out.data(), items.data(),
                                             item_lens.data(), count);
  assert(ok != 0 && "SeedHash::digest requires well-formed labels");
  (void)ok;
  return out;
}

Status derive_scalar(FieldElement &out, std::span<const unsigned char> seed,
                     const TaggedHash &tag, std::size_t index,
                     std::uint64_t attempt) {
  const SeedHash seed_hash(tag, seed);
  return derive_scalar(out, seed_hash, index, attempt);
}

Status derive_scalar(FieldElement &out, const SeedHash &seed_hash,
                     std::size_t index, std::uint64_t attempt) {
  PURIFY_ASSIGN_OR_RETURN(const auto &encoded_index, narrow_size_to_u64(index));
  const U64Le index_le = u64_le(encoded_index);
  const U64Le attempt_le = u64_le(attempt);
  for (std::uint64_t counter = 0; counter < 256; ++counter) {
    Result<FieldElement> candidate = secret_scalar_candidate(
        seed_hash, index_le, attempt_le, u64_le(counter));
    if (candidate.has_value()) {
      out = *candidate;
      ::purify::detail::secure_erase(*candidate);
      return {};
    }
  }
  return unexpected_error(ErrorCode::InternalMismatch);
}

Status derive_secret_nonzero_scalar(FieldElement &out,
                                    std::span<const unsigned char> seed,
                                    const TaggedHash &tag,
                                    std::size_t index) {
  PURIFY_ASSIGN_OR_RETURN(const auto &encoded_index, narrow_size_to_u64(index));
  const U64Le index_le = u64_le(encoded_index);
  const SeedHash seed_hash(tag, seed);
  for (std::uint64_t counter = 0; counter < 256; ++counter) {
    Result<FieldElement> candidate =
        secret_scalar_candidate(seed_hash, index_le, u64_le(counter));
    if (candidate.has_value()) {
      if (!candidate->is_zero()) {
        out = *candidate;
        ::purify::detail::secure_erase(*candidate);
        return {};
      }
      ::purify::detail::secure_erase(*candidate);
    }
  }
  return unexpected_error(ErrorCode::InternalMismatch);
}

FieldElement weighted_bppp_inner_product(std::span<const FieldElement> lhs,
                                         std::span<const FieldElement> rhs,
                                         const FieldElement &rho) {
  assert(lhs.size() == rhs.size() &&
         "weighted_bppp_inner_product requires matching vector lengths");
  FieldElement mu = rho * rho;
  FieldElement weight = mu;
  FieldElement total = FieldElement::zero();
  for (std::size_t i = 0; i < lhs.size(); ++i) {
    total = total + (weight * lhs[i] * rhs[i]);
    weight = weight * mu;
  }
  return total;
}

} // namespace purify::bppp::detail
