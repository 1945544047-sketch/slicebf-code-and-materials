#include <algorithm>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#include "slicebf.hpp"

using namespace sbf;

namespace {

std::set<std::string> as_set(const std::vector<std::string>& values) {
    return {values.begin(), values.end()};
}

bool expect(const SliceBF& scheme, const std::vector<std::string>& query,
            const std::set<std::string>& wanted, SearchStats* stats = nullptr) {
    const auto got = as_set(scheme.search(query, stats));
    if (got == wanted) return true;
    std::cerr << "query mismatch:";
    for (const auto& term : query) std::cerr << ' ' << term;
    std::cerr << "\nexpected:";
    for (const auto& id : wanted) std::cerr << ' ' << id;
    std::cerr << "\nactual:";
    for (const auto& id : got) std::cerr << ' ' << id;
    std::cerr << "\n";
    return false;
}

bool padded_batch_is_valid(const UpdatePrepareStats& stats) {
    const size_t n = stats.padded_delta_records;
    return n >= stats.real_delta_records && n != 0 && (n & (n - 1)) == 0;
}

}  // namespace

int main() {
    Params params;
    params.m = 64;
    params.k = 4;
    params.bucket_size = 4;
    params.chain_threshold = 2;
    params.delta_batch_min = 2;
    params.reserve_buckets_per_class = 1;

    const Document d1{"doc-01", {"cloud", "search"}};
    const Document d2{"doc-02", {"cloud", "privacy"}};
    const Document d3{"doc-03", {"search", "privacy"}};
    const Document d4{"doc-04", {"cloud", "search", "privacy", "alpha"}};

    SliceBF scheme(params);
    scheme.build({d1, d2, d3});
    if (!expect(scheme, {"cloud", "search"}, {d1.id})) return 1;

    UpdatePrepareStats add_stats;
    auto add = scheme.insert(d4, &add_stats);
    if (!padded_batch_is_valid(add_stats) || !scheme.verify_token(add)) {
        std::cerr << "valid padded insertion rejected\n";
        return 1;
    }
    if (!expect(scheme, {"cloud", "search", "privacy"}, {d4.id})) return 1;

    UpdatePrepareStats modify_stats;
    auto modify_add = scheme.modify_keywords(d2.id, {"search"}, {},
                                               &modify_stats);
    if (!padded_batch_is_valid(modify_stats) ||
        !scheme.verify_token(modify_add) ||
        !expect(scheme, {"cloud", "search"}, {d1.id, d2.id, d4.id})) {
        std::cerr << "keyword addition failed\n";
        return 1;
    }
    auto modify_del = scheme.modify_keywords(d2.id, {}, {"privacy"}, nullptr);
    if (!scheme.verify_token(modify_del) ||
        !expect(scheme, {"cloud", "privacy"}, {d4.id})) {
        std::cerr << "keyword deletion failed\n";
        return 1;
    }

    UpdatePrepareStats del_stats;
    auto del = scheme.remove(d1.id, &del_stats);
    if (!padded_batch_is_valid(del_stats) || !scheme.verify_token(del)) {
        std::cerr << "valid padded deletion rejected\n";
        return 1;
    }
    // d2 gained "search" above; removing its "privacy" did not remove "search".
    if (!expect(scheme, {"cloud", "search"}, {d2.id, d4.id})) return 1;

    auto reinsert = scheme.insert(d1, nullptr);
    if (!scheme.verify_token(reinsert) ||
        !expect(scheme, {"cloud", "search"}, {d1.id, d2.id, d4.id})) {
        std::cerr << "delete/reinsert lifecycle failed\n";
        return 1;
    }

    SearchStats search_stats;
    if (!expect(scheme, {"cloud", "search", "privacy", "alpha"}, {d4.id},
                &search_stats) ||
        // With m=64, duplicate hash positions within a keyword can reduce
        // the total below 16. Either one or two groups is correct here.
        search_stats.groups < 1 || search_stats.groups > 2 ||
        search_stats.requested_buckets == 0 ||
        search_stats.returned_bucket_slots !=
            search_stats.requested_buckets * params.bucket_size ||
        search_stats.aggregate_bytes == 0 || search_stats.round_trips != 2) {
        std::cerr << "grouping or bucket accounting failed\n";
        return 1;
    }

    // Guarantee a multi-group test without assuming collision-free hashing:
    // each of 16 distinct keywords contributes at least one position.
    Document grouped_doc{"grouped", {}};
    for (int i = 0; i < 16; ++i)
        grouped_doc.tokens.push_back("term-" + std::to_string(i));
    SliceBF grouped(params);
    grouped.build({grouped_doc});
    SearchStats grouped_stats;
    if (!expect(grouped, grouped_doc.tokens, {grouped_doc.id}, &grouped_stats) ||
        grouped_stats.groups < 2 || grouped_stats.groups > 5) {
        std::cerr << "guaranteed multi-group query failed\n";
        return 1;
    }

    if (!scheme.needs_compaction() || scheme.delta_log_bytes() == 0) {
        std::cerr << "delta-chain threshold was not enforced\n";
        return 1;
    }
    const auto before_compaction = as_set(scheme.search({"cloud", "search"}));
    const auto compact = scheme.compact();
    const auto after_compaction = as_set(scheme.search({"cloud", "search"}));
    if (compact.new_generation != compact.old_generation + 1 ||
        compact.removed_delta_records == 0 || scheme.delta_log_bytes() != 0 ||
        after_compaction != before_compaction) {
        std::cerr << "compaction changed query semantics\n";
        std::cerr << "before:";
        for (const auto& id : before_compaction) std::cerr << ' ' << id;
        std::cerr << "\nafter:";
        for (const auto& id : after_compaction) std::cerr << ' ' << id;
        std::cerr << "\n";
        return 1;
    }

    SliceBF authentication(params);
    auto valid = authentication.insert(d1, nullptr);
    auto tampered = valid;
    tampered.records.front().ciphertext.front() ^= 0x01;
    if (authentication.verify_token(tampered) ||
        !authentication.verify_token(valid) ||
        authentication.verify_token(valid)) {
        std::cerr << "tamper or replay protection failed\n";
        return 1;
    }

    if (scheme.owner_state_bytes() == 0 || scheme.client_state_bytes() == 0 ||
        scheme.server_storage_bytes() == 0) {
        std::cerr << "storage accounting is incomplete\n";
        return 1;
    }

    std::cout << "SliceBF protocol smoke test: PASS\n";
    std::cout << "snapshot=" << scheme.snapshot_bytes()
              << " owner=" << scheme.owner_state_bytes()
              << " client=" << scheme.client_state_bytes()
              << " server=" << scheme.server_storage_bytes() << " bytes\n";
    return 0;
}
