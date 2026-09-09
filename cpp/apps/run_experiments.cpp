// SliceBF-only experiment runner for the public code-and-materials package.
// It preserves the measurement boundaries used for the SliceBF rows in the
// manuscript without distributing any comparison-scheme implementation.
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#elif defined(__linux__)
#include <sched.h>
#endif

#include "corpus.hpp"
#include "experiment.hpp"
#include "json.hpp"
#include "slicebf.hpp"

using namespace exp_util;
using namespace sbf;
using nlohmann::json;

namespace {

volatile uint64_t calibration_sink = 0;

double host_calibration_ms() {
    // A fixed, dependency-chained integer workload acts as an in-band check
    // for core migration, power-state changes, and external CPU contention.
    // The volatile state prevents the optimizer from removing the loop.
    volatile uint64_t x = UINT64_C(0x9e3779b97f4a7c15);
    const auto t0 = Clock::now();
    for (uint64_t i = 0; i < UINT64_C(5000000); ++i) {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x *= UINT64_C(2685821657736338717);
        x += i;
    }
    const auto t1 = Clock::now();
    calibration_sink = x;
    return ms(t0, t1);
}

int current_logical_cpu() {
#ifdef _WIN32
    return static_cast<int>(GetCurrentProcessorNumber());
#elif defined(__linux__)
    return sched_getcpu();
#else
    return -1;
#endif
}

struct Config {
    std::string corpus_dir = "data/processed_300k_v2";
    std::string query_dir = "data/processed_300k_v2/queries";
    std::string output_dir = "results_300k";
    std::string experiment = "all";
    int repetitions = 1;
    int run_id = 0;
    int warmup = 10;
    int update_cycles = 10000;
    int correctness_interval = 100;
    uint64_t seed = 20260711;
    std::string slicebf_variant = "full";
    std::vector<size_t> scales{50000, 100000, 150000, 200000, 250000, 300000};
    std::vector<int> arities{2, 3, 4, 5};
};

struct Query {
    std::string id;
    std::string bucket;
    int q = 0;
    std::vector<std::string> terms;
};

struct Measurement {
    double trapdoor_ms = 0;
    double server_ms = 0;
    double unmask_ms = 0;
    double delta_replay_ms = 0;
    double verify_ms = 0;
    double client_ms = 0;
    double total_ms = 0;
    size_t groups = 0;
    size_t aggregate_bytes = 0;
    size_t delta_records = 0;
    size_t delta_bytes = 0;
    size_t requested_buckets = 0;
    size_t returned_bucket_slots = 0;
    size_t trapdoor_bytes = 0;
    size_t bucket_bytes = 0;
    size_t client_to_server_bytes = 0;
    size_t server_to_client_bytes = 0;
    size_t candidates = 0;
    std::vector<std::string> result;
};

size_t keyword_pairs(const std::vector<Document>& docs);

std::vector<Document> load_docs(const Config& c, size_t n) {
    return load_corpus(c.corpus_dir + "/corpus_N" + std::to_string(n) + ".jsonl");
}

std::vector<Query> load_queries(const Config& c, int q) {
    const std::string path = c.query_dir + "/q" + std::to_string(q) + "_80.jsonl";
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open query file: " + path);
    std::vector<Query> out;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        auto j = json::parse(line);
        Query query;
        query.id = j.value("query_id", std::string{});
        query.bucket = j.value("bucket", std::string{});
        query.q = j.value("q", q);
        query.terms = j.at("terms").get<std::vector<std::string>>();
        std::unordered_set<std::string> distinct(query.terms.begin(),
                                                 query.terms.end());
        if (query.terms.empty() || distinct.size() != query.terms.size())
            throw std::runtime_error("query terms are empty or duplicated: " +
                                     query.id);
        out.push_back(std::move(query));
    }
    return out;
}

std::string query_key(const Query& q) {
    return std::to_string(q.q) + ":" + q.id;
}

class PlainOracle {
public:
    PlainOracle(const std::vector<Document>& docs,
                const std::vector<std::vector<Query>>& groups) {
        std::unordered_set<std::string> needed;
        for (const auto& group : groups)
            for (const auto& q : group)
                needed.insert(q.terms.begin(), q.terms.end());

        std::unordered_map<std::string, std::vector<uint32_t>> postings;
        postings.reserve(needed.size() * 2);
        for (uint32_t i = 0; i < docs.size(); ++i) {
            std::unordered_set<std::string> seen;
            for (const auto& term : docs[i].tokens)
                if (needed.count(term) && seen.insert(term).second)
                    postings[term].push_back(i);
        }
        for (const auto& group : groups) {
            for (const auto& q : group) {
                std::vector<uint32_t> current;
                bool first = true;
                for (const auto& term : q.terms) {
                    const auto& posting = postings[term];
                    if (first) {
                        current = posting;
                        first = false;
                    } else {
                        std::vector<uint32_t> next;
                        std::set_intersection(current.begin(), current.end(),
                                              posting.begin(), posting.end(),
                                              std::back_inserter(next));
                        current.swap(next);
                    }
                    if (current.empty()) break;
                }
                std::set<std::string> ids;
                for (uint32_t index : current) ids.insert(docs[index].id);
                answers_.emplace(query_key(q), std::move(ids));
            }
        }
    }

    const std::set<std::string>& answer(const Query& q) const {
        return answers_.at(query_key(q));
    }

private:
    std::unordered_map<std::string, std::set<std::string>> answers_;
};

Measurement measure(SliceBF& scheme, const Query& query) {
    sbf::SearchStats stats;
    Measurement m;
    m.result = scheme.search(query.terms, &stats);
    m.trapdoor_ms = stats.ms_trapdoor;
    m.server_ms = stats.ms_server;
    m.unmask_ms = stats.ms_unmask;
    m.delta_replay_ms = stats.ms_delta_replay;
    m.verify_ms = stats.ms_verify;
    m.client_ms = stats.ms_client;
    m.total_ms = stats.ms_total;
    m.groups = stats.groups;
    m.aggregate_bytes = stats.aggregate_bytes;
    m.delta_records = stats.delta_records;
    m.delta_bytes = stats.delta_bytes;
    m.requested_buckets = stats.requested_buckets;
    m.returned_bucket_slots = stats.returned_bucket_slots;
    m.trapdoor_bytes = stats.trapdoor_bytes;
    m.bucket_bytes = stats.bucket_bytes;
    m.client_to_server_bytes = stats.client_to_server_bytes;
    m.server_to_client_bytes = stats.server_to_client_bytes;
    m.candidates = stats.candidate_count;
    return m;
}

void write_search_header(CsvWriter& writer) {
    writer.header({"experiment", "run_id", "scheme", "N", "query_id", "q",
        "bucket", "trapdoor_ms", "server_ms", "unmask_ms", "delta_replay_ms",
        "verify_ms", "client_ms", "total_ms", "groups", "aggregate_bytes",
        "delta_records", "delta_bytes", "requested_buckets",
        "returned_bucket_slots", "trapdoor_bytes", "bucket_bytes",
        "client_to_server_bytes", "server_to_client_bytes", "candidates",
        "final_results", "correct", "seed"});
}

template <class Scheme>
void run_query_groups(const Config& c, const std::string& experiment,
                      const std::string& name, size_t n, Scheme& scheme,
                      const std::vector<std::vector<Query>>& groups,
                      const PlainOracle& oracle, CsvWriter& raw,
                      SummaryWriter& summary, CsvWriter& host) {
    for (const auto& group : groups) {
        if (group.empty()) continue;
        const int cpu_before = current_logical_cpu();
        const double calibration_before = host_calibration_ms();

        std::vector<size_t> warmup_order(group.size());
        for (size_t i = 0; i < warmup_order.size(); ++i) warmup_order[i] = i;
        std::mt19937_64 warmup_rng(
            c.seed + static_cast<uint64_t>(c.run_id) + n +
            static_cast<uint64_t>(group[0].q) * UINT64_C(2000003));
        std::shuffle(warmup_order.begin(), warmup_order.end(), warmup_rng);
        for (int i = 0; i < std::min<int>(c.warmup, group.size()); ++i)
            (void)measure(scheme, group[warmup_order[static_cast<size_t>(i)]]);

        std::vector<double> total_times;
        for (int repetition = 0; repetition < c.repetitions; ++repetition) {
            std::vector<size_t> order(group.size());
            for (size_t i = 0; i < order.size(); ++i) order[i] = i;
            const int measured_run = c.run_id + repetition;
            std::mt19937_64 rng(c.seed + measured_run + n +
                                group[0].q * 1000003ULL);
            std::shuffle(order.begin(), order.end(), rng);
            for (size_t index : order) {
                const auto& query = group[index];
                auto measurement = measure(scheme, query);
                std::set<std::string> got(measurement.result.begin(),
                                          measurement.result.end());
                const bool no_duplicate_results =
                    got.size() == measurement.result.size();
                const bool correct = no_duplicate_results &&
                                     got == oracle.answer(query);
                raw.row(experiment, measured_run, name, n, query.id, query.q,
                    query.bucket, measurement.trapdoor_ms, measurement.server_ms,
                    measurement.unmask_ms, measurement.delta_replay_ms,
                    measurement.verify_ms, measurement.client_ms,
                    measurement.total_ms, measurement.groups,
                    measurement.aggregate_bytes, measurement.delta_records,
                    measurement.delta_bytes, measurement.requested_buckets,
                    measurement.returned_bucket_slots, measurement.trapdoor_bytes,
                    measurement.bucket_bytes, measurement.client_to_server_bytes,
                    measurement.server_to_client_bytes, measurement.candidates,
                    measurement.result.size(), correct ? 1 : 0, c.seed);
                total_times.push_back(measurement.total_ms);
                if (!correct)
                    throw std::runtime_error(name + " result mismatch for " +
                                             query_key(query));
            }
        }
        summary.write(experiment, name, n, group[0].q, "all", "total_query_ms",
                      Stats::from(total_times), "seed=" + std::to_string(c.seed));

        const double calibration_after = host_calibration_ms();
        const int cpu_after = current_logical_cpu();
        host.row(experiment, name, n, group[0].q, c.run_id,
                 calibration_before, calibration_after,
                 calibration_after / std::max(1e-12, calibration_before),
                 cpu_before, cpu_after);
    }
}

void run_search(const Config& c, bool by_size) {
    const std::string experiment = by_size ? "E1" : "E2";
    const std::string dir = c.output_dir + "/" + experiment;
    std::filesystem::create_directories(dir);
    CsvWriter raw(dir + "/raw.csv");
    write_search_header(raw);
    SummaryWriter summary(dir + "/summary.csv");
    CsvWriter host(dir + "/host.csv");
    host.header({"experiment", "scheme", "N", "q", "run_id",
        "calibration_before_ms", "calibration_after_ms",
        "calibration_ratio", "logical_cpu_before", "logical_cpu_after"});

    std::vector<size_t> scales = by_size ? c.scales
                                         : std::vector<size_t>{c.scales.back()};
    for (size_t n : scales) {
        auto docs = load_docs(c, n);
        std::vector<std::vector<Query>> groups;
        if (by_size) {
            groups.push_back(load_queries(c, 3));
        } else {
            for (int q : c.arities) groups.push_back(load_queries(c, q));
            std::mt19937_64 group_rng(
                c.seed + static_cast<uint64_t>(c.run_id) + n +
                UINT64_C(0x6a09e667f3bcc909));
            std::shuffle(groups.begin(), groups.end(), group_rng);
        }
        PlainOracle oracle(docs, groups);

        {
            Params params;
            std::string name = "SliceBF";
            if (c.slicebf_variant == "no-mask") {
                params.enable_masking = false;
                name = "SliceBF-NoMask";
            } else if (c.slicebf_variant == "no-bit-slice") {
                params.enable_bit_sliced_aggregation = false;
                name = "SliceBF-NoBitSlice";
            } else if (c.slicebf_variant == "no-pruning") {
                params.enable_bucket_pruning = false;
                name = "SliceBF-NoPruning";
            }
            SliceBF scheme(params);
            scheme.build(docs);
            run_query_groups(c, experiment, name, n, scheme, groups,
                             oracle, raw, summary, host);
        }
    }
}

size_t keyword_pairs(const std::vector<Document>& docs) {
    size_t total = 0;
    for (const auto& doc : docs) total += doc.tokens.size();
    return total;
}

void run_setup(const Config& c) {
    const std::string dir = c.output_dir + "/E3";
    std::filesystem::create_directories(dir);
    CsvWriter raw(dir + "/raw.csv");
    raw.header({"run_id", "scheme", "N", "documents", "pairs", "setup_ms",
                "ms_per_document", "ms_per_pair", "build_attempts",
                "success", "seed"});
    SummaryWriter summary(dir + "/summary.csv");
    CsvWriter host(dir + "/host.csv");
    host.header({"experiment", "scheme", "N", "q", "run_id",
        "calibration_before_ms", "calibration_after_ms",
        "calibration_ratio", "logical_cpu_before", "logical_cpu_after"});
    for (size_t n : c.scales) {
        auto docs = load_docs(c, n);
        const size_t pairs = keyword_pairs(docs);
        auto run = [&](const std::string& name, auto factory) {
            std::vector<double> times;
            for (int iteration = 0; iteration < c.repetitions; ++iteration) {
                const int cpu_before = current_logical_cpu();
                const double calibration_before = host_calibration_ms();
                size_t build_attempts = 1;
                const double elapsed = timed_ms(
                    [&] { build_attempts = factory(docs); });
                const double calibration_after = host_calibration_ms();
                const int cpu_after = current_logical_cpu();
                times.push_back(elapsed);
                raw.row(c.run_id + iteration, name, n, docs.size(), pairs, elapsed,
                        elapsed / std::max<size_t>(1, docs.size()),
                        elapsed / std::max<size_t>(1, pairs), build_attempts,
                        1, c.seed);
                host.row("E3", name, n, 0, c.run_id + iteration,
                         calibration_before, calibration_after,
                         calibration_after /
                             std::max(1e-12, calibration_before),
                         cpu_before, cpu_after);
            }
            summary.write("E3", name, n, 0, "all", "setup_ms",
                          Stats::from(times), "seed=" + std::to_string(c.seed));
        };
        {
            run("SliceBF", [](const auto& input) {
                SliceBF s;
                s.build(input);
                return size_t{1};
            });
        }
    }
}

void run_storage(const Config& c) {
    const std::string dir = c.output_dir + "/E4";
    std::filesystem::create_directories(dir);
    CsvWriter raw(dir + "/raw.csv");
    raw.header({"scheme", "N", "client_keys_bytes", "client_aux_bytes",
        "client_total_state_bytes", "owner_total_state_bytes",
        "owner_counter_plane_bytes", "owner_token_state_bytes",
        "snapshot_bytes", "delta_log_bytes",
        "verification_metadata_bytes", "encrypted_records_bytes",
        "server_index_bytes", "total_managed_bytes", "xset_bytes", "tset_bytes",
        "cms_bytes", "padded_slots", "run_id", "seed"});
    for (size_t n : c.scales) {
        auto docs = load_docs(c, n);
        {
            SliceBF s;
            s.build(docs);
            raw.row("SliceBF", n, SliceBF::search_seed_bytes(),
                s.client_capsule_bytes(), s.client_state_bytes(),
                s.owner_state_bytes(), s.owner_counter_plane_bytes(),
                s.owner_token_state_bytes(), s.snapshot_bytes(),
                s.delta_log_bytes(), s.metadata_bytes(),
                s.encrypted_records_bytes(), s.server_storage_bytes(),
                s.owner_state_bytes() + s.client_state_bytes() +
                    s.server_storage_bytes(),
                0, 0, 0, s.padded_slots(), c.run_id, c.seed);
        }
    }
}

bool contains_id(const std::vector<std::string>& ids, const std::string& id) {
    return std::find(ids.begin(), ids.end(), id) != ids.end();
}

void write_update_row(CsvWriter& raw, const Config& c, size_t n,
                      int iteration, const std::string& operation,
                      const Document& doc, const UpdatePrepareStats& prep,
                      double server_ms, bool accepted, bool checked, bool correct,
                      const CompactionStats& compaction, size_t updates_since_compact,
                      size_t delta_records_before_compaction,
                      uint32_t max_chain_before_compaction,
                      uint32_t chain_threshold) {
    const double amortized = compaction.ms_total > 0
        ? compaction.ms_total / std::max<size_t>(1, updates_since_compact) : 0;
    raw.row(operation, c.run_id, iteration, "SliceBF", n, doc.tokens.size(),
        prep.ms_token_generation, prep.ms_client_crypto, server_ms,
        prep.ms_total + server_ms, prep.token_bytes, prep.real_delta_records,
        prep.padded_delta_records, accepted ? 1 : 0, checked ? 1 : 0,
        correct ? 1 : 0, compaction.ms_total, amortized,
        compaction.removed_delta_records, delta_records_before_compaction,
        max_chain_before_compaction, chain_threshold,
        compaction.ms_total > 0 ? 1 : 0, c.seed);
}

void run_updates(const Config& c) {
    const std::string dir = c.output_dir + "/E7";
    std::filesystem::create_directories(dir);
    CsvWriter raw(dir + "/raw.csv");
    raw.header({"operation", "run_id", "cycle", "scheme", "N", "keywords",
        "token_generation_ms", "client_crypto_ms", "server_apply_ms", "total_ms",
        "token_bytes", "real_delta_records", "padded_delta_records", "accepted",
        "correctness_checked", "correct", "compaction_ms",
        "amortized_compaction_ms", "removed_delta_records",
        "delta_records_before_compaction", "max_chain_before_compaction",
        "chain_threshold", "compaction_triggered", "seed"});
    SummaryWriter summary(dir + "/summary.csv");

    for (size_t n : c.scales) {
        auto docs = load_docs(c, n);
        SliceBF scheme;
        scheme.build(docs);
        std::vector<double> add_times, delete_times;
        std::vector<double> amortized_compaction_times;
        size_t since_compaction = 0;

        for (int iteration = 0; iteration < c.update_cycles; ++iteration) {
            const Document& doc = docs[static_cast<size_t>(iteration) % docs.size()];
            const bool check = c.correctness_interval > 0 &&
                               iteration % c.correctness_interval == 0 &&
                               !doc.tokens.empty();

            UpdatePrepareStats del_prep;
            auto del = scheme.remove(doc.id, &del_prep);
            bool del_accepted = false;
            const double del_server = timed_ms([&] {
                del_accepted = scheme.verify_token(del);
            });
            ++since_compaction;
            bool del_correct = del_accepted;
            if (check) del_correct = del_correct &&
                !contains_id(scheme.search({doc.tokens.front()}), doc.id);
            CompactionStats del_compaction;
            size_t del_amortization_window = since_compaction;
            const size_t del_log_records = scheme.delta_log_records();
            const uint32_t del_max_chain = scheme.max_chain_length();
            if (scheme.needs_compaction()) {
                del_compaction = scheme.compact();
                amortized_compaction_times.push_back(
                    del_compaction.ms_total /
                    std::max<size_t>(1, del_amortization_window));
                since_compaction = 0;
            }
            write_update_row(raw, c, n, iteration, "delete", doc, del_prep,
                del_server, del_accepted, check, del_correct, del_compaction,
                del_amortization_window, del_log_records, del_max_chain,
                scheme.params().chain_threshold);
            delete_times.push_back(del_prep.ms_total + del_server);

            UpdatePrepareStats add_prep;
            auto add = scheme.insert(doc, &add_prep);
            bool add_accepted = false;
            const double add_server = timed_ms([&] {
                add_accepted = scheme.verify_token(add);
            });
            ++since_compaction;
            bool add_correct = add_accepted;
            if (check) add_correct = add_correct &&
                contains_id(scheme.search({doc.tokens.front()}), doc.id);
            CompactionStats add_compaction;
            size_t add_amortization_window = since_compaction;
            const size_t add_log_records = scheme.delta_log_records();
            const uint32_t add_max_chain = scheme.max_chain_length();
            if (scheme.needs_compaction()) {
                add_compaction = scheme.compact();
                amortized_compaction_times.push_back(
                    add_compaction.ms_total /
                    std::max<size_t>(1, add_amortization_window));
                since_compaction = 0;
            }
            write_update_row(raw, c, n, iteration, "insert", doc, add_prep,
                add_server, add_accepted, check, add_correct, add_compaction,
                add_amortization_window, add_log_records, add_max_chain,
                scheme.params().chain_threshold);
            add_times.push_back(add_prep.ms_total + add_server);
        }
        summary.write("E7", "SliceBF", n, 0, "all", "insert_ms",
                      Stats::from(add_times), "L=512", "B=64");
        summary.write("E7", "SliceBF", n, 0, "all", "delete_ms",
                      Stats::from(delete_times), "L=512", "B=64");
        if (!amortized_compaction_times.empty())
            summary.write("E7", "SliceBF", n, 0, "all",
                          "amortized_compaction_ms",
                          Stats::from(amortized_compaction_times),
                          "event_intervals", "L=512");
    }
}

void run_first_after_update(const Config& c) {
    const std::string dir = c.output_dir + "/E8";
    std::filesystem::create_directories(dir);
    CsvWriter raw(dir + "/raw.csv");
    raw.header({"experiment", "run_id", "cycle", "scheme", "scenario",
        "operation", "N", "q", "document_id", "keywords",
        "batch_update_ms", "first_query_ms", "migrated_updates",
        "result_size", "correct", "seed"});
    SummaryWriter summary(dir + "/summary.csv");
    CsvWriter host(dir + "/host.csv");
    host.header({"experiment", "scheme", "N", "q", "run_id",
        "calibration_before_ms", "calibration_after_ms",
        "calibration_ratio", "logical_cpu_before", "logical_cpu_after"});

    for (size_t n : c.scales) {
        auto docs = load_docs(c, n);
        std::vector<const Document*> eligible;
        eligible.reserve(docs.size());
        for (const auto& document : docs)
            if (document.tokens.size() >= 3) eligible.push_back(&document);
        if (eligible.empty())
            throw std::runtime_error("E8 requires documents with at least 3 keywords");

        const size_t cycles = std::min<size_t>(
            static_cast<size_t>(std::max(0, c.update_cycles)), eligible.size());

        {
            const int cpu_before = current_logical_cpu();
            const double calibration_before = host_calibration_ms();
            SliceBF scheme;
            scheme.build(docs);
            std::vector<double> delete_updates, insert_updates;
            std::vector<double> delete_queries, insert_queries;
            for (size_t cycle = 0; cycle < cycles; ++cycle) {
                const auto& document = *eligible[cycle];
                const std::vector<std::string> query(
                    document.tokens.begin(), document.tokens.begin() + 3);

                UpdatePrepareStats delete_prepare;
                auto delete_token = scheme.remove(document.id, &delete_prepare);
                bool delete_accepted = false;
                const double delete_server = timed_ms([&] {
                    delete_accepted = scheme.verify_token(delete_token);
                });
                sbf::SearchStats delete_search;
                const auto delete_result = scheme.search(query, &delete_search);
                const bool delete_correct = delete_accepted &&
                    !contains_id(delete_result, document.id);
                const double delete_batch = delete_prepare.ms_total + delete_server;
                raw.row("E8", c.run_id, cycle, "SliceBF",
                    "first_after_update", "delete", n, query.size(), document.id,
                    document.tokens.size(), delete_batch, delete_search.ms_total,
                    delete_search.delta_records, delete_result.size(),
                    delete_correct ? 1 : 0, c.seed);
                if (!delete_correct)
                    throw std::runtime_error("SliceBF E8 deletion check failed");
                delete_updates.push_back(delete_batch);
                delete_queries.push_back(delete_search.ms_total);

                UpdatePrepareStats insert_prepare;
                auto insert_token = scheme.insert(document, &insert_prepare);
                bool insert_accepted = false;
                const double insert_server = timed_ms([&] {
                    insert_accepted = scheme.verify_token(insert_token);
                });
                sbf::SearchStats insert_search;
                const auto insert_result = scheme.search(query, &insert_search);
                const bool insert_correct = insert_accepted &&
                    contains_id(insert_result, document.id);
                const double insert_batch = insert_prepare.ms_total + insert_server;
                raw.row("E8", c.run_id, cycle, "SliceBF",
                    "first_after_update", "insert", n, query.size(), document.id,
                    document.tokens.size(), insert_batch, insert_search.ms_total,
                    insert_search.delta_records, insert_result.size(),
                    insert_correct ? 1 : 0, c.seed);
                if (!insert_correct)
                    throw std::runtime_error("SliceBF E8 insertion check failed");
                insert_updates.push_back(insert_batch);
                insert_queries.push_back(insert_search.ms_total);
            }
            summary.write("E8", "SliceBF", n, 3, "delete",
                "batch_update_ms", Stats::from(delete_updates),
                "scenario=first_after_update");
            summary.write("E8", "SliceBF", n, 3, "delete",
                "first_query_ms", Stats::from(delete_queries),
                "scenario=first_after_update");
            summary.write("E8", "SliceBF", n, 3, "insert",
                "batch_update_ms", Stats::from(insert_updates),
                "scenario=first_after_update");
            summary.write("E8", "SliceBF", n, 3, "insert",
                "first_query_ms", Stats::from(insert_queries),
                "scenario=first_after_update");
            const double calibration_after = host_calibration_ms();
            const int cpu_after = current_logical_cpu();
            host.row("E8", "SliceBF", n, 3, c.run_id,
                calibration_before, calibration_after,
                calibration_after / std::max(1e-12, calibration_before),
                cpu_before, cpu_after);
        }

    }
}

void print_list() {
    std::cout << "E1  query latency vs N (q=3)\n"
              << "E2  query latency vs q (full scale; includes breakdown/communication)\n"
              << "E3  secure setup time\n"
              << "E4  owner/client/server storage breakdown\n"
              << "E7  SliceBF sparse update and compaction cost\n"
              << "E8  SliceBF first query after document updates\n";
}

}  // namespace

int main(int argc, char** argv) {
    try {
        Config c;
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--exp" && i + 1 < argc) c.experiment = argv[++i];
            else if (arg == "--all") c.experiment = "all";
            else if (arg == "--corpus-dir" && i + 1 < argc) c.corpus_dir = argv[++i];
            else if (arg == "--query-dir" && i + 1 < argc) c.query_dir = argv[++i];
            else if (arg == "--output-dir" && i + 1 < argc) c.output_dir = argv[++i];
            else if (arg == "--repetitions" && i + 1 < argc)
                c.repetitions = std::stoi(argv[++i]);
            else if (arg == "--run-id" && i + 1 < argc)
                c.run_id = std::stoi(argv[++i]);
            else if (arg == "--warmup" && i + 1 < argc)
                c.warmup = std::stoi(argv[++i]);
            else if (arg == "--update-cycles" && i + 1 < argc)
                c.update_cycles = std::stoi(argv[++i]);
            else if (arg == "--correctness-interval" && i + 1 < argc)
                c.correctness_interval = std::stoi(argv[++i]);
            else if (arg == "--seed" && i + 1 < argc)
                c.seed = std::stoull(argv[++i]);
            else if (arg == "--slicebf-variant" && i + 1 < argc) {
                c.slicebf_variant = argv[++i];
                if (c.slicebf_variant != "full" &&
                    c.slicebf_variant != "no-mask" &&
                    c.slicebf_variant != "no-bit-slice" &&
                    c.slicebf_variant != "no-pruning") {
                    throw std::invalid_argument(
                        "--slicebf-variant must be full, no-mask, "
                        "no-bit-slice, or no-pruning");
                }
            }
            else if (arg == "--scales" && i + 1 < argc) {
                c.scales.clear();
                std::stringstream ss(argv[++i]);
                std::string item;
                while (std::getline(ss, item, ',')) c.scales.push_back(std::stoull(item));
            }
            else if (arg == "--arities" && i + 1 < argc) {
                c.arities.clear();
                std::stringstream ss(argv[++i]);
                std::string item;
                while (std::getline(ss, item, ',')) {
                    const int q = std::stoi(item);
                    if (q < 2 || q > 5)
                        throw std::invalid_argument("--arities values must be 2..5");
                    c.arities.push_back(q);
                }
                if (c.arities.empty())
                    throw std::invalid_argument("--arities must not be empty");
            } else if (arg == "--list") {
                print_list();
                return 0;
            } else {
                throw std::invalid_argument("unknown argument: " + arg);
            }
        }

        std::filesystem::create_directories(c.output_dir);
        const bool all = c.experiment == "all";
        if (all || c.experiment == "E1") run_search(c, true);
        if (all || c.experiment == "E2") run_search(c, false);
        if (all || c.experiment == "E3") run_setup(c);
        if (all || c.experiment == "E4") run_storage(c);
        if (all || c.experiment == "E7") run_updates(c);
        if (all || c.experiment == "E8") run_first_after_update(c);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "experiment runner failed: " << e.what() << '\n';
        return 1;
    }
}
