// dyn_correctness.cpp — SliceBF dynamic update correctness (checklist §2.1, E8).
// Verifies insert / delete / re-insert against a plaintext oracle maintained in
// lockstep, plus update-token authentication.
#include <iostream>
#include <set>
#include <unordered_map>

#include "corpus.hpp"
#include "slicebf.hpp"

using namespace sbf;

static std::set<std::string> plain_search(
    const std::unordered_map<std::string, std::set<std::string>>& live,
    const std::vector<std::string>& q) {
    std::set<std::string> r;
    for (const auto& kv : live) {
        bool all = true;
        for (const auto& w : q) if (!kv.second.count(w)) { all = false; break; }
        if (all) r.insert(kv.first);
    }
    return r;
}

int main(int argc, char** argv) {
    const std::string corpus = argc > 1 ? argv[1]
        : "data/processed_300k_v2/corpus_N50000.jsonl";
    const std::string oracle_path = argc > 2 ? argv[2]
        : "data/processed_300k_v2/queries/oracle_results.json";
    const size_t max_docs = argc > 3
        ? static_cast<size_t>(std::stoull(argv[3])) : 50000;
    auto docs = load_corpus(corpus);
    if (docs.size() > max_docs) docs.resize(max_docs);
    std::cerr << "[dyn] corpus docs = " << docs.size() << "\n";
    if (docs.size() < 2) { std::cerr << "corpus too small\n"; return 1; }

    // Security-state checks: token tampering, replay, ordering, duplicate IDs,
    // absent deletion, and collision-heavy delete/reinsert behavior.
    {
        SliceBF auth;
        // Pre-provision three size classes before creating simultaneous pending
        // updates.  Dense corpora such as Enron can otherwise make the ordering
        // test trigger an unrelated capacity rebuild while a token is pending.
        Document auth_a{"auth-a", {"a1", "a2", "a3", "a4"}};
        Document auth_b{"auth-b", {"b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8"}};
        Document auth_c{"auth-c", {"c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8",
                                     "c9", "c10", "c11", "c12", "c13", "c14", "c15", "c16"}};
        auth.build({auth_a, auth_b, auth_c});
        for (const auto& seed : {auth_a, auth_b, auth_c}) {
            auto removed = auth.remove(seed.id, nullptr);
            if (!auth.verify_token(removed)) return 1;
        }
        auto first = auth.insert(auth_a, nullptr);
        auto tampered = first;
        if (tampered.records.empty() || tampered.records[0].ciphertext.empty())
            return 1;
        tampered.records[0].ciphertext[0] ^= 0x01;
        if (auth.verify_token(tampered)) { std::cerr << "TAMPER ACCEPTED\n"; return 1; }
        if (!auth.verify_token(first)) { std::cerr << "VALID TOKEN REJECTED\n"; return 1; }
        if (auth.verify_token(first)) { std::cerr << "REPLAY ACCEPTED\n"; return 1; }
        auto second = auth.insert(auth_b, nullptr);
        auto third = auth.insert(auth_c, nullptr);
        if (auth.verify_token(third)) { std::cerr << "OUT-OF-ORDER ACCEPTED\n"; return 1; }
        if (!auth.verify_token(second) || !auth.verify_token(third)) {
            std::cerr << "ORDERED TOKENS REJECTED\n"; return 1;
        }
        bool duplicate_rejected = false;
        try { auth.insert(auth_a, nullptr); } catch (const std::invalid_argument&) {
            duplicate_rejected = true;
        }
        if (!duplicate_rejected) { std::cerr << "DUPLICATE ID ACCEPTED\n"; return 1; }
        bool absent_delete_rejected = false;
        try { auth.remove("__absent__", nullptr); } catch (const std::invalid_argument&) {
            absent_delete_rejected = true;
        }
        if (!absent_delete_rejected) { std::cerr << "ABSENT DELETE ACCEPTED\n"; return 1; }
    }
    {
        Params small; small.m = 8; small.k = 4;
        SliceBF collisions(small);
        Document a{"collision-a", {"alpha", "beta", "gamma", "delta"}};
        Document b{"collision-b", {"alpha", "epsilon"}};
        auto ta = collisions.insert(a, nullptr); if (!collisions.verify_token(ta)) return 1;
        auto tb = collisions.insert(b, nullptr); if (!collisions.verify_token(tb)) return 1;
        auto td = collisions.remove(a.id, nullptr); if (!collisions.verify_token(td)) return 1;
        auto got = collisions.search({"alpha"});
        if (got.size() != 1 || got[0] != b.id) {
            std::cerr << "COLLISION DELETE CORRUPTED SURVIVOR\n"; return 1;
        }
        auto tr = collisions.insert(a, nullptr); if (!collisions.verify_token(tr)) return 1;
        got = collisions.search({"alpha"});
        if (std::set<std::string>(got.begin(), got.end()).size() != 2) {
            std::cerr << "REINSERT VERSION FAILURE\n"; return 1;
        }
    }

    SliceBF scheme;
    std::unordered_map<std::string, std::set<std::string>> live;  // plaintext oracle
    std::unordered_map<std::string, Document> by_id;

    size_t half = docs.size() / 2;
    // Phase 1: materialize a protected snapshot from the first half.
    std::vector<Document> initial(docs.begin(), docs.begin() + half);
    scheme.build(initial);
    for (size_t i = 0; i < half; ++i) {
        live[docs[i].id] = {docs[i].tokens.begin(), docs[i].tokens.end()};
        by_id[docs[i].id] = docs[i];
    }
    // Phase 2: delete every 3rd inserted doc.
    size_t deleted = 0;
    for (size_t i = 0; i < half; i += 3) {
        auto t = scheme.remove(docs[i].id, nullptr);
        if (!scheme.verify_token(t)) { std::cerr << "TOKEN FAIL delete\n"; return 1; }
        live.erase(docs[i].id);
        ++deleted;
    }
    // Phase 3: insert second half.
    for (size_t i = half; i < docs.size(); ++i) {
        auto t = scheme.insert(docs[i], nullptr);
        if (!scheme.verify_token(t)) { std::cerr << "TOKEN FAIL insert\n"; return 1; }
        live[docs[i].id] = {docs[i].tokens.begin(), docs[i].tokens.end()};
        by_id[docs[i].id] = docs[i];
    }
    // Phase 4: re-insert some previously deleted docs.
    size_t reins = 0;
    for (size_t i = 0; i < half && reins < deleted / 2; i += 3, ++reins) {
        auto t = scheme.insert(docs[i], nullptr);
        if (!scheme.verify_token(t)) { std::cerr << "TOKEN FAIL reinsert\n"; return 1; }
        live[docs[i].id] = {docs[i].tokens.begin(), docs[i].tokens.end()};
    }

    // Phase 5: keyword-level replacements keep the public size class fixed but
    // exercise multiplicity-aware 0 <-> 1 transitions in the counter plane.
    std::vector<std::string> modify_ids;
    for (const auto& kv : live) {
        if (!kv.second.empty()) modify_ids.push_back(kv.first);
        if (modify_ids.size() == 64) break;
    }
    size_t modified = 0;
    for (const auto& id : modify_ids) {
        const std::string removed = *live[id].begin();
        const std::string added = "__dynamic_keyword_" + std::to_string(modified);
        auto t = scheme.modify_keywords(id, {added}, {removed}, nullptr);
        if (!scheme.verify_token(t)) {
            std::cerr << "TOKEN FAIL keyword modify\n";
            return 1;
        }
        live[id].erase(removed);
        live[id].insert(added);
        ++modified;
    }
    if (!modify_ids.empty()) {
        auto got = scheme.search({"__dynamic_keyword_0"});
        if (got.size() != 1 || got[0] != modify_ids[0]) {
            std::cerr << "KEYWORD MODIFY QUERY FAILURE\n";
            return 1;
        }
    }

    std::cerr << "[dyn] live=" << scheme.live_docs() << " (oracle=" << live.size()
              << ") deleted=" << deleted << " reinserted=" << reins
              << " modified=" << modified << "\n";

    // Correctness: run every oracle query on the mutated index.
    auto queries = load_oracle(oracle_path);
    size_t total = 0, passed = 0, fp = 0, fn = 0;
    for (const auto& oq : queries) {
        auto got_v = scheme.search(oq.terms);
        std::set<std::string> got(got_v.begin(), got_v.end());
        auto want = plain_search(live, oq.terms);
        ++total;
        size_t lfp = 0, lfn = 0;
        for (auto& id : got) if (!want.count(id)) ++lfp;
        for (auto& id : want) if (!got.count(id)) ++lfn;
        if (lfp == 0 && lfn == 0) ++passed; else { fp += lfp; fn += lfn; }
    }
    std::cout << "\n=========== DYNAMIC CORRECTNESS ===========\n";
    std::cout << "queries: " << total << "  passed: " << passed
              << "  fp: " << fp << "  fn: " << fn << "\n";
    bool ok = (passed == total && fp == 0 && fn == 0);
    std::cout << "RESULT : " << (ok ? "PASS" : "FAIL") << "\n";
    std::cout << "===========================================\n";
    if (!ok) return 1;

    // Compaction must rotate the generation, remove the delta log, and retain
    // exact results after labels, masks, aliases, and chain heads are refreshed.
    auto compaction = scheme.compact();
    if (compaction.new_generation != compaction.old_generation + 1 ||
        compaction.removed_delta_records == 0) {
        std::cerr << "COMPACTION STATE FAILURE\n";
        return 1;
    }
    for (const auto& oq : queries) {
        auto got_v = scheme.search(oq.terms);
        std::set<std::string> got(got_v.begin(), got_v.end());
        if (got != plain_search(live, oq.terms)) {
            std::cerr << "COMPACTION CORRECTNESS FAILURE\n";
            return 1;
        }
    }
    std::cout << "COMPACTION : PASS (generation " << compaction.old_generation
              << " -> " << compaction.new_generation << ")\n";
    return 0;
}
