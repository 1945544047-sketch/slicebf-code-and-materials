// Full-scale correctness admission gate for the protected SliceBF protocol.
// Expected answers are recomputed from the selected corpus; no legacy oracle
// result IDs are trusted.
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "corpus.hpp"
#include "json.hpp"
#include "slicebf.hpp"

using namespace sbf;
using nlohmann::json;

namespace {

struct Query {
    std::string id;
    std::string bucket;
    int q = 0;
    std::vector<std::string> terms;
};

std::vector<Query> load_queries(const std::string& dir) {
    std::vector<Query> out;
    for (int q = 2; q <= 5; ++q) {
        const std::string path = dir + "/q" + std::to_string(q) + "_80.jsonl";
        std::ifstream in(path);
        if (!in) throw std::runtime_error("cannot open query file: " + path);
        std::string line;
        while (std::getline(in, line)) {
            if (line.empty()) continue;
            auto j = json::parse(line);
            Query query{j.value("query_id", std::string{}),
                        j.value("bucket", std::string{}),
                        j.value("q", q),
                        j.at("terms").get<std::vector<std::string>>()};
            std::unordered_set<std::string> distinct(query.terms.begin(),
                                                     query.terms.end());
            if (query.id.empty() || query.q != q || query.terms.empty() ||
                distinct.size() != query.terms.size())
                throw std::runtime_error("invalid frozen query: " + query.id);
            out.push_back(std::move(query));
        }
    }
    return out;
}

class PlainOracle {
public:
    PlainOracle(const std::vector<Document>& docs,
                const std::vector<Query>& queries) : docs_(docs) {
        std::unordered_set<std::string> needed;
        for (const auto& query : queries)
            needed.insert(query.terms.begin(), query.terms.end());
        postings_.reserve(needed.size() * 2);
        for (uint32_t i = 0; i < docs.size(); ++i) {
            std::unordered_set<std::string> seen;
            for (const auto& term : docs[i].tokens) {
                if (needed.count(term) && seen.insert(term).second)
                    postings_[term].push_back(i);
            }
        }
    }

    std::set<std::string> answer(const Query& query) const {
        std::vector<uint32_t> current;
        bool first = true;
        for (const auto& term : query.terms) {
            auto it = postings_.find(term);
            if (it == postings_.end()) return {};
            if (first) {
                current = it->second;
                first = false;
            } else {
                std::vector<uint32_t> next;
                std::set_intersection(current.begin(), current.end(),
                                      it->second.begin(), it->second.end(),
                                      std::back_inserter(next));
                current.swap(next);
            }
            if (current.empty()) break;
        }
        std::set<std::string> ids;
        for (uint32_t index : current) ids.insert(docs_[index].id);
        return ids;
    }

private:
    const std::vector<Document>& docs_;
    std::unordered_map<std::string, std::vector<uint32_t>> postings_;
};

}  // namespace

int main(int argc, char** argv) {
    try {
        const std::string corpus_path = argc > 1 ? argv[1]
            : "data/processed_300k_v2/corpus_N300000.jsonl";
        const std::string query_dir = argc > 2 ? argv[2]
            : "data/processed_300k_v2/queries";

        std::cerr << "[E9] loading final corpus: " << corpus_path << "\n";
        auto docs = load_corpus(corpus_path);
        auto queries = load_queries(query_dir);
        PlainOracle oracle(docs, queries);

        std::cerr << "[E9] building protected SliceBF (m=8192,k=4,b=4,B=64)...\n";
        SliceBF scheme;
        scheme.build(docs);

        size_t passed = 0, false_positive = 0, false_negative = 0;
        size_t candidates = 0, returned_slots = 0;
        for (const auto& query : queries) {
            SearchStats stats;
            auto result = scheme.search(query.terms, &stats);
            const std::set<std::string> got(result.begin(), result.end());
            const auto wanted = oracle.answer(query);
            size_t fp = result.size() == got.size() ? 0 : result.size() - got.size();
            size_t fn = 0;
            for (const auto& id : got) if (!wanted.count(id)) ++fp;
            for (const auto& id : wanted) if (!got.count(id)) ++fn;
            false_positive += fp;
            false_negative += fn;
            candidates += stats.candidate_count;
            returned_slots += stats.returned_bucket_slots;
            if (fp == 0 && fn == 0) {
                ++passed;
            } else {
                std::cout << "MISMATCH q=" << query.q << " id=" << query.id
                          << " bucket=" << query.bucket << " got=" << got.size()
                          << " wanted=" << wanted.size() << " fp=" << fp
                          << " fn=" << fn << "\n";
            }
        }

        SearchStats absent_stats;
        const bool absent_ok = scheme.search(
            {"__slicebf_absent_term_20260714__"}, &absent_stats).empty();
        const bool ok = passed == queries.size() && false_positive == 0 &&
                        false_negative == 0 && absent_ok;

        std::cout << "\n================ E9 FINAL CORRECTNESS ================\n"
                  << "documents       : " << docs.size() << "\n"
                  << "queries         : " << queries.size() << "\n"
                  << "passed          : " << passed << "\n"
                  << "false positives : " << false_positive << "\n"
                  << "false negatives : " << false_negative << "\n"
                  << "absent-term test: " << (absent_ok ? "PASS" : "FAIL") << "\n"
                  << "avg candidates  : "
                  << (queries.empty() ? 0.0 : double(candidates) / queries.size())
                  << "\n"
                  << "avg bucket slots: "
                  << (queries.empty() ? 0.0 : double(returned_slots) / queries.size())
                  << "\nRESULT           : "
                  << (ok ? "PASS (precision=recall=1)" : "FAIL")
                  << "\n======================================================\n";
        return ok ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "E9 correctness failed: " << e.what() << "\n";
        return 1;
    }
}
