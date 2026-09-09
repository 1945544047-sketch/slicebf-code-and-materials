// corpus.hpp — loaders for the frozen preprocessed data assets.
#pragma once
#include <string>
#include <vector>

namespace sbf {

struct Document {
    std::string id;                 // original award id, e.g. "9003139"
    std::vector<std::string> tokens;  // stemmed keyword set W_i
};

// The frozen experimental corpus is canonical: document identifiers are
// unique, and every token vector is a sorted set.  Scheme implementations also
// call the uniqueness validator so a non-canonical caller cannot inflate only
// one index with repeated (document, keyword) pairs.
bool has_unique_tokens(const Document& document);
bool has_canonical_tokens(const Document& document);
void validate_documents(const std::vector<Document>& documents,
                        bool require_sorted_tokens = false);

// One conjunctive query with its plaintext-oracle answer.
struct OracleQuery {
    std::string query_id;
    std::string bucket;             // rare / medium / common
    int q = 0;
    std::vector<std::string> terms;
    std::vector<std::string> result_ids;  // ground-truth conjunctive result
};

// Load corpus_N*.jsonl (one JSON object per line; uses id + tokens fields).
std::vector<Document> load_corpus(const std::string& path);

// Load queries/oracle_results.json -> map key "q2".."q5" flattened into a
// single vector, each carrying its q group. Order preserved.
std::vector<OracleQuery> load_oracle(const std::string& path);

}  // namespace sbf
