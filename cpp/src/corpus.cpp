#include "corpus.hpp"

#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <unordered_set>

#include "json.hpp"

using nlohmann::json;

namespace sbf {

bool has_unique_tokens(const Document& document) {
    std::unordered_set<std::string> seen;
    seen.reserve(document.tokens.size() * 2);
    for (const auto& token : document.tokens) {
        if (token.empty() || !seen.insert(token).second) return false;
    }
    return true;
}

bool has_canonical_tokens(const Document& document) {
    return has_unique_tokens(document) &&
           std::is_sorted(document.tokens.begin(), document.tokens.end());
}

void validate_documents(const std::vector<Document>& documents,
                        bool require_sorted_tokens) {
    std::unordered_set<std::string> ids;
    ids.reserve(documents.size() * 2);
    for (const auto& document : documents) {
        if (document.id.empty())
            throw std::invalid_argument("empty document identifier");
        if (!ids.insert(document.id).second)
            throw std::invalid_argument("duplicate document identifier: " +
                                        document.id);
        const bool valid = require_sorted_tokens
            ? has_canonical_tokens(document) : has_unique_tokens(document);
        if (!valid)
            throw std::invalid_argument(
                "document tokens are not a canonical keyword set: " +
                document.id);
    }
}

std::vector<Document> load_corpus(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open corpus: " + path);
    std::vector<Document> docs;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        json j = json::parse(line);
        Document d;
        d.id = j.at("id").get<std::string>();
        d.tokens = j.at("tokens").get<std::vector<std::string>>();
        docs.push_back(std::move(d));
    }
    validate_documents(docs, true);
    return docs;
}

std::vector<OracleQuery> load_oracle(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open oracle: " + path);
    json root = json::parse(in);
    std::vector<OracleQuery> out;
    for (const char* key : {"q2", "q3", "q4", "q5"}) {
        if (!root.contains(key)) continue;
        for (const auto& e : root[key]) {
            OracleQuery oq;
            oq.query_id = e.value("query_id", std::string{});
            oq.bucket = e.value("bucket", std::string{});
            oq.q = e.value("q", 0);
            oq.terms = e.at("terms").get<std::vector<std::string>>();
            oq.result_ids = e.at("result_ids").get<std::vector<std::string>>();
            out.push_back(std::move(oq));
        }
    }
    return out;
}

}  // namespace sbf
