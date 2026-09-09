#include "slicebf.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <limits>
#include <set>
#include <stdexcept>
#include <unordered_set>

namespace sbf {
namespace {

using Clock = std::chrono::high_resolution_clock;
using Ms = std::chrono::duration<double, std::milli>;

void put16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v));
}

void put32(std::vector<uint8_t>& out, uint32_t v) {
    for (int s = 24; s >= 0; s -= 8) out.push_back(static_cast<uint8_t>(v >> s));
}

void put64(std::vector<uint8_t>& out, uint64_t v) {
    for (int s = 56; s >= 0; s -= 8) out.push_back(static_cast<uint8_t>(v >> s));
}

uint16_t get16(const uint8_t* p) {
    return static_cast<uint16_t>((uint16_t(p[0]) << 8) | uint16_t(p[1]));
}

uint32_t get32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

uint64_t get64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

uint64_t first64(const std::array<uint8_t, 32>& x) {
    return get64(x.data());
}

template <class T>
void cryptographic_shuffle(std::vector<T>& values) {
    for (size_t remaining = values.size(); remaining > 1; --remaining) {
        const uint64_t bound = static_cast<uint64_t>(remaining);
        const uint64_t threshold = (uint64_t(0) - bound) % bound;
        uint64_t sample = 0;
        do {
            sample = first64(random_key());
        } while (sample < threshold);
        std::swap(values[remaining - 1], values[sample % bound]);
    }
}

uint32_t ceil_pow2(uint32_t v) {
    if (v <= 1) return 1;
    --v;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    if (v == std::numeric_limits<uint32_t>::max())
        throw std::overflow_error("size class overflow");
    return v + 1;
}

uint32_t round_up(uint32_t v, uint32_t unit) {
    if (!unit) throw std::invalid_argument("rounding unit is zero");
    return ((v + unit - 1) / unit) * unit;
}

Key16 first16(const Key32& k) {
    Key16 out{};
    std::copy_n(k.begin(), out.size(), out.begin());
    return out;
}

std::string bytes(const std::array<uint8_t, 32>& x) {
    return std::string(reinterpret_cast<const char*>(x.data()), x.size());
}

std::array<uint8_t, 32> keyed_state_prf(const Key32& key,
                                        const std::string& domain,
                                        const Key32& state) {
    std::string message = domain;
    message.append(reinterpret_cast<const char*>(state.data()), state.size());
    return prf(key, message);
}

std::array<uint8_t, 16> exact_tag(const Key32& key, const std::string& word) {
    auto h = prf(key, "verify|" + word);
    std::array<uint8_t, 16> out{};
    std::copy_n(h.begin(), out.size(), out.begin());
    return out;
}

std::vector<std::string> unique_terms(const std::vector<std::string>& tokens) {
    std::set<std::string> s(tokens.begin(), tokens.end());
    return {s.begin(), s.end()};
}

bool same_alias(const std::array<uint8_t, 16>& a,
                const std::array<uint8_t, 16>& b) {
    return std::equal(a.begin(), a.end(), b.begin());
}

}  // namespace

size_t UpdateToken::logical_bytes() const {
    size_t total = 1 + 8 + 8 + 8 + 4 + 8 + 32;
    for (const auto& rec : records)
        total += rec.address.size() + rec.link.size() + 8 + rec.ciphertext.size();
    total += 8 + tuple.metadata.size() + tuple.record.size();
    return total;
}

SliceBF::SliceBF(Params p) : p_(p) {
    if (p_.lane_bits != 4 || p_.max_group == 0 || p_.max_group > 15)
        throw std::invalid_argument("SliceBF requires b=4 and 1 <= G <= 15");
    if (!p_.m || !p_.k || p_.k > p_.m || !p_.bucket_size)
        throw std::invalid_argument("invalid SliceBF parameters");
    setup();
}

void SliceBF::setup() {
    master_ = random_key();
    k_doc_root_ = hkdf_sha256(master_, "SliceBF/document-encryption");
    k_upd_ = hkdf_sha256(master_, "SliceBF/update-authentication");
    k_doc_ = first16(k_doc_root_);
    derive_generation_keys();
}

void SliceBF::derive_generation_keys() {
    const std::string g = std::to_string(generation_);
    k_search_ = hkdf_sha256(master_, "SliceBF/generation/" + g + "/search-seed");
    k_pos_ = hkdf_sha256(k_search_, "SliceBF/" + g + "/pos");
    k_label_ = hkdf_sha256(k_search_, "SliceBF/" + g + "/label");
    k_pad_ = hkdf_sha256(k_search_, "SliceBF/" + g + "/pad");
    k_walk_ = hkdf_sha256(k_search_, "SliceBF/" + g + "/walk");
    k_delta_root_ = hkdf_sha256(k_search_, "SliceBF/" + g + "/delta");
    k_bucket_ = hkdf_sha256(k_search_, "SliceBF/" + g + "/bucket");
    k_meta_root_ = hkdf_sha256(k_search_, "SliceBF/" + g + "/meta");
    k_ver_ = hkdf_sha256(k_search_, "SliceBF/" + g + "/verify");
    k_delta_ = first16(k_delta_root_);
    k_meta_ = first16(k_meta_root_);
}

std::vector<uint32_t> SliceBF::positions(const std::string& word) const {
    std::vector<uint32_t> out;
    out.reserve(p_.k);
    std::unordered_set<uint32_t> seen;
    for (uint32_t counter = 0; out.size() < p_.k; ++counter) {
        auto h = prf(k_pos_, "pos|" + word + "|" + std::to_string(counter));
        uint32_t p = get32(h.data()) % p_.m;
        if (seen.insert(p).second) out.push_back(p);
        if (counter > p_.m * 8)
            throw std::runtime_error("unable to derive distinct CBF positions");
    }
    return out;
}

std::vector<SliceBF::CounterEntry> SliceBF::support_for(
    const std::vector<std::string>& tokens) const {
    std::unordered_map<uint32_t, uint32_t> counts;
    for (const auto& word : unique_terms(tokens))
        for (uint32_t p : positions(word)) ++counts[p];

    std::vector<CounterEntry> out;
    out.reserve(counts.size());
    for (const auto& kv : counts) {
        if (kv.second > std::numeric_limits<uint16_t>::max())
            throw std::overflow_error("CBF multiplicity exceeds uint16_t");
        out.push_back({kv.first, static_cast<uint16_t>(kv.second)});
    }
    std::sort(out.begin(), out.end(), [](const CounterEntry& a,
                                         const CounterEntry& b) {
        return a.position < b.position;
    });
    return out;
}

std::string SliceBF::label(uint32_t p) const {
    auto h = prf(k_label_, "label|" + std::to_string(generation_) + "|" +
                            std::to_string(p));
    return std::string(reinterpret_cast<const char*>(h.data()), 16);
}

uint64_t SliceBF::size_class_for(const Document& d) const {
    uint32_t tags = std::max<uint32_t>(4, static_cast<uint32_t>(
        unique_terms(d.tokens).size()));
    uint32_t ids = std::max<uint32_t>(16, static_cast<uint32_t>(d.id.size()));
    return (uint64_t(ceil_pow2(tags)) << 32) | ceil_pow2(ids);
}

SliceBF::ProtectedRow SliceBF::zero_row(size_t words) {
    ProtectedRow out;
    for (auto& plane : out.plane) plane.assign(words, 0);
    return out;
}

SliceBF::ProtectedRow SliceBF::mask_row(uint32_t p) const {
    ProtectedRow out = zero_row(n_words_);
    if (!p_.enable_masking) return out;
    const Key16 key = first16(k_pad_);
    const size_t output_bytes = n_words_ * sizeof(uint64_t);
    for (uint32_t bit = 0; bit < 4; ++bit) {
        auto h = prf(k_pad_, "mask-iv|" + std::to_string(generation_) + "|" +
                            std::to_string(p) + "|" + std::to_string(bit));
        std::array<uint8_t, 16> iv{};
        std::copy_n(h.begin(), iv.size(), iv.begin());
        auto stream = aes128_ctr_prg(key, iv, output_bytes);
        if (output_bytes)
            std::memcpy(out.plane[bit].data(), stream.data(), output_bytes);
    }
    return out;
}

void SliceBF::add_row(ProtectedRow& acc, const ProtectedRow& value) {
    const size_t words = acc.plane[0].size();
    for (size_t w = 0; w < words; ++w) {
        uint64_t carry = 0;
        for (size_t bit = 0; bit < 4; ++bit) {
            const uint64_t a = acc.plane[bit][w];
            const uint64_t b = value.plane[bit][w];
            acc.plane[bit][w] = a ^ b ^ carry;
            carry = (a & b) | (carry & (a ^ b));
        }
    }
}

SliceBF::ProtectedRow SliceBF::subtract_row(const ProtectedRow& a,
                                             const ProtectedRow& b) {
    ProtectedRow out = zero_row(a.plane[0].size());
    for (size_t w = 0; w < a.plane[0].size(); ++w) {
        uint64_t borrow = 0;
        for (size_t bit = 0; bit < 4; ++bit) {
            const uint64_t av = a.plane[bit][w];
            const uint64_t bv = b.plane[bit][w];
            out.plane[bit][w] = av ^ bv ^ borrow;
            borrow = (~av & (bv | borrow)) | (bv & borrow);
        }
    }
    return out;
}

void SliceBF::increment_lane(ProtectedRow& row, uint32_t slot) {
    const size_t word = slot >> 6;
    const uint64_t mask = uint64_t(1) << (slot & 63);
    bool carry = true;
    for (size_t bit = 0; bit < 4 && carry; ++bit) {
        const bool old = (row.plane[bit][word] & mask) != 0;
        row.plane[bit][word] ^= mask;
        carry = old;
    }
}

uint8_t SliceBF::lane_value(const ProtectedRow& row, uint32_t slot) {
    const size_t word = slot >> 6;
    const uint64_t mask = uint64_t(1) << (slot & 63);
    uint8_t out = 0;
    for (uint8_t bit = 0; bit < 4; ++bit)
        if (row.plane[bit][word] & mask) out |= uint8_t(1U << bit);
    return out;
}

SliceBF::Alias SliceBF::fresh_alias() const {
    auto r = random_key();
    Alias out{};
    std::copy_n(r.begin(), out.size(), out.begin());
    return out;
}

std::vector<uint8_t> SliceBF::meta_aad(uint32_t slot) const {
    std::vector<uint8_t> aad;
    put64(aad, generation_);
    put32(aad, slot);
    return aad;
}

std::vector<uint8_t> SliceBF::record_aad(const Alias& alias,
                                         uint64_t version) const {
    std::vector<uint8_t> aad;
    put64(aad, generation_);
    aad.insert(aad.end(), alias.begin(), alias.end());
    put64(aad, version);
    return aad;
}

std::vector<uint8_t> SliceBF::delta_aad(
    const std::array<uint8_t, 32>& address) const {
    std::vector<uint8_t> aad;
    put64(aad, generation_);
    aad.insert(aad.end(), address.begin(), address.end());
    return aad;
}

EncryptedTuple SliceBF::encrypt_tuple(
    uint32_t slot, const Alias& alias, uint64_t version, bool active,
    const std::vector<std::string>& tokens, const std::string& id,
    uint64_t size_class) const {
    const uint32_t tag_cap = tag_capacity(size_class);
    const uint32_t id_cap = id_capacity(size_class);
    auto terms = unique_terms(tokens);
    if (terms.size() > tag_cap || id.size() > id_cap)
        throw std::invalid_argument("document does not fit tuple size class");

    std::vector<uint8_t> meta;
    meta.insert(meta.end(), {'S', 'B', 'M', '2'});
    put64(meta, generation_);
    put32(meta, slot);
    meta.insert(meta.end(), alias.begin(), alias.end());
    put64(meta, version);
    meta.push_back(active ? 1 : 0);
    put16(meta, static_cast<uint16_t>(terms.size()));
    for (const auto& term : terms) {
        auto tag = exact_tag(k_ver_, term);
        meta.insert(meta.end(), tag.begin(), tag.end());
    }
    meta.resize(meta.size() + (tag_cap - terms.size()) * 16, 0);

    std::vector<uint8_t> record;
    record.insert(record.end(), {'S', 'B', 'R', '2'});
    put32(record, static_cast<uint32_t>(id.size()));
    record.insert(record.end(), id.begin(), id.end());
    record.resize(8 + id_cap, 0);

    EncryptedTuple out;
    out.size_class = size_class;
    out.metadata = aead_encrypt(k_meta_, meta, meta_aad(slot));
    out.record = aead_encrypt(k_doc_, record, record_aad(alias, version));
    return out;
}

SliceBF::DecodedMeta SliceBF::decrypt_meta(
    uint32_t slot, const EncryptedTuple& tuple) const {
    auto plain = aead_decrypt(k_meta_, tuple.metadata, meta_aad(slot));
    const size_t header = 4 + 8 + 4 + 16 + 8 + 1 + 2;
    if (plain.size() < header || std::memcmp(plain.data(), "SBM2", 4) != 0)
        throw std::runtime_error("invalid SliceBF metadata");
    if (get64(plain.data() + 4) != generation_ ||
        get32(plain.data() + 12) != slot)
        throw std::runtime_error("metadata generation/slot mismatch");

    DecodedMeta out;
    std::copy_n(plain.begin() + 16, out.alias.size(), out.alias.begin());
    out.version = get64(plain.data() + 32);
    out.active = plain[40] != 0;
    const uint16_t count = get16(plain.data() + 41);
    if (header + size_t(count) * 16 > plain.size())
        throw std::runtime_error("invalid metadata tag count");
    out.tags.resize(count);
    size_t off = header;
    for (auto& tag : out.tags) {
        std::copy_n(plain.begin() + off, tag.size(), tag.begin());
        off += tag.size();
    }
    return out;
}

std::string SliceBF::decrypt_record(const DecodedMeta& meta,
                                    const EncryptedTuple& tuple) const {
    auto plain = aead_decrypt(k_doc_, tuple.record,
                              record_aad(meta.alias, meta.version));
    if (plain.size() < 8 || std::memcmp(plain.data(), "SBR2", 4) != 0)
        throw std::runtime_error("invalid SliceBF encrypted record");
    uint32_t len = get32(plain.data() + 4);
    if (8 + size_t(len) > plain.size())
        throw std::runtime_error("invalid encrypted record length");
    return std::string(reinterpret_cast<const char*>(plain.data() + 8), len);
}

void SliceBF::materialize_snapshot() {
    snapshot_.clear();
    snapshot_.reserve(p_.m);
    labels_.resize(p_.m);
    label_to_position_.clear();
    label_to_position_.reserve(p_.m * 2);
    for (uint32_t p = 0; p < p_.m; ++p) {
        snapshot_.push_back(mask_row(p));
        labels_[p] = label(p);
        label_to_position_.emplace(labels_[p], p);
    }
    for (uint32_t slot = 0; slot < capacity_slots_; ++slot) {
        if (!active_[slot]) continue;
        for (const auto& entry : counters_[slot])
            increment_lane(snapshot_[entry.position], slot);
    }
    chain_heads_.assign(p_.m, Key32{});
    chain_lengths_.assign(p_.m, 0);
    delta_log_.clear();
}

void SliceBF::rebuild(
    const std::vector<Document>& docs,
    const std::unordered_map<std::string, uint64_t>& versions,
    uint64_t extra_class) {
    std::map<uint64_t, std::vector<size_t>> grouped;
    std::vector<uint64_t> doc_classes(docs.size());
    for (size_t i = 0; i < docs.size(); ++i) {
        doc_classes[i] = size_class_for(docs[i]);
        grouped[doc_classes[i]].push_back(i);
    }
    if (extra_class) grouped[extra_class];

    classes_.clear();
    free_slots_.clear();
    uint32_t offset = 0;
    for (const auto& kv : grouped) {
        const uint32_t used = static_cast<uint32_t>(kv.second.size());
        uint32_t cap = round_up(used, p_.bucket_size) +
                       p_.reserve_buckets_per_class * p_.bucket_size;
        if (!cap) cap = p_.bucket_size;
        SizeClassInfo info;
        info.id = kv.first;
        info.tag_capacity = tag_capacity(kv.first);
        info.id_capacity = id_capacity(kv.first);
        info.logical_begin = offset;
        info.physical_begin = offset;
        info.capacity = cap;
        classes_.emplace(kv.first, info);
        offset += cap;
    }

    capacity_slots_ = offset;
    n_words_ = (capacity_slots_ + 63) / 64;
    live_ = docs.size();
    active_.assign(capacity_slots_, 0);
    alias_version_.assign(capacity_slots_, 0);
    aliases_.assign(capacity_slots_, Alias{});
    id_by_slot_.assign(capacity_slots_, {});
    tokens_by_slot_.assign(capacity_slots_, {});
    counters_.assign(capacity_slots_, {});
    class_by_slot_.assign(capacity_slots_, 0);
    physical_by_slot_.assign(capacity_slots_, 0);
    slot_by_physical_.assign(capacity_slots_, 0);
    tuples_by_physical_.assign(capacity_slots_, {});

    std::map<uint64_t, uint32_t> cursor;
    for (const auto& kv : classes_) cursor[kv.first] = kv.second.logical_begin;
    for (size_t i = 0; i < docs.size(); ++i) {
        const uint64_t cls = doc_classes[i];
        const uint32_t slot = cursor[cls]++;
        active_[slot] = 1;
        auto it = versions.find(docs[i].id);
        alias_version_[slot] = it == versions.end() ? 1 : it->second;
        aliases_[slot] = fresh_alias();
        id_by_slot_[slot] = docs[i].id;
        tokens_by_slot_[slot] = docs[i].tokens;
        counters_[slot] = support_for(docs[i].tokens);
        class_by_slot_[slot] = cls;
    }

    for (const auto& kv : classes_) {
        const auto& info = kv.second;
        auto& free = free_slots_[kv.first];
        for (uint32_t slot = info.logical_begin;
             slot < info.logical_begin + info.capacity; ++slot) {
            class_by_slot_[slot] = kv.first;
            if (!active_[slot]) free.push_back(slot);
        }

        std::vector<std::pair<Key32, uint32_t>> order;
        order.reserve(info.capacity);
        for (uint32_t slot = info.logical_begin;
             slot < info.logical_begin + info.capacity; ++slot) {
            auto rank = prf(k_bucket_, "perm|" + std::to_string(generation_) +
                "|" + std::to_string(kv.first) + "|" + std::to_string(slot));
            order.emplace_back(rank, slot);
        }
        std::sort(order.begin(), order.end(),
                  [](const auto& a, const auto& b) {
                      return a.first == b.first ? a.second < b.second
                                                : a.first < b.first;
                  });
        for (uint32_t rank = 0; rank < info.capacity; ++rank) {
            const uint32_t slot = order[rank].second;
            const uint32_t physical = info.physical_begin + rank;
            physical_by_slot_[slot] = physical;
            slot_by_physical_[physical] = slot;
        }
    }

    for (uint32_t slot = 0; slot < capacity_slots_; ++slot) {
        Alias alias = active_[slot] ? aliases_[slot] : fresh_alias();
        EncryptedTuple tuple = encrypt_tuple(
            slot, alias, active_[slot] ? alias_version_[slot] : 0,
            active_[slot] != 0, active_[slot] ? tokens_by_slot_[slot]
                                              : std::vector<std::string>{},
            active_[slot] ? id_by_slot_[slot] : std::string{},
            class_by_slot_[slot]);
        tuples_by_physical_[physical_by_slot_[slot]] = std::move(tuple);
    }

    materialize_snapshot();
    pending_.clear();
    compaction_due_ = false;
}

void SliceBF::build(const std::vector<Document>& docs) {
    validate_documents(docs);
    generation_ = 1;
    next_update_sequence_ = 0;
    last_verified_sequence_ = 0;
    derive_generation_keys();
    rebuild(docs, {}, 0);
}

bool SliceBF::zero_state(const Key32& s) {
    uint8_t acc = 0;
    for (uint8_t b : s) acc |= b;
    return acc == 0;
}

DeltaUpload SliceBF::make_delta(uint32_t p, Op op, uint32_t slot,
                                const Alias& alias, uint64_t version,
                                uint64_t sequence) {
    Key32 next = random_key();
    auto address = keyed_state_prf(k_walk_, "addr|", next);
    auto link_mask = keyed_state_prf(k_walk_, "link|", next);

    DeltaUpload rec;
    rec.address = address;
    for (size_t i = 0; i < rec.link.size(); ++i)
        rec.link[i] = chain_heads_[p][i] ^ link_mask[i];

    std::vector<uint8_t> payload;
    payload.insert(payload.end(), {'S', 'B', 'D', '2'});
    payload.push_back(op == Op::Add ? 1 : 0);
    put64(payload, generation_);
    put32(payload, slot);
    payload.insert(payload.end(), alias.begin(), alias.end());
    put64(payload, version);
    put64(payload, sequence);
    rec.ciphertext = aead_encrypt(k_delta_, payload, delta_aad(rec.address));

    chain_heads_[p] = next;
    ++chain_lengths_[p];
    if (chain_lengths_[p] >= p_.chain_threshold) compaction_due_ = true;
    return rec;
}

DeltaUpload SliceBF::make_dummy_delta() const {
    DeltaUpload rec;
    rec.address = random_key();
    rec.link = random_key();
    std::vector<uint8_t> dummy(4 + 1 + 8 + 4 + 16 + 8 + 8, 0);
    rec.ciphertext = aead_encrypt(k_delta_, dummy, delta_aad(rec.address));
    return rec;
}

SliceBF::DecodedDelta SliceBF::decrypt_delta(const DeltaUpload& rec) const {
    auto plain = aead_decrypt(k_delta_, rec.ciphertext, delta_aad(rec.address));
    const size_t expected = 4 + 1 + 8 + 4 + 16 + 8 + 8;
    if (plain.size() != expected || std::memcmp(plain.data(), "SBD2", 4) != 0)
        throw std::runtime_error("invalid SliceBF delta payload");
    DecodedDelta out;
    out.op = plain[4] ? Op::Add : Op::Del;
    out.generation = get64(plain.data() + 5);
    out.slot = get32(plain.data() + 13);
    std::copy_n(plain.begin() + 17, out.alias.size(), out.alias.begin());
    out.version = get64(plain.data() + 33);
    out.sequence = get64(plain.data() + 41);
    return out;
}

std::vector<DeltaUpload> SliceBF::walk_chain(const Key32& head) const {
    std::vector<DeltaUpload> out;
    Key32 state = head;
    size_t guard = 0;
    while (!zero_state(state)) {
        auto address = keyed_state_prf(k_walk_, "addr|", state);
        auto it = delta_log_.find(bytes(address));
        if (it == delta_log_.end())
            throw std::runtime_error("delta chain record missing");
        out.push_back(it->second);
        auto mask = keyed_state_prf(k_walk_, "link|", state);
        Key32 previous{};
        for (size_t i = 0; i < previous.size(); ++i)
            previous[i] = it->second.link[i] ^ mask[i];
        state = previous;
        if (++guard > delta_log_.size())
            throw std::runtime_error("delta chain cycle detected");
    }
    return out;
}

std::array<uint8_t, 32> SliceBF::mac_token(const UpdateToken& token) const {
    std::vector<uint8_t> buf;
    buf.push_back(static_cast<uint8_t>(token.op));
    put64(buf, token.generation);
    put64(buf, token.sequence);
    put64(buf, token.size_class);
    put32(buf, token.physical_handle);
    put64(buf, token.records.size());
    for (const auto& rec : token.records) {
        buf.insert(buf.end(), rec.address.begin(), rec.address.end());
        buf.insert(buf.end(), rec.link.begin(), rec.link.end());
        put64(buf, rec.ciphertext.size());
        buf.insert(buf.end(), rec.ciphertext.begin(), rec.ciphertext.end());
    }
    put64(buf, token.tuple.size_class);
    put64(buf, token.tuple.metadata.size());
    buf.insert(buf.end(), token.tuple.metadata.begin(), token.tuple.metadata.end());
    put64(buf, token.tuple.record.size());
    buf.insert(buf.end(), token.tuple.record.begin(), token.tuple.record.end());
    return hmac_sha256(k_upd_.data(), k_upd_.size(), buf.data(), buf.size());
}

uint32_t SliceBF::allocate_slot(uint64_t cls) {
    auto it = free_slots_.find(cls);
    if (it == free_slots_.end() || it->second.empty())
        throw std::runtime_error("no free slot in requested size class");
    uint32_t slot = it->second.back();
    it->second.pop_back();
    return slot;
}

void SliceBF::ensure_class_capacity(uint64_t cls) {
    auto it = free_slots_.find(cls);
    if (it != free_slots_.end() && !it->second.empty()) return;
    if (!pending_.empty())
        throw std::runtime_error("capacity rebuild requires acknowledged updates");

    std::vector<Document> docs;
    std::unordered_map<std::string, uint64_t> versions;
    docs.reserve(live_);
    for (uint32_t slot = 0; slot < capacity_slots_; ++slot) {
        if (!active_[slot]) continue;
        docs.push_back({id_by_slot_[slot], tokens_by_slot_[slot]});
        versions[id_by_slot_[slot]] = alias_version_[slot] + 1;
    }
    if (capacity_slots_ != 0 || live_ != 0) {
        ++generation_;
        derive_generation_keys();
    }
    rebuild(docs, versions, cls);
}

UpdateToken SliceBF::insert(const Document& d, UpdatePrepareStats* stats) {
    const auto t0 = Clock::now();
    if (d.id.empty() || !has_unique_tokens(d))
        throw std::invalid_argument(
            "insert requires a nonempty id and unique keyword set");
    for (uint32_t slot = 0; slot < capacity_slots_; ++slot)
        if (active_[slot] && id_by_slot_[slot] == d.id)
            throw std::invalid_argument("duplicate live document id");

    const uint64_t cls = size_class_for(d);
    ensure_class_capacity(cls);
    const uint32_t slot = allocate_slot(cls);
    const uint64_t version = alias_version_[slot] + 1;
    const Alias alias = fresh_alias();
    const auto support = support_for(d.tokens);
    const uint64_t sequence = ++next_update_sequence_;
    const auto t1 = Clock::now();

    UpdateToken token;
    token.op = Op::Add;
    token.generation = generation_;
    token.sequence = sequence;
    token.size_class = cls;
    token.physical_handle = physical_by_slot_[slot];
    token.records.reserve(std::max<size_t>(p_.delta_batch_min, support.size()));
    for (const auto& entry : support)
        token.records.push_back(make_delta(entry.position, Op::Add, slot, alias,
                                           version, sequence));
    const uint32_t padded = ceil_pow2(std::max<uint32_t>(
        p_.delta_batch_min, static_cast<uint32_t>(support.size())));
    while (token.records.size() < padded)
        token.records.push_back(make_dummy_delta());
    cryptographic_shuffle(token.records);
    token.tuple = encrypt_tuple(slot, alias, version, true, d.tokens, d.id, cls);

    active_[slot] = 1;
    alias_version_[slot] = version;
    aliases_[slot] = alias;
    id_by_slot_[slot] = d.id;
    tokens_by_slot_[slot] = d.tokens;
    counters_[slot] = support;
    ++live_;

    token.mac = mac_token(token);
    pending_[sequence] = token.mac;
    const auto t2 = Clock::now();
    if (stats) {
        stats->ms_token_generation = Ms(t1 - t0).count();
        stats->ms_client_crypto = Ms(t2 - t1).count();
        stats->ms_total = Ms(t2 - t0).count();
        stats->real_delta_records = support.size();
        stats->padded_delta_records = token.records.size();
        stats->token_bytes = token.logical_bytes();
    }
    return token;
}

UpdateToken SliceBF::remove(const std::string& doc_id,
                            UpdatePrepareStats* stats) {
    const auto t0 = Clock::now();
    uint32_t slot = UINT32_MAX;
    for (uint32_t i = 0; i < capacity_slots_; ++i) {
        if (active_[i] && id_by_slot_[i] == doc_id) {
            slot = i;
            break;
        }
    }
    if (slot == UINT32_MAX)
        throw std::invalid_argument("delete for absent document");

    const size_t real_count = counters_[slot].size();
    const uint64_t sequence = ++next_update_sequence_;
    const auto t1 = Clock::now();
    UpdateToken token;
    token.op = Op::Del;
    token.generation = generation_;
    token.sequence = sequence;
    token.size_class = class_by_slot_[slot];
    token.physical_handle = UINT32_MAX;
    for (const auto& entry : counters_[slot])
        token.records.push_back(make_delta(entry.position, Op::Del, slot,
                                           aliases_[slot], alias_version_[slot],
                                           sequence));
    const uint32_t padded = ceil_pow2(std::max<uint32_t>(
        p_.delta_batch_min, static_cast<uint32_t>(counters_[slot].size())));
    while (token.records.size() < padded)
        token.records.push_back(make_dummy_delta());
    cryptographic_shuffle(token.records);

    active_[slot] = 0;
    id_by_slot_[slot].clear();
    tokens_by_slot_[slot].clear();
    counters_[slot].clear();
    free_slots_[class_by_slot_[slot]].push_back(slot);
    --live_;

    token.mac = mac_token(token);
    pending_[sequence] = token.mac;
    const auto t2 = Clock::now();
    if (stats) {
        stats->ms_token_generation = Ms(t1 - t0).count();
        stats->ms_client_crypto = Ms(t2 - t1).count();
        stats->ms_total = Ms(t2 - t0).count();
        stats->real_delta_records = real_count;
        stats->padded_delta_records = token.records.size();
        stats->token_bytes = token.logical_bytes();
    }
    return token;
}

UpdateToken SliceBF::modify_keywords(
    const std::string& doc_id,
    const std::vector<std::string>& add_terms,
    const std::vector<std::string>& remove_terms,
    UpdatePrepareStats* stats) {
    const auto t0 = Clock::now();
    uint32_t slot = UINT32_MAX;
    for (uint32_t i = 0; i < capacity_slots_; ++i) {
        if (active_[i] && id_by_slot_[i] == doc_id) {
            slot = i;
            break;
        }
    }
    if (slot == UINT32_MAX)
        throw std::invalid_argument("keyword modification for absent document");

    std::set<std::string> terms(tokens_by_slot_[slot].begin(),
                                tokens_by_slot_[slot].end());
    const auto adds = unique_terms(add_terms);
    const auto dels = unique_terms(remove_terms);
    if (adds.empty() && dels.empty())
        throw std::invalid_argument("empty keyword modification");
    for (const auto& term : dels) {
        if (!terms.erase(term))
            throw std::invalid_argument("keyword removal for absent term");
    }
    for (const auto& term : adds) {
        if (!terms.insert(term).second)
            throw std::invalid_argument("keyword addition for existing term");
    }
    if (terms.empty())
        throw std::invalid_argument("keyword modification cannot empty a document");

    std::vector<std::string> new_terms(terms.begin(), terms.end());
    Document updated{doc_id, new_terms};
    const uint64_t cls = size_class_for(updated);
    if (cls != class_by_slot_[slot])
        throw std::invalid_argument(
            "keyword modification crosses a public size class; use delete plus insert");

    const auto old_support = counters_[slot];
    const auto new_support = support_for(new_terms);
    std::unordered_set<uint32_t> old_positions;
    std::unordered_set<uint32_t> new_positions;
    for (const auto& entry : old_support) old_positions.insert(entry.position);
    for (const auto& entry : new_support) new_positions.insert(entry.position);

    std::vector<std::pair<uint32_t, Op>> transitions;
    for (uint32_t p : old_positions)
        if (!new_positions.count(p)) transitions.push_back({p, Op::Del});
    for (uint32_t p : new_positions)
        if (!old_positions.count(p)) transitions.push_back({p, Op::Add});
    std::sort(transitions.begin(), transitions.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    const uint64_t sequence = ++next_update_sequence_;
    const uint64_t version = alias_version_[slot] + 1;
    const Alias alias = fresh_alias();
    const auto t1 = Clock::now();

    UpdateToken token;
    token.op = Op::Modify;
    token.generation = generation_;
    token.sequence = sequence;
    token.size_class = cls;
    token.physical_handle = physical_by_slot_[slot];
    token.records.reserve(std::max<size_t>(p_.delta_batch_min,
                                           transitions.size()));
    for (const auto& transition : transitions)
        token.records.push_back(make_delta(transition.first, transition.second,
                                           slot, alias, version, sequence));
    const uint32_t padded = ceil_pow2(std::max<uint32_t>(
        p_.delta_batch_min, static_cast<uint32_t>(transitions.size())));
    while (token.records.size() < padded)
        token.records.push_back(make_dummy_delta());
    cryptographic_shuffle(token.records);
    token.tuple = encrypt_tuple(slot, alias, version, true, new_terms, doc_id, cls);

    alias_version_[slot] = version;
    aliases_[slot] = alias;
    tokens_by_slot_[slot] = std::move(new_terms);
    counters_[slot] = new_support;

    token.mac = mac_token(token);
    pending_[sequence] = token.mac;
    const auto t2 = Clock::now();
    if (stats) {
        stats->ms_token_generation = Ms(t1 - t0).count();
        stats->ms_client_crypto = Ms(t2 - t1).count();
        stats->ms_total = Ms(t2 - t0).count();
        stats->real_delta_records = transitions.size();
        stats->padded_delta_records = token.records.size();
        stats->token_bytes = token.logical_bytes();
    }
    return token;
}

bool SliceBF::verify_token(const UpdateToken& token) {
    const auto expected = mac_token(token);
    if (!ct_equal(expected, token.mac)) return false;
    if (token.generation != generation_ ||
        token.sequence != last_verified_sequence_ + 1)
        return false;
    auto pending = pending_.find(token.sequence);
    if (pending == pending_.end() || !ct_equal(pending->second, token.mac))
        return false;

    std::unordered_set<std::string> new_addresses;
    for (const auto& rec : token.records) {
        const std::string key = bytes(rec.address);
        if (delta_log_.count(key) || !new_addresses.insert(key).second)
            return false;
    }
    if (token.op == Op::Add || token.op == Op::Modify) {
        if (token.physical_handle >= capacity_slots_ ||
            token.tuple.size_class != token.size_class ||
            class_by_slot_[slot_by_physical_[token.physical_handle]] !=
                token.size_class)
            return false;
    } else if (token.physical_handle != UINT32_MAX) {
        return false;
    }

    for (const auto& rec : token.records)
        delta_log_.emplace(bytes(rec.address), rec);
    if (token.op == Op::Add || token.op == Op::Modify)
        tuples_by_physical_[token.physical_handle] = token.tuple;
    last_verified_sequence_ = token.sequence;
    pending_.erase(pending);
    return true;
}

std::vector<std::string> SliceBF::search(
    const std::vector<std::string>& query_terms, SearchStats* stats) const {
    const auto t0 = Clock::now();
    std::vector<std::string> results;
    if (!pending_.empty())
        throw std::runtime_error("search requires all prepared updates to be acknowledged");
    if (query_terms.empty() || capacity_slots_ == 0) {
        if (stats) stats->ms_total = Ms(Clock::now() - t0).count();
        return results;
    }

    struct Item {
        uint32_t position = 0;
        std::string label;
        Key32 head{};
    };
    struct ServerGroup {
        std::vector<Item> items;
        ProtectedRow aggregate;
        std::vector<std::vector<DeltaUpload>> chains;
    };

    std::vector<Item> items;
    for (const auto& word : query_terms) {
        for (uint32_t p : positions(word))
            items.push_back({p, label(p), chain_heads_[p]});
    }
    std::vector<ServerGroup> groups;
    for (size_t begin = 0; begin < items.size(); begin += p_.max_group) {
        const size_t end = std::min(items.size(), begin + p_.max_group);
        ServerGroup group;
        group.items.assign(items.begin() + begin, items.begin() + end);
        groups.push_back(std::move(group));
    }
    const auto t1 = Clock::now();

    size_t returned_delta_bytes = 0;
    size_t returned_delta_records = 0;
    for (auto& group : groups) {
        group.aggregate = zero_row(n_words_);
        group.chains.reserve(group.items.size());
        for (const auto& item : group.items) {
            auto it = label_to_position_.find(item.label);
            if (it == label_to_position_.end())
                throw std::runtime_error("snapshot label missing");
            if (p_.enable_bit_sliced_aggregation)
                add_row(group.aggregate, snapshot_[it->second]);
            auto chain = walk_chain(item.head);
            for (const auto& rec : chain) {
                returned_delta_bytes += rec.ciphertext.size();
                ++returned_delta_records;
            }
            group.chains.push_back(std::move(chain));
        }
    }
    const auto t2 = Clock::now();

    std::vector<std::vector<int16_t>> group_values;
    group_values.reserve(groups.size());
    for (const auto& group : groups) {
        std::vector<int16_t> values(capacity_slots_);
        if (p_.enable_bit_sliced_aggregation) {
            ProtectedRow mask_sum = zero_row(n_words_);
            for (const auto& item : group.items) {
                auto mask = mask_row(item.position);
                add_row(mask_sum, mask);
            }
            auto clear = subtract_row(group.aggregate, mask_sum);
            for (uint32_t slot = 0; slot < capacity_slots_; ++slot)
                values[slot] = lane_value(clear, slot);
        } else {
            // Scalar reference path: return and unmask every selected row,
            // then decode every lane separately.  It produces identical
            // candidates while removing bit-sliced server aggregation.
            for (const auto& item : group.items) {
                auto clear = subtract_row(snapshot_[item.position],
                                          mask_row(item.position));
                for (uint32_t slot = 0; slot < capacity_slots_; ++slot)
                    values[slot] += lane_value(clear, slot);
            }
        }
        group_values.push_back(std::move(values));
    }
    const auto t3 = Clock::now();

    for (size_t gi = 0; gi < groups.size(); ++gi) {
        for (size_t ii = 0; ii < groups[gi].items.size(); ++ii) {
            std::vector<DecodedDelta> decoded;
            decoded.reserve(groups[gi].chains[ii].size());
            for (const auto& rec : groups[gi].chains[ii]) {
                auto delta = decrypt_delta(rec);
                if (delta.generation != generation_ ||
                    delta.slot >= capacity_slots_)
                    throw std::runtime_error("delta generation/slot mismatch");
                decoded.push_back(std::move(delta));
            }
            std::sort(decoded.begin(), decoded.end(),
                      [](const DecodedDelta& a, const DecodedDelta& b) {
                          return a.sequence < b.sequence;
                      });
            for (const auto& delta : decoded)
                group_values[gi][delta.slot] +=
                    delta.op == Op::Add ? int16_t(1) : int16_t(-1);
        }
    }

    std::vector<uint32_t> candidates;
    for (uint32_t slot = 0; slot < capacity_slots_; ++slot) {
        bool match = true;
        for (size_t gi = 0; gi < groups.size(); ++gi) {
            if (group_values[gi][slot] !=
                static_cast<int16_t>(groups[gi].items.size())) {
                match = false;
                break;
            }
        }
        if (match) candidates.push_back(slot);
    }
    const auto t4 = Clock::now();

    std::set<uint32_t> bucket_ids;
    if (p_.enable_bucket_pruning) {
        for (uint32_t slot : candidates)
            bucket_ids.insert(physical_by_slot_[slot] / p_.bucket_size);
    } else {
        for (uint32_t physical = 0; physical < capacity_slots_;
             physical += p_.bucket_size)
            bucket_ids.insert(physical / p_.bucket_size);
    }
    size_t bucket_bytes = 0;
    volatile size_t fetch_checksum = 0;
    for (uint32_t bucket : bucket_ids) {
        const uint32_t begin = bucket * p_.bucket_size;
        const uint32_t end = std::min<uint32_t>(capacity_slots_,
                                                begin + p_.bucket_size);
        for (uint32_t physical = begin; physical < end; ++physical) {
            bucket_bytes += tuples_by_physical_[physical].logical_bytes();
            fetch_checksum ^= tuples_by_physical_[physical].metadata.size();
        }
    }
    (void)fetch_checksum;
    const auto t5 = Clock::now();

    std::vector<std::array<uint8_t, 16>> wanted_tags;
    wanted_tags.reserve(query_terms.size());
    for (const auto& word : query_terms) wanted_tags.push_back(exact_tag(k_ver_, word));
    for (uint32_t slot : candidates) {
        const uint32_t physical = physical_by_slot_[slot];
        const auto& tuple = tuples_by_physical_[physical];
        try {
            auto meta = decrypt_meta(slot, tuple);
            if (!meta.active || !active_[slot] ||
                meta.version != alias_version_[slot] ||
                !same_alias(meta.alias, aliases_[slot]))
                continue;
            std::set<std::string> present;
            for (const auto& tag : meta.tags)
                present.emplace(reinterpret_cast<const char*>(tag.data()), tag.size());
            bool exact = true;
            for (const auto& tag : wanted_tags) {
                std::string key(reinterpret_cast<const char*>(tag.data()), tag.size());
                if (!present.count(key)) {
                    exact = false;
                    break;
                }
            }
            if (exact) results.push_back(decrypt_record(meta, tuple));
        } catch (const std::runtime_error&) {
            // Authentication failure or stale tuple: reject this candidate.
        }
    }
    const auto t6 = Clock::now();

    if (stats) {
        const size_t returned_rows = p_.enable_bit_sliced_aggregation
            ? groups.size() : items.size();
        const size_t aggregate_bytes = returned_rows * 4 * n_words_ *
                                       sizeof(uint64_t);
        const size_t trapdoor_bytes = 32 + 8 + items.size() * (16 + 32);
        stats->candidate_count = candidates.size();
        stats->verified_count = results.size();
        stats->groups = groups.size();
        stats->trapdoor_bytes = trapdoor_bytes;
        stats->aggregate_bytes = aggregate_bytes;
        stats->delta_records = returned_delta_records;
        stats->delta_bytes = returned_delta_bytes;
        stats->requested_buckets = bucket_ids.size();
        stats->returned_bucket_slots = bucket_ids.size() * p_.bucket_size;
        stats->bucket_bytes = bucket_bytes;
        stats->client_to_server_bytes = trapdoor_bytes +
            bucket_ids.size() * sizeof(uint32_t);
        stats->server_to_client_bytes = aggregate_bytes + returned_delta_bytes +
                                        bucket_bytes;
        stats->round_trips = 2;
        stats->ms_trapdoor = Ms(t1 - t0).count();
        stats->ms_server = Ms(t2 - t1).count() + Ms(t5 - t4).count();
        stats->ms_unmask = Ms(t3 - t2).count();
        stats->ms_delta_replay = Ms(t4 - t3).count();
        stats->ms_bucket_fetch = Ms(t5 - t4).count();
        stats->ms_verify = Ms(t6 - t5).count();
        stats->ms_client = stats->ms_unmask + stats->ms_delta_replay +
                           stats->ms_verify;
        stats->ms_total = Ms(t6 - t0).count();
    }
    return results;
}

CompactionStats SliceBF::compact() {
    if (!pending_.empty())
        throw std::runtime_error("cannot compact with unacknowledged updates");
    const auto t0 = Clock::now();
    CompactionStats stats;
    stats.old_generation = generation_;
    stats.old_snapshot_bytes = snapshot_bytes();
    stats.removed_delta_records = delta_log_.size();

    std::vector<Document> docs;
    std::unordered_map<std::string, uint64_t> versions;
    docs.reserve(live_);
    for (uint32_t slot = 0; slot < capacity_slots_; ++slot) {
        if (!active_[slot]) continue;
        docs.push_back({id_by_slot_[slot], tokens_by_slot_[slot]});
        versions[id_by_slot_[slot]] = alias_version_[slot] + 1;
    }
    ++generation_;
    derive_generation_keys();
    rebuild(docs, versions, 0);
    stats.new_generation = generation_;
    stats.new_snapshot_bytes = snapshot_bytes();
    stats.ms_total = Ms(Clock::now() - t0).count();
    return stats;
}

size_t SliceBF::snapshot_bytes() const {
    size_t total = 4 * sizeof(uint64_t);  // generation, rows, slots, words
    for (const auto& row : snapshot_) {
        total += 16;
        for (const auto& plane : row.plane)
            total += plane.size() * sizeof(uint64_t);
    }
    return total;
}

size_t SliceBF::delta_log_bytes() const {
    if (delta_log_.empty()) return 0;
    size_t total = sizeof(uint64_t);  // record count
    for (const auto& kv : delta_log_)
        total += 32 + kv.second.link.size() + sizeof(uint32_t) +
                 kv.second.ciphertext.size();
    return total;
}

uint32_t SliceBF::max_chain_length() const {
    return chain_lengths_.empty()
        ? 0
        : *std::max_element(chain_lengths_.begin(), chain_lengths_.end());
}

size_t SliceBF::metadata_bytes() const {
    size_t total = 0;
    for (const auto& tuple : tuples_by_physical_)
        total += sizeof(uint64_t) + sizeof(uint32_t) + tuple.metadata.size();
    return total;
}

size_t SliceBF::encrypted_records_bytes() const {
    size_t total = 0;
    for (const auto& tuple : tuples_by_physical_)
        total += sizeof(uint32_t) + tuple.record.size();
    return total;
}

size_t SliceBF::server_storage_bytes() const {
    return snapshot_bytes() + delta_log_bytes() + metadata_bytes() +
           encrypted_records_bytes();
}

size_t SliceBF::owner_counter_plane_bytes() const {
    size_t total = capacity_slots_ * sizeof(uint32_t);  // per-slot offset/length
    for (const auto& entries : counters_)
        total += entries.size() * (sizeof(uint32_t) + sizeof(uint16_t));
    return total;
}

size_t SliceBF::owner_token_state_bytes() const {
    size_t total = capacity_slots_ * sizeof(uint32_t);  // token-vector lengths
    for (const auto& terms : tokens_by_slot_)
        for (const auto& term : terms)
            total += sizeof(uint32_t) + term.size();
    return total;
}

size_t SliceBF::owner_state_bytes() const {
    // Master secret, generation/update counters, alias/version map, document
    // identifiers, canonical keyword sets needed for compaction, sparse CBF
    // counters, class membership, and free-slot lists.
    size_t total = 32 + 3 * sizeof(uint64_t);
    for (uint32_t slot = 0; slot < capacity_slots_; ++slot) {
        total += 1 + sizeof(uint64_t) + 16 + sizeof(uint64_t);
        total += sizeof(uint32_t) + id_by_slot_[slot].size();
    }
    total += owner_token_state_bytes();
    total += owner_counter_plane_bytes();
    total += classes_.size() * (sizeof(uint64_t) + 5 * sizeof(uint32_t));
    for (const auto& kv : free_slots_)
        total += sizeof(uint64_t) + kv.second.size() * sizeof(uint32_t);
    return total;
}

size_t SliceBF::client_capsule_bytes() const {
    // Search recovery needs the authenticated chain heads, class directory,
    // secret logical-to-physical mapping, and the active alias/version state
    // checked during local exact verification.
    const size_t capsule_plain = sizeof(uint64_t) * 2 +
        chain_heads_.size() * sizeof(Key32) +
        classes_.size() * (sizeof(uint64_t) + 5 * sizeof(uint32_t)) +
        capacity_slots_ * (sizeof(uint32_t) + 1 + sizeof(uint64_t) + 16);
    return capsule_plain + 12 + 16;
}

size_t SliceBF::client_state_bytes() const {
    return search_seed_bytes() + client_capsule_bytes();
}

}  // namespace sbf
