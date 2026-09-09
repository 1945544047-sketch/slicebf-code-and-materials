// SliceBF: leakage-reduced dual-plane CBF index used by the final experiments.
//
// The cloud-facing snapshot contains four additively masked bit slices per CBF
// position.  Dynamic changes are appended as fixed-size, forward-private delta
// records.  Candidate recovery, delta replay, bucket selection, and exact-tag
// verification are client-side operations.
#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "corpus.hpp"
#include "crypto.hpp"

namespace sbf {

struct Params {
    uint32_t m = 8192;
    uint32_t k = 4;
    uint32_t lane_bits = 4;
    uint32_t max_group = 15;
    uint32_t bucket_size = 64;
    uint32_t chain_threshold = 512;
    uint32_t delta_batch_min = 8;
    uint32_t reserve_buckets_per_class = 1;
    // Performance-only ablation switches.  The default preserves the complete
    // protected protocol.  Disabling masking weakens the claimed leakage
    // profile and is only valid as an explicitly labelled ablation.
    bool enable_masking = true;
    bool enable_bit_sliced_aggregation = true;
    bool enable_bucket_pruning = true;
};

struct SearchStats {
    size_t candidate_count = 0;
    size_t verified_count = 0;
    size_t groups = 0;
    size_t trapdoor_bytes = 0;
    size_t aggregate_bytes = 0;
    size_t delta_records = 0;
    size_t delta_bytes = 0;
    size_t requested_buckets = 0;
    size_t returned_bucket_slots = 0;
    size_t bucket_bytes = 0;
    size_t client_to_server_bytes = 0;
    size_t server_to_client_bytes = 0;
    size_t round_trips = 0;

    double ms_trapdoor = 0;
    double ms_server = 0;
    double ms_unmask = 0;
    double ms_delta_replay = 0;
    double ms_bucket_fetch = 0;
    double ms_verify = 0;
    double ms_client = 0;
    double ms_total = 0;
};

enum class Op : uint8_t { Del = 0, Add = 1, Modify = 2 };

struct DeltaUpload {
    std::array<uint8_t, 32> address{};
    std::array<uint8_t, 32> link{};
    std::vector<uint8_t> ciphertext;
};

struct EncryptedTuple {
    uint64_t size_class = 0;
    std::vector<uint8_t> metadata;
    std::vector<uint8_t> record;

    size_t logical_bytes() const {
        return sizeof(uint64_t) + 2 * sizeof(uint32_t) +
               metadata.size() + record.size();
    }
};

// Server-visible authenticated update batch. Logical position, slot, alias,
// and version appear only inside the delta ciphertexts. Insertions and
// keyword-level modifications reveal one opaque physical tuple handle;
// deletions use UINT32_MAX.
struct UpdateToken {
    Op op = Op::Add;
    uint64_t generation = 0;
    uint64_t sequence = 0;
    uint64_t size_class = 0;
    uint32_t physical_handle = UINT32_MAX;
    std::vector<DeltaUpload> records;
    EncryptedTuple tuple;
    std::array<uint8_t, 32> mac{};

    size_t logical_bytes() const;
};

struct CompactionStats {
    double ms_total = 0;
    size_t old_snapshot_bytes = 0;
    size_t new_snapshot_bytes = 0;
    size_t removed_delta_records = 0;
    uint64_t old_generation = 0;
    uint64_t new_generation = 0;
};

struct UpdatePrepareStats {
    double ms_token_generation = 0;
    double ms_client_crypto = 0;
    double ms_total = 0;
    size_t real_delta_records = 0;
    size_t padded_delta_records = 0;
    size_t token_bytes = 0;
};

class SliceBF {
public:
    explicit SliceBF(Params p = {});

    void build(const std::vector<Document>& docs);

    // Owner prepares a batch; verify_token models authenticated, ordered server
    // acceptance and the acknowledgement that commits the prepared state.
    UpdateToken insert(const Document& d, UpdatePrepareStats* stats = nullptr);
    UpdateToken remove(const std::string& doc_id,
                       UpdatePrepareStats* stats = nullptr);
    // Modify one live document without replacing its logical slot. Counter
    // multiplicities determine which affected positions cross 0 <-> 1 and
    // therefore require encrypted query-plane deltas. A public size-class
    // change is handled as delete plus insert instead of an in-place modify.
    UpdateToken modify_keywords(
        const std::string& doc_id,
        const std::vector<std::string>& add_terms,
        const std::vector<std::string>& remove_terms,
        UpdatePrepareStats* stats = nullptr);
    bool verify_token(const UpdateToken& t);

    std::vector<std::string> search(const std::vector<std::string>& query_terms,
                                    SearchStats* stats = nullptr) const;

    CompactionStats compact();
    bool needs_compaction() const { return compaction_due_; }

    const Params& params() const { return p_; }
    size_t index_labels() const { return snapshot_.size(); }
    size_t live_docs() const { return live_; }
    size_t padded_slots() const { return capacity_slots_; }
    uint64_t generation() const { return generation_; }

    // Logical serialized storage accounting.
    size_t snapshot_bytes() const;
    size_t query_plane_bytes() const { return snapshot_bytes(); }
    size_t delta_log_bytes() const;
    size_t delta_log_records() const { return delta_log_.size(); }
    uint32_t max_chain_length() const;
    size_t metadata_bytes() const;
    size_t meta_bytes() const { return metadata_bytes(); }
    size_t encrypted_records_bytes() const;
    size_t server_storage_bytes() const;
    size_t owner_counter_plane_bytes() const;
    size_t owner_token_state_bytes() const;
    size_t owner_state_bytes() const;
    size_t counter_plane_bytes() const { return owner_counter_plane_bytes(); }
    size_t client_capsule_bytes() const;
    size_t client_state_bytes() const;
    static constexpr size_t search_seed_bytes() { return 32; }

private:
    using Bitmap = std::vector<uint64_t>;
    using Alias = std::array<uint8_t, 16>;

    struct ProtectedRow {
        std::array<Bitmap, 4> plane;
    };

    struct CounterEntry {
        uint32_t position = 0;
        uint16_t multiplicity = 0;
    };

    struct SizeClassInfo {
        uint64_t id = 0;
        uint32_t tag_capacity = 0;
        uint32_t id_capacity = 0;
        uint32_t logical_begin = 0;
        uint32_t physical_begin = 0;
        uint32_t capacity = 0;
    };

    struct DecodedMeta {
        Alias alias{};
        uint64_t version = 0;
        bool active = false;
        std::vector<std::array<uint8_t, 16>> tags;
    };

    struct DecodedDelta {
        Op op = Op::Add;
        uint64_t generation = 0;
        uint32_t slot = 0;
        Alias alias{};
        uint64_t version = 0;
        uint64_t sequence = 0;
    };

    void setup();
    void derive_generation_keys();
    void rebuild(const std::vector<Document>& docs,
                 const std::unordered_map<std::string, uint64_t>& versions,
                 uint64_t extra_class = 0);

    std::vector<uint32_t> positions(const std::string& w) const;
    std::vector<CounterEntry> support_for(
        const std::vector<std::string>& tokens) const;
    std::string label(uint32_t p) const;
    uint64_t size_class_for(const Document& d) const;
    static uint32_t tag_capacity(uint64_t size_class) {
        return static_cast<uint32_t>(size_class >> 32);
    }
    static uint32_t id_capacity(uint64_t size_class) {
        return static_cast<uint32_t>(size_class & 0xffffffffULL);
    }

    ProtectedRow mask_row(uint32_t p) const;
    static ProtectedRow zero_row(size_t words);
    static void add_row(ProtectedRow& acc, const ProtectedRow& value);
    static ProtectedRow subtract_row(const ProtectedRow& a,
                                       const ProtectedRow& b);
    static void increment_lane(ProtectedRow& row, uint32_t slot);
    static uint8_t lane_value(const ProtectedRow& row, uint32_t slot);
    void materialize_snapshot();

    Alias fresh_alias() const;
    EncryptedTuple encrypt_tuple(uint32_t slot, const Alias& alias,
                                 uint64_t version, bool active,
                                 const std::vector<std::string>& tokens,
                                 const std::string& id,
                                 uint64_t size_class) const;
    DecodedMeta decrypt_meta(uint32_t slot, const EncryptedTuple& tuple) const;
    std::string decrypt_record(const DecodedMeta& meta,
                               const EncryptedTuple& tuple) const;

    DeltaUpload make_delta(uint32_t p, Op op, uint32_t slot,
                           const Alias& alias, uint64_t version,
                           uint64_t sequence);
    DeltaUpload make_dummy_delta() const;
    DecodedDelta decrypt_delta(const DeltaUpload& rec) const;
    std::vector<DeltaUpload> walk_chain(const Key32& head) const;
    static bool zero_state(const Key32& s);

    std::array<uint8_t, 32> mac_token(const UpdateToken& t) const;
    uint32_t allocate_slot(uint64_t size_class);
    void ensure_class_capacity(uint64_t size_class);

    std::vector<uint8_t> meta_aad(uint32_t slot) const;
    std::vector<uint8_t> record_aad(const Alias& alias,
                                    uint64_t version) const;
    std::vector<uint8_t> delta_aad(
        const std::array<uint8_t, 32>& address) const;

    Params p_;
    Key32 master_{};
    Key32 k_doc_root_{}, k_upd_{};
    Key32 k_search_{}, k_pos_{}, k_label_{}, k_pad_{}, k_walk_{};
    Key32 k_delta_root_{}, k_bucket_{}, k_meta_root_{}, k_ver_{};
    Key16 k_doc_{}, k_delta_{}, k_meta_{};

    uint64_t generation_ = 1;
    uint64_t next_update_sequence_ = 0;
    uint64_t last_verified_sequence_ = 0;
    size_t live_ = 0;
    uint32_t capacity_slots_ = 0;
    size_t n_words_ = 0;
    bool compaction_due_ = false;

    // Cloud snapshot and label directory.
    std::vector<ProtectedRow> snapshot_;
    std::vector<std::string> labels_;
    std::unordered_map<std::string, uint32_t> label_to_position_;

    // Owner-side sparse state and client-visible current slot state.
    std::vector<char> active_;
    std::vector<uint64_t> alias_version_;
    std::vector<Alias> aliases_;
    std::vector<std::string> id_by_slot_;
    std::vector<std::vector<std::string>> tokens_by_slot_;
    std::vector<std::vector<CounterEntry>> counters_;
    std::vector<uint64_t> class_by_slot_;

    // Size-class-preserving secret permutation and cloud tuple array.
    std::map<uint64_t, SizeClassInfo> classes_;
    std::map<uint64_t, std::vector<uint32_t>> free_slots_;
    std::vector<uint32_t> physical_by_slot_;
    std::vector<uint32_t> slot_by_physical_;
    std::vector<EncryptedTuple> tuples_by_physical_;

    // Forward-private delta chains.  Heads belong to the authenticated client
    // capsule; the address map belongs to the cloud.
    std::vector<Key32> chain_heads_;
    std::vector<uint32_t> chain_lengths_;
    std::unordered_map<std::string, DeltaUpload> delta_log_;

    // Prepared owner batches awaiting ordered acknowledgement.
    std::unordered_map<uint64_t, std::array<uint8_t, 32>> pending_;
};

}  // namespace sbf
