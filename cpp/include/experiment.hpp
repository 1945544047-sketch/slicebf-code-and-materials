// experiment.hpp — Unified experiment infrastructure (checklist §4, §7).
// High-resolution timing, statistical aggregation, CSV output.
#pragma once
#include <algorithm>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <numeric>
#include <sstream>
#include <string>
#include <vector>

namespace exp_util {

using Clock = std::chrono::high_resolution_clock;
using TimePoint = Clock::time_point;
using Ms = std::chrono::duration<double, std::milli>;

inline TimePoint now() { return Clock::now(); }
inline double ms(TimePoint t0, TimePoint t1) {
    return std::chrono::duration<double, std::milli>(t1 - t0).count();
}

// ---- statistics -----------------------------------------------------------
struct Stats {
    double mean = 0, median = 0, p50 = 0, p95 = 0;
    double sd = 0, ci95_half = 0;
    size_t n = 0;

    static Stats from(std::vector<double> v) {
        if (v.empty()) return {};
        std::sort(v.begin(), v.end());
        Stats s;
        s.n = v.size();
        double sum = std::accumulate(v.begin(), v.end(), 0.0);
        s.mean = sum / s.n;
        s.median = s.n % 2 ? v[s.n / 2]
                           : (v[s.n / 2 - 1] + v[s.n / 2]) / 2.0;
        auto quantile = [&](double probability) {
            if (s.n == 1) return v.front();
            const double position = probability * double(s.n - 1);
            const size_t lower = static_cast<size_t>(std::floor(position));
            const size_t upper = static_cast<size_t>(std::ceil(position));
            const double weight = position - double(lower);
            return v[lower] * (1.0 - weight) + v[upper] * weight;
        };
        s.p50 = quantile(0.50);
        s.p95 = quantile(0.95);
        double sq = 0;
        for (double x : v) sq += (x - s.mean) * (x - s.mean);
        s.sd = s.n > 1 ? std::sqrt(sq / double(s.n - 1)) : 0;
        // One C++ unit is one process.  Final confidence intervals are
        // bootstrapped over fresh-process means by summarize_results.py.
        s.ci95_half = std::numeric_limits<double>::quiet_NaN();
        return s;
    }
};

// ---- CSV writer (raw per-iteration data) ----------------------------------
class CsvWriter {
public:
    explicit CsvWriter(const std::string& path) : os_(path) {
        if (!os_) throw std::runtime_error("cannot open " + path);
    }

    void header(const std::vector<std::string>& cols) {
        for (size_t i = 0; i < cols.size(); ++i) {
            if (i) os_ << ',';
            os_ << cols[i];
        }
        os_ << '\n';
    }

    template <typename... Args>
    void row(Args... args) {
        write_row(0, args...);
    }

    void flush() { os_.flush(); }

    static std::string path(const std::string& base, const std::string& experiment,
                            const std::string& scheme, const std::string& suffix = "csv") {
        return base + "/" + experiment + "_" + scheme + "." + suffix;
    }

private:
    std::ofstream os_;

    void write_row(size_t) { os_ << '\n'; }  // base case: terminate the row

    template <typename T, typename... Rest>
    void write_row(size_t idx, T val, Rest... rest) {
        if (idx) os_ << ',';
        os_ << val;
        write_row(idx + 1, rest...);
    }

    // Special handling for strings with commas
    void write_row(size_t idx, const std::string& val) {
        if (idx) os_ << ',';
        os_ << '"' << val << '"';
    }
    template <typename... Rest>
    void write_row(size_t idx, const std::string& val, Rest... rest) {
        if (idx) os_ << ',';
        os_ << '"' << val << '"';
        write_row(idx + 1, rest...);
    }
};

// ---- summary writer (one aggregated row per configuration) -----------------
class SummaryWriter {
public:
    explicit SummaryWriter(const std::string& path) : os_(path) {
        if (!os_) throw std::runtime_error("cannot open " + path);
        os_ << "experiment,scheme,N,q,selectivity,metric,mean_ms,median_ms,p50_ms,"
            << "p95_ms,sd_ms,ci95_half_ms,n_measurements,param1,param2\n";
    }

    void write(const std::string& exp, const std::string& scheme, size_t N, int q,
               const std::string& sel, const std::string& metric,
               const Stats& s, const std::string& p1 = "", const std::string& p2 = "") {
        os_ << exp << ',' << scheme << ',' << N << ',' << q << ',' << sel << ','
            << metric << ',' << s.mean << ',' << s.median << ',' << s.p50 << ','
            << s.p95 << ',' << s.sd << ',' << s.ci95_half << ',' << s.n << ','
            << p1 << ',' << p2 << '\n';
    }

private:
    std::ofstream os_;
};

// ---- timer with batching for sub-ms operations (checklist §7) --------------
class BatchTimer {
public:
    explicit BatchTimer(size_t min_iterations = 10)
        : min_iter_(min_iterations) {}

    // Run fn at least min_iter_ times (and until ≥1s has elapsed).
    // Returns per-iteration mean in ms.
    template <typename F>
    double measure(F&& fn) {
        // Warmup
        size_t warmup = std::max(size_t(10), min_iter_ / 2);
        for (size_t i = 0; i < warmup; ++i) fn();

        std::vector<double> times;
        double total = 0;
        size_t iter = 0;
        while (iter < min_iter_ || total < 1000.0) {
            auto t0 = now();
            fn();
            double t = ms(t0, now());
            times.push_back(t);
            total += t;
            ++iter;
            if (iter > 1000000) break;  // safety valve
        }
        return total / iter;
    }

private:
    size_t min_iter_;
};

// ---- precision timer for single invocation (ms-scale ops) ------------------
template <typename F>
double timed_ms(F&& fn) {
    auto t0 = now();
    fn();
    return ms(t0, now());
}

}  // namespace exp_util
