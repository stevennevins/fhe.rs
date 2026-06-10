// CUDA kernels for fhe-math. These mirror, operation for operation, the
// arithmetic in src/zq/mod.rs and src/ntt/native.rs so that GPU results are
// bit-exact with the CPU implementation. Do not "optimize" the arithmetic
// here without changing the CPU side identically.

// NVRTC compiles without standard headers; define the fixed-width types.
typedef unsigned long long uint64_t;
typedef unsigned __int128 u128;

// zq::Modulus::reduce1: x mod p for x < 2p.
__device__ __forceinline__ uint64_t reduce1(uint64_t x, uint64_t p) {
    return x >= p ? x - p : x;
}

// zq::Modulus::lazy_mul_shoup: a * b mod p in [0, 2p), b_shoup = (b << 64) / p.
__device__ __forceinline__ uint64_t lazy_mul_shoup(uint64_t a, uint64_t b,
                                                   uint64_t b_shoup,
                                                   uint64_t p) {
    uint64_t q = __umul64hi(a, b_shoup);
    return a * b - q * p;
}

// zq::Modulus::mul_shoup.
__device__ __forceinline__ uint64_t mul_shoup(uint64_t a, uint64_t b,
                                              uint64_t b_shoup, uint64_t p) {
    return reduce1(lazy_mul_shoup(a, b, b_shoup, p), p);
}

// zq::Modulus::lazy_reduce_u128: Barrett reduction of a 128-bit value into
// [0, 2p), with barrett = floor(2^128 / p) split into hi/lo 64-bit limbs.
__device__ __forceinline__ uint64_t lazy_reduce_u128(u128 a, uint64_t p,
                                                     uint64_t barrett_hi,
                                                     uint64_t barrett_lo) {
    uint64_t a_lo = (uint64_t)a;
    uint64_t a_hi = (uint64_t)(a >> 64);
    u128 p_lo_lo = ((u128)a_lo * (u128)barrett_lo) >> 64;
    u128 p_hi_lo = (u128)a_hi * (u128)barrett_lo;
    u128 p_lo_hi = (u128)a_lo * (u128)barrett_hi;
    u128 q = ((p_lo_hi + p_hi_lo + p_lo_lo) >> 64) + (u128)a_hi * (u128)barrett_hi;
    return (uint64_t)(a - q * (u128)p);
}

// zq::Modulus::mul (Barrett, constant-time variant's exact value).
__device__ __forceinline__ uint64_t mul_barrett(uint64_t a, uint64_t b,
                                                uint64_t p, uint64_t barrett_hi,
                                                uint64_t barrett_lo) {
    return reduce1(lazy_reduce_u128((u128)a * (u128)b, p, barrett_hi, barrett_lo), p);
}

// ---------------------------------------------------------------------------
// NTT. One stage per launch; data is a k x n row-major matrix (k RNS rows).
// Per-row twiddle tables are concatenated: row r uses omegas[r*n .. r*n+n].
// Mirrors ntt::native::NttOperator::forward / backward.
// ---------------------------------------------------------------------------

// Forward NTT stage with butterfly distance l. Thread t handles butterfly
// j = t % (n/2) of row r = t / (n/2). reduce_out != 0 on the last stage
// (l == 1), where the CPU code fully reduces with reduce3.
extern "C" __global__ void ntt_fwd_stage(uint64_t *a, const uint64_t *omegas,
                                         const uint64_t *omegas_shoup,
                                         const uint64_t *moduli,
                                         unsigned int n, unsigned int k,
                                         unsigned int tab_off,
                                         unsigned int l, int reduce_out) {
    unsigned int half = n >> 1;
    unsigned long long t = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= (unsigned long long)k * half) return;
    unsigned int r = (unsigned int)(t / half);
    unsigned int j = (unsigned int)(t % half);

    unsigned int m = half / l;          // number of chunks in this stage
    unsigned int i = j / l;             // chunk index
    unsigned int s = 2 * i * l + (j % l); // index of x; y is at s + l

    unsigned int tr = r + tab_off;
    uint64_t p = moduli[tr];
    uint64_t p2 = p << 1;
    uint64_t w = omegas[(unsigned long long)tr * n + m + i];
    uint64_t w_shoup = omegas_shoup[(unsigned long long)tr * n + m + i];

    uint64_t *row = a + (unsigned long long)r * n;
    uint64_t x = row[s];
    uint64_t y = row[s + l];

    // NttOperator::butterfly
    x = reduce1(x, p2);
    uint64_t tt = lazy_mul_shoup(y, w, w_shoup, p);
    y = x + p2 - tt;
    x = x + tt;

    if (reduce_out) {
        // NttOperator::reduce3
        x = reduce1(reduce1(x, p2), p);
        y = reduce1(reduce1(y, p2), p);
    }

    row[s] = x;
    row[s + l] = y;
}

// Backward NTT stage with butterfly distance l. On the last stage
// (scale != 0, i.e. l == n/2 completed afterwards), the CPU code multiplies
// by size_inv; that is done by ntt_inv_final below to mirror the CPU's
// separate loop.
extern "C" __global__ void ntt_inv_stage(uint64_t *a, const uint64_t *zetas_inv,
                                         const uint64_t *zetas_inv_shoup,
                                         const uint64_t *moduli,
                                         unsigned int n, unsigned int k,
                                         unsigned int tab_off,
                                         unsigned int l) {
    unsigned int half = n >> 1;
    unsigned long long t = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= (unsigned long long)k * half) return;
    unsigned int r = (unsigned int)(t / half);
    unsigned int j = (unsigned int)(t % half);

    unsigned int m = half / l;            // chunks in this stage
    unsigned int i = j / l;               // chunk index
    unsigned int s = 2 * i * l + (j % l); // index of x; y is at s + l
    unsigned int start = n - 2 * m;       // first zeta index of this stage

    unsigned int tr = r + tab_off;
    uint64_t p = moduli[tr];
    uint64_t p2 = p << 1;
    uint64_t z = zetas_inv[(unsigned long long)tr * n + start + i];
    uint64_t z_shoup = zetas_inv_shoup[(unsigned long long)tr * n + start + i];

    uint64_t *row = a + (unsigned long long)r * n;
    uint64_t x = row[s];
    uint64_t y = row[s + l];

    // NttOperator::inv_butterfly
    uint64_t tt = x;
    x = reduce1(y + tt, p2);
    y = lazy_mul_shoup(p2 + tt - y, z, z_shoup, p);

    row[s] = x;
    row[s + l] = y;
}

// Final scaling of the backward NTT: a[i] = mul_shoup(a[i], size_inv).
extern "C" __global__ void ntt_inv_final(uint64_t *a, const uint64_t *size_inv,
                                         const uint64_t *size_inv_shoup,
                                         const uint64_t *moduli,
                                         unsigned int n, unsigned int k,
                                         unsigned int tab_off) {
    unsigned long long t = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= (unsigned long long)k * n) return;
    unsigned int r = (unsigned int)(t / n) + tab_off;
    a[t] = mul_shoup(a[t], size_inv[r], size_inv_shoup[r], moduli[r]);
}

// ---------------------------------------------------------------------------
// Element-wise operations on k x n matrices. Mirrors zq::Modulus::{add, sub,
// neg, mul, mul_shoup} applied row-wise (one modulus per row).
// ---------------------------------------------------------------------------

extern "C" __global__ void ew_add(uint64_t *a, const uint64_t *b,
                                  const uint64_t *moduli, unsigned int n,
                                  unsigned int k) {
    unsigned long long t = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= (unsigned long long)k * n) return;
    uint64_t p = moduli[t / n];
    a[t] = reduce1(a[t] + b[t], p);
}

extern "C" __global__ void ew_sub(uint64_t *a, const uint64_t *b,
                                  const uint64_t *moduli, unsigned int n,
                                  unsigned int k) {
    unsigned long long t = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= (unsigned long long)k * n) return;
    uint64_t p = moduli[t / n];
    a[t] = reduce1(a[t] + p - b[t], p);
}

extern "C" __global__ void ew_neg(uint64_t *a, const uint64_t *moduli,
                                  unsigned int n, unsigned int k) {
    unsigned long long t = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= (unsigned long long)k * n) return;
    uint64_t p = moduli[t / n];
    a[t] = reduce1(p - a[t], p);
}

extern "C" __global__ void ew_mul(uint64_t *a, const uint64_t *b,
                                  const uint64_t *moduli,
                                  const uint64_t *barrett_hi,
                                  const uint64_t *barrett_lo, unsigned int n,
                                  unsigned int k) {
    unsigned long long t = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= (unsigned long long)k * n) return;
    unsigned int r = (unsigned int)(t / n);
    a[t] = mul_barrett(a[t], b[t], moduli[r], barrett_hi[r], barrett_lo[r]);
}

extern "C" __global__ void ew_mul_shoup(uint64_t *a, const uint64_t *b,
                                        const uint64_t *b_shoup,
                                        const uint64_t *moduli, unsigned int n,
                                        unsigned int k) {
    unsigned long long t = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= (unsigned long long)k * n) return;
    a[t] = mul_shoup(a[t], b[t], b_shoup[t], moduli[t / n]);
}

// ---------------------------------------------------------------------------
// RNS scaling (rns::scaler::RnsScaler::scale), one thread per coefficient.
// 256-bit accumulators mirror the CPU's ethnum::U256 wrapping arithmetic.
// ---------------------------------------------------------------------------

struct u256 {
    u128 lo;
    u128 hi;
};

// acc += r * (t_hi << 64 | t_lo), a 64x128 -> 192-bit product (wrapping).
__device__ __forceinline__ void mac_64x128(u256 &acc, uint64_t r, uint64_t t_lo,
                                           uint64_t t_hi) {
    u128 p_lo = (u128)r * (u128)t_lo;       // 128-bit
    u128 p_hi = (u128)r * (u128)t_hi;       // contributes << 64
    u128 add_lo = p_lo + (p_hi << 64);
    u128 carry = add_lo < p_lo ? 1 : 0;
    u128 new_lo = acc.lo + add_lo;
    acc.hi += (p_hi >> 64) + carry + (new_lo < acc.lo ? 1 : 0);
    acc.lo = new_lo;
}

// acc -= r * (t_hi << 64 | t_lo) (wrapping).
__device__ __forceinline__ void msub_64x128(u256 &acc, uint64_t r, uint64_t t_lo,
                                            uint64_t t_hi) {
    u128 p_lo = (u128)r * (u128)t_lo;
    u128 p_hi = (u128)r * (u128)t_hi;
    u128 sub_lo = p_lo + (p_hi << 64);
    u128 carry = sub_lo < p_lo ? 1 : 0;
    u128 sub_hi = (p_hi >> 64) + carry;
    u128 new_lo = acc.lo - sub_lo;
    acc.hi -= sub_hi + (acc.lo < sub_lo ? 1 : 0);
    acc.lo = new_lo;
}

// acc op= v * (t_hi << 64 | t_lo) where v is 128-bit: full 128x128 product
// truncated to 256 bits (wrapping), added or subtracted.
__device__ __forceinline__ void mac_128x128(u256 &acc, u128 v, uint64_t t_lo,
                                            uint64_t t_hi, bool subtract) {
    uint64_t v_lo = (uint64_t)v;
    uint64_t v_hi = (uint64_t)(v >> 64);
    // (v_hi*2^64 + v_lo) * (t_hi*2^64 + t_lo)
    u128 ll = (u128)v_lo * (u128)t_lo;
    u128 lh = (u128)v_lo * (u128)t_hi;
    u128 hl = (u128)v_hi * (u128)t_lo;
    u128 hh = (u128)v_hi * (u128)t_hi; // contributes to hi only
    u256 p;
    p.lo = ll;
    p.hi = hh;
    // add (lh + hl) << 64 with carries
    u128 mid = lh + hl;
    u128 mid_carry = mid < lh ? ((u128)1 << 64) : 0; // overflow of 128-bit mid
    u128 add_lo = mid << 64;
    u128 new_lo = p.lo + add_lo;
    p.hi += (mid >> 64) + mid_carry + (new_lo < p.lo ? 1 : 0);
    p.lo = new_lo;
    if (subtract) {
        u128 res_lo = acc.lo - p.lo;
        acc.hi -= p.hi + (acc.lo < p.lo ? 1 : 0);
        acc.lo = res_lo;
    } else {
        u128 res_lo = acc.lo + p.lo;
        acc.hi += p.hi + (res_lo < acc.lo ? 1 : 0);
        acc.lo = res_lo;
    }
}

// (acc >> s) truncated to 128 bits, for 0 < s < 128.
__device__ __forceinline__ u128 shr256_to_u128(const u256 &acc, unsigned int s) {
    return (acc.lo >> s) | (acc.hi << (128 - s));
}

extern "C" __global__ void rns_scale(
    const uint64_t *in,         // k_from x n (power basis)
    uint64_t *out,              // k_write x n
    const uint64_t *to_moduli,  // full to-context tables, indexed start + i
    const uint64_t *to_barrett_hi, const uint64_t *to_barrett_lo,
    const uint64_t *gamma, const uint64_t *gamma_shoup,        // [k_to]
    const uint64_t *omega, const uint64_t *omega_shoup,        // [k_to][k_from]
    const uint64_t *theta_omega_lo, const uint64_t *theta_omega_hi,
    const uint64_t *theta_omega_sign,                          // [k_from]
    const uint64_t *theta_garner_lo, const uint64_t *theta_garner_hi, // [k_from]
    uint64_t theta_gamma_lo, uint64_t theta_gamma_hi,
    unsigned int theta_gamma_sign, unsigned int theta_garner_shift,
    unsigned int is_one, unsigned int n, unsigned int k_from,
    unsigned int k_write, unsigned int start) {
    unsigned int j = blockIdx.x * blockDim.x + threadIdx.x;
    if (j >= n) return;

    // v = round(sum(rests * theta_garner) / 2^shift)
    u256 sum_tg = {0, 0};
    for (unsigned int f = 0; f < k_from; f++) {
        mac_64x128(sum_tg, in[(unsigned long long)f * n + j], theta_garner_lo[f],
                   theta_garner_hi[f]);
    }
    u128 sv = shr256_to_u128(sum_tg, theta_garner_shift - 1);
    u128 v = (sv >> 1) + (sv & 1); // div_ceil(2)

    bool w_sign = false;
    u128 w = 0;
    if (!is_one) {
        u256 sum_to = {0, 0};
        for (unsigned int f = 0; f < k_from; f++) {
            uint64_t r = in[(unsigned long long)f * n + j];
            if (theta_omega_sign[f]) {
                msub_64x128(sum_to, r, theta_omega_lo[f], theta_omega_hi[f]);
            } else {
                mac_64x128(sum_to, r, theta_omega_lo[f], theta_omega_hi[f]);
            }
        }
        // sum_to -+= v * theta_gamma
        mac_128x128(sum_to, v, theta_gamma_lo, theta_gamma_hi,
                    theta_gamma_sign == 0);
        // w = round(sum_to / 2^192), with sign
        w_sign = (sum_to.hi >> 63) != 0;
        if (w_sign) {
            u256 inv = {~sum_to.lo, ~sum_to.hi};
            w = shr256_to_u128(inv, 126) + 1;
            w >>= 1;
        } else {
            w = shr256_to_u128(sum_to, 126);
            w = (w >> 1) + (w & 1); // div_ceil(2)
        }
    }

    for (unsigned int i = 0; i < k_write; i++) {
        unsigned int t = start + i;
        uint64_t q = to_moduli[t];
        uint64_t bhi = to_barrett_hi[t];
        uint64_t blo = to_barrett_lo[t];

        uint64_t v_mod = reduce1(lazy_reduce_u128(v, q, bhi, blo), q);
        u128 yi = (u128)(2 * q - lazy_mul_shoup(v_mod, gamma[t], gamma_shoup[t], q));

        if (!is_one) {
            uint64_t wi = lazy_reduce_u128(w, q, bhi, blo);
            yi += (u128)(w_sign ? 2 * q - wi : wi);
        }

        for (unsigned int f = 0; f < k_from; f++) {
            yi += (u128)lazy_mul_shoup(in[(unsigned long long)f * n + j],
                                       omega[(unsigned long long)t * k_from + f],
                                       omega_shoup[(unsigned long long)t * k_from + f], q);
        }

        out[(unsigned long long)i * n + j] = reduce1(lazy_reduce_u128(yi, q, bhi, blo), q);
    }
}

// ---------------------------------------------------------------------------
// Fused key switching support.
// ---------------------------------------------------------------------------

// zq::Modulus::lazy_reduce (u64 input, output in [0, 2p)).
__device__ __forceinline__ uint64_t lazy_reduce_u64(uint64_t a, uint64_t p,
                                                    uint64_t barrett_hi,
                                                    uint64_t barrett_lo) {
    u128 p_lo_lo = ((u128)a * (u128)barrett_lo) >> 64;
    u128 p_lo_hi = (u128)a * (u128)barrett_hi;
    u128 q = (p_lo_hi + p_lo_lo) >> 64;
    return (uint64_t)((u128)a - q * (u128)p);
}

// zq::Modulus::lazy_reduce_opt (only valid when the modulus supports it).
__device__ __forceinline__ uint64_t lazy_reduce_opt_u64(uint64_t a, uint64_t p,
                                                        unsigned int leading_zeros) {
    uint64_t q = a >> (64 - leading_zeros);
    return a - q * p;
}

// Broadcast one length-n row into k rows, lazily reduced per row modulus.
// Mirrors Modulus::lazy_reduce_vec (including its supports_opt branch).
extern "C" __global__ void broadcast_lazy_reduce(
    uint64_t *out, const uint64_t *in, const uint64_t *moduli,
    const uint64_t *barrett_hi, const uint64_t *barrett_lo,
    const uint64_t *supports_opt, const uint64_t *leading_zeros,
    unsigned int n, unsigned int k) {
    unsigned long long t = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= (unsigned long long)k * n) return;
    unsigned int r = (unsigned int)(t / n);
    unsigned int j = (unsigned int)(t % n);
    uint64_t p = moduli[r];
    uint64_t a = in[j];
    out[t] = supports_opt[r]
                 ? lazy_reduce_opt_u64(a, p, (unsigned int)leading_zeros[r])
                 : lazy_reduce_u64(a, p, barrett_hi[r], barrett_lo[r]);
}

// acc = add(acc, mul_shoup(a, b)): the inner statement of the key-switch
// accumulation (Poly<Ntt> += &Poly<Ntt> * &Poly<NttShoup>). `a` may hold
// lazy (< 4p) coefficients; Shoup multiplication reduces them exactly like
// the CPU's mul_shoup_vec.
extern "C" __global__ void ew_mul_shoup_acc(uint64_t *acc, const uint64_t *a,
                                            const uint64_t *b,
                                            const uint64_t *b_shoup,
                                            const uint64_t *moduli,
                                            unsigned int n, unsigned int k) {
    unsigned long long t = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= (unsigned long long)k * n) return;
    uint64_t p = moduli[t / n];
    uint64_t prod = mul_shoup(a[t], b[t], b_shoup[t], p);
    acc[t] = reduce1(acc[t] + prod, p);
}

// ---------------------------------------------------------------------------
// Fused NTT stages in shared memory. One block of 256 threads owns one
// 512-element tile; all butterfly stages with distance l <= 256 stay inside
// the tile, so they run back-to-back with __syncthreads() instead of one
// kernel launch per stage. The arithmetic per butterfly is identical to the
// per-stage kernels (and to the CPU), in the same stage order, so results
// are bit-exact.
// ---------------------------------------------------------------------------

#define FUSED_TILE 512u
#define FUSED_THREADS 256u

// Forward NTT stages l = 256, 128, ..., 1. reduce_out mirrors the CPU's
// reduce3 on the last stage (0 for the lazy variant used in key switching).
extern "C" __global__ void ntt_fwd_fused_tail(uint64_t *a, const uint64_t *omegas,
                                              const uint64_t *omegas_shoup,
                                              const uint64_t *moduli,
                                              unsigned int n, unsigned int k,
                                              unsigned int tab_off,
                                              int reduce_out) {
    __shared__ uint64_t tile[FUSED_TILE];
    unsigned int tiles_per_row = n / FUSED_TILE;
    unsigned int r = blockIdx.x / tiles_per_row;
    if (r >= k) return;
    unsigned int tile_in_row = blockIdx.x % tiles_per_row;
    unsigned long long base = (unsigned long long)r * n + (unsigned long long)tile_in_row * FUSED_TILE;
    unsigned int tid = threadIdx.x;

    tile[tid] = a[base + tid];
    tile[tid + FUSED_THREADS] = a[base + tid + FUSED_THREADS];
    __syncthreads();

    unsigned int tr = r + tab_off;
    uint64_t p = moduli[tr];
    uint64_t p2 = p << 1;
    const uint64_t *om = omegas + (unsigned long long)tr * n;
    const uint64_t *oms = omegas_shoup + (unsigned long long)tr * n;

    for (unsigned int l = FUSED_TILE / 2; l >= 1; l >>= 1) {
        unsigned int i_loc = tid / l;
        unsigned int pos = tid % l;
        unsigned int s = 2 * i_loc * l + pos;
        unsigned int m = (n >> 1) / l;
        unsigned int i_glob = tile_in_row * (FUSED_THREADS / l) + i_loc;
        uint64_t w = om[m + i_glob];
        uint64_t w_shoup = oms[m + i_glob];

        uint64_t x = tile[s];
        uint64_t y = tile[s + l];
        x = reduce1(x, p2);
        uint64_t tt = lazy_mul_shoup(y, w, w_shoup, p);
        y = x + p2 - tt;
        x = x + tt;
        if (l == 1 && reduce_out) {
            x = reduce1(reduce1(x, p2), p);
            y = reduce1(reduce1(y, p2), p);
        }
        tile[s] = x;
        tile[s + l] = y;
        __syncthreads();
        if (l == 1) break;
    }

    a[base + tid] = tile[tid];
    a[base + tid + FUSED_THREADS] = tile[tid + FUSED_THREADS];
}

// Backward NTT stages l = 1, 2, ..., 256.
extern "C" __global__ void ntt_inv_fused_head(uint64_t *a, const uint64_t *zetas_inv,
                                              const uint64_t *zetas_inv_shoup,
                                              const uint64_t *moduli,
                                              unsigned int n, unsigned int k,
                                              unsigned int tab_off) {
    __shared__ uint64_t tile[FUSED_TILE];
    unsigned int tiles_per_row = n / FUSED_TILE;
    unsigned int r = blockIdx.x / tiles_per_row;
    if (r >= k) return;
    unsigned int tile_in_row = blockIdx.x % tiles_per_row;
    unsigned long long base = (unsigned long long)r * n + (unsigned long long)tile_in_row * FUSED_TILE;
    unsigned int tid = threadIdx.x;

    tile[tid] = a[base + tid];
    tile[tid + FUSED_THREADS] = a[base + tid + FUSED_THREADS];
    __syncthreads();

    unsigned int tr = r + tab_off;
    uint64_t p = moduli[tr];
    uint64_t p2 = p << 1;
    const uint64_t *ze = zetas_inv + (unsigned long long)tr * n;
    const uint64_t *zes = zetas_inv_shoup + (unsigned long long)tr * n;

    for (unsigned int l = 1; l <= FUSED_TILE / 2; l <<= 1) {
        unsigned int i_loc = tid / l;
        unsigned int pos = tid % l;
        unsigned int s = 2 * i_loc * l + pos;
        unsigned int m = (n >> 1) / l;
        unsigned int start = n - 2 * m;
        unsigned int i_glob = tile_in_row * (FUSED_THREADS / l) + i_loc;
        uint64_t z = ze[start + i_glob];
        uint64_t z_shoup = zes[start + i_glob];

        uint64_t x = tile[s];
        uint64_t y = tile[s + l];
        uint64_t tt = x;
        x = reduce1(y + tt, p2);
        y = lazy_mul_shoup(p2 + tt - y, z, z_shoup, p);
        tile[s] = x;
        tile[s + l] = y;
        __syncthreads();
    }

    a[base + tid] = tile[tid];
    a[base + tid + FUSED_THREADS] = tile[tid + FUSED_THREADS];
}
