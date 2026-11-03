/* guard_file_seal.c — Lane 7：文件封印（原引擎 guard.c 第三泳道还原）。
 *
 * 机制：构建期对最终二进制（含 ai-decoy 拖车、不含封印块自身）计算
 * SHA-256，追加封印块 [hashed_len(8B)][digest(32B)][magic(8B)] 到文件尾。
 * 运行期构造器（优先级 102，在 deny-attach(101) 之后）：
 *   1. 裸 syscall 打开 /proc/self/exe（防 LD_PRELOAD 挂钩 open/read）
 *   2. 读文件尾 48 字节 → 校验 magic → 取 hashed_len + digest
 *   3. 重算 file[0:hashed_len] 的 SHA-256 → 比对烤入摘要
 *   4. 不匹配（任何字节被 patch，包括其它守卫/比较分支/运行时代码）
 *      → exit_group(174)；打不开文件同样拒绝（fail-closed）
 *
 * 诚实边界：自校验的引导问题——封印校验器自身也在被哈希范围内，
 * patch 校验器本身可使其失效（但攻击者必须先定位并理解它）；
 * 与 deny-attach/integrity 互为成本叠加。摘要不覆盖封印块自身
 * （否则鸡生蛋），封印块被篡改由 magic 校验兜底。
 */

static long __seal_sys3(long n, long a, long b, long c)
{
    long r;
    __asm__ volatile("syscall"
                     : "=a"(r)
                     : "a"(n), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return r;
}

#define SEAL_SYS_read       0
#define SEAL_SYS_openat     257
#define SEAL_SYS_close      3
#define SEAL_SYS_exit_group 231
#define SEAL_AT_FDCWD       (-100)
#define SEAL_O_RDONLY       0
#define SEAL_EXIT           174

/* ---- 紧凑 SHA-256（公有领域风格，自包含无 libc）---- */
typedef struct {
    unsigned int h[8];
    unsigned long long len;
    unsigned char buf[64];
    unsigned int buflen;
} sha256_ctx;

static const unsigned int K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_init(sha256_ctx *c)
{
    static const unsigned int H0[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,
        0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    for (int i = 0; i < 8; i++) c->h[i] = H0[i];
    c->len = 0; c->buflen = 0;
}

static void sha256_block(sha256_ctx *c, const unsigned char *p)
{
    unsigned int w[64], a, b, cc, d, e, f, g, h, t1, t2;
    for (int i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[i*4] << 24) | ((unsigned int)p[i*4+1] << 16)
             | ((unsigned int)p[i*4+2] << 8) | (unsigned int)p[i*4+3];
    for (int i = 16; i < 64; i++) {
        unsigned int s0 = ROTR(w[i-15],7) ^ ROTR(w[i-15],18) ^ (w[i-15] >> 3);
        unsigned int s1 = ROTR(w[i-2],17) ^ ROTR(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=c->h[0]; b=c->h[1]; cc=c->h[2]; d=c->h[3];
    e=c->h[4]; f=c->h[5]; g=c->h[6]; h=c->h[7];
    for (int i = 0; i < 64; i++) {
        unsigned int S1 = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25);
        unsigned int ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + K[i] + w[i];
        unsigned int S0 = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22);
        unsigned int mj = (a & b) ^ (a & cc) ^ (b & cc);
        t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
    c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}

static void sha256_update(sha256_ctx *c, const unsigned char *p, unsigned long n)
{
    c->len += n;
    while (n) {
        unsigned int take = 64 - c->buflen;
        if (take > n) take = (unsigned int)n;
        for (unsigned int i = 0; i < take; i++)
            c->buf[c->buflen + i] = p[i];
        c->buflen += take; p += take; n -= take;
        if (c->buflen == 64) { sha256_block(c, c->buf); c->buflen = 0; }
    }
}

static void sha256_final(sha256_ctx *c, unsigned char out[32])
{
    unsigned long long bits = c->len * 8;
    unsigned char pad = 0x80;
    sha256_update(c, &pad, 1);
    pad = 0;
    while (c->buflen != 56) sha256_update(c, &pad, 1);
    unsigned char lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (unsigned char)(bits >> (56 - i*8));
    sha256_update(c, lenb, 8);            /* buflen==64 → 已消费 */
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (unsigned char)(c->h[i] >> 24);
        out[i*4+1] = (unsigned char)(c->h[i] >> 16);
        out[i*4+2] = (unsigned char)(c->h[i] >> 8);
        out[i*4+3] = (unsigned char)(c->h[i]);
    }
}

/* ---- 封印校验 ---- */
static void __sdk_seal_init(void) __attribute__((constructor(102)));

static void __sdk_seal_init(void)
{
    long fd = __seal_sys3(SEAL_SYS_openat, SEAL_AT_FDCWD,
                          (long)"/proc/self/exe", SEAL_O_RDONLY);
    if (fd < 0)
        __seal_sys3(SEAL_SYS_exit_group, SEAL_EXIT, 0, 0);   /* fail-closed */

    /* 第一遍：只取文件尾 48 字节（封印块） */
    unsigned char buf[4096];
    unsigned char tail[48];
    unsigned char magic_ref[8] = {0x53,0x45,0x41,0x4c,0x42,0x4c,0x41,0x31};
    unsigned char digest_ref[32];
    int have_tail = 0;

    for (;;) {
        long n = __seal_sys3(SEAL_SYS_read, fd, (long)buf,
                             (long)sizeof(buf));
        if (n <= 0) break;
        if (n >= 48) {
            for (int i = 0; i < 48; i++) tail[i] = buf[n - 48 + i];
            have_tail = 1;
        } else {
            /* EOF 短读：滑动合并尾部窗口 */
            unsigned char tmp[96];
            for (int i = 0; i < 48; i++) tmp[i] = tail[i];
            for (int i = 0; i < n; i++) tmp[48 + i] = buf[i];
            for (int i = 0; i < 48; i++) tail[i] = tmp[n + i];
        }
    }
    __seal_sys3(SEAL_SYS_close, fd, 0, 0);

    if (!have_tail)
        __seal_sys3(SEAL_SYS_exit_group, SEAL_EXIT, 0, 0);

    /* tail = [hashed_len(8)][digest(32)][magic(8)] */
    for (int i = 0; i < 8; i++)
        if (tail[40 + i] != magic_ref[i])
            __seal_sys3(SEAL_SYS_exit_group, SEAL_EXIT, 0, 0);
    unsigned long long hlen = 0;
    for (int i = 0; i < 8; i++)
        hlen = (hlen << 8) | tail[i];
    for (int i = 0; i < 32; i++)
        digest_ref[i] = tail[8 + i];

    /* 第二遍：精确哈希 [0, hlen) 并比对 */
    sha256_ctx ctx;
    sha256_init(&ctx);
    fd = __seal_sys3(SEAL_SYS_openat, SEAL_AT_FDCWD,
                     (long)"/proc/self/exe", SEAL_O_RDONLY);
    if (fd < 0)
        __seal_sys3(SEAL_SYS_exit_group, SEAL_EXIT, 0, 0);
    unsigned long long done = 0;
    while (done < hlen) {
        long want = (hlen - done) > sizeof(buf)
                    ? (long)sizeof(buf) : (long)(hlen - done);
        long n = __seal_sys3(SEAL_SYS_read, fd, (long)buf, want);
        if (n <= 0) break;
        sha256_update(&ctx, buf, (unsigned long)n);
        done += (unsigned long long)n;
    }
    __seal_sys3(SEAL_SYS_close, fd, 0, 0);
    if (done != hlen)
        __seal_sys3(SEAL_SYS_exit_group, SEAL_EXIT, 0, 0);

    unsigned char digest[32];
    sha256_final(&ctx, digest);
    int seal_ok = 1;
    for (int i = 0; i < 32; i++)
        if (digest[i] != digest_ref[i]) { seal_ok = 0; break; }

    /* Reject mismatches independently of optional VM poison consumers.
     * A valid seal must not mutate execution state. */
    if (!seal_ok)
        __seal_sys3(SEAL_SYS_exit_group, SEAL_EXIT, 0, 0);
}