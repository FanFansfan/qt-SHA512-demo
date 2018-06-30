#include "sha.h"
#include <QDebug>
#include <QFile>
#include <QUrl>
#include <QDir>

static inline uint64_t bswap_64(uint64_t x) {
    x= ((x<< 8)&0xFF00FF00FF00FF00ULL) | ((x>> 8)&0x00FF00FF00FF00FFULL);
    x= ((x<<16)&0xFFFF0000FFFF0000ULL) | ((x>>16)&0x0000FFFF0000FFFFULL);
    return (x>>32) | (x<<32);
}

sha::sha(QObject *parent) : QObject(parent)
{
    len = 0;
    memcpy(s, iv, 512 / 8);
}

const uint64_t sha::k[80] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
        0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
        0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
        0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
        0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
        0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
        0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
        0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
        0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
        0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
        0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
        0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
        0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
        0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
        0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
        0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
        0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
        0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
        0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
        0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
        0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
    };

const uint64_t sha::iv[8] = {
    0x6a09e667f3bcc908ULL,
    0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL,
    0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL,
    0x5be0cd19137e2179ULL
};

void sha::update(const QByteArray &n)
{
    //qDebug() << n;
    bytes.append(n);
    len += n.length();

    const size_t blk_siz = 1024 / 8;
    const size_t blk_num = bytes.length() / blk_siz;
    qDebug() << "update(): blk_num : " << blk_num;
    // process 1024bit(a block)
    for(size_t i = 0; i < blk_num; ++i)
    {
        blk_proc(i * blk_siz);
    }
    bytes.remove(0, blk_siz * blk_num);
}

void sha::updateFile(const QString &path)
{
    const QUrl url(path);
    if (url.isLocalFile()) {
        QFile file(QDir::toNativeSeparators(url.toLocalFile()));
        if(!file.open(QIODevice::ReadOnly))
            assert(false);
        qint64 _siz = file.size(), blk_siz = 1024 * 1024 * 512, offset = 0;
        qDebug() << "file size:" << _siz;
        while(_siz > 0)
        {
            qint64 read_siz = _siz > blk_siz ? blk_siz : _siz;
            const char *fpr = (const char*)file.map(offset, read_siz);
            _siz -= read_siz;
            offset += read_siz;
            update(QByteArray::fromRawData(fpr, read_siz));
        }
    }
}

// get the final hash
QString sha::hexdigest()
{
    const size_t blk_siz = 1024 / 8;
    const size_t msg_len_field_siz = 128 / 8;

    size_t pad_len = blk_siz - msg_len_field_siz - bytes.length();

    // padding
    bytes.push_back(0x80);
    bytes.append(QByteArray(pad_len-1, 0x00));

    len *= 8;
    QByteArray msg_len(msg_len_field_siz, 0x00);
    int offset = msg_len_field_siz - (mpz_sizeinbase(len.get_mpz_t(), 2) + 8 - 1) / 8;
    assert(offset >= 0);
    mpz_export(msg_len.data()+offset, NULL, 1, sizeof(char), 0, 0, len.get_mpz_t());
    bytes.append(msg_len);
    qDebug() << "hexdigest() : " << bytes << " : " << msg_len << ": " << mpz_sizeinbase(len.get_mpz_t(), 2);
    assert(bytes.length() == blk_siz);
    // remember the last block
    blk_proc(0);

    QString res;
    res.sprintf("%llx%llx%llx%llx%llx%llx%llx%llx",
                s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]);
    // reset state after user pull result
    reset();
    qDebug() << "hexdigest() : " << res;
    return res;
}

void sha::blk_proc(size_t blk_start)
{
    uint64_t n[8];
    memcpy(n, s, sizeof(uint64_t) * 8);
    f(n, bytes.data() + blk_start);
    add(s, n);
}

void sha::reset()
{
    memcpy(s, iv, 512 / 8);
    bytes.remove(0, bytes.length());
    len = 0;
}

void sha::f(uint64_t *const s, char *const mi)
{
    uint64_t w[80];
    memcpy(w, mi, 1024 / 8);
    for(int i = 0; i < 16; ++i)
    {
        // x86 is little endian, while sha512 assumes it's buffer is big edian
        w[i] = bswap_64(w[i]);
    }
//    for(int i = 0; i < 16; ++i)
//    {
//        qDebug() << "w" << i << ":" << QString().sprintf("%llx", w[i]);
//    }

    for(int i = 16; i < 80; ++i)
        w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];

    for(int i = 0; i < 80; ++i)
    {
//        if(i == 0 || i == 1 || i == 3)
//        {
//             qDebug() << QString().sprintf("f(): "
//                                          "a: %llx "
//                                          "b: %llx "
//                                          "c: %llx "
//                                          "d: %llx "
//                                          "e: %llx "
//                                          "f: %llx "
//                                          "g: %llx "
//                                          "h: %llx ", s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]);
//        }
        r(s, w[i], k[i]);
    }
}

// round func
void sha::r(uint64_t *const s, uint64_t wt, uint64_t kt)
{
    uint64_t T1 = s[7] + ch(s[4], s[5], s[6]) + sigmae(s[4]) + wt + kt;
    uint64_t T2 = sigmaa(s[0]) + maj(s[0], s[1], s[2]);
    //qDebug() << QString().sprintf("wt: %llx, T1: %llx, T2: %llx, ch:%llx, e:%llx", wt, T1, T2, ch(s[4], s[5], s[6]), sigmae(s[4]));

    s[7] = s[6];
    s[6] = s[5];
    s[5] = s[4];
    s[4] = s[3] + T1;
    s[3] = s[2];
    s[2] = s[1];
    s[1] = s[0];
    s[0] = T1 + T2;
}

inline void sha::add(uint64_t *const s, uint64_t *const a)
{
    for(int i = 0; i < 8; ++i)
    {
        s[i] += a[i];
    }
}

inline uint64_t sha::sigma0(uint64_t x)
{
    return ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7);
}

inline uint64_t sha::sigma1(uint64_t x)
{
    return ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6);
}

inline uint64_t sha::sigmaa(uint64_t x)
{
    return ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39);
}

inline uint64_t sha::sigmae(uint64_t x)
{
    return ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41);
}

inline uint64_t sha::ch(uint64_t e, uint64_t f, uint64_t g)
{
    return (e & f) ^ (~e & g);
}

inline uint64_t sha::maj(uint64_t a, uint64_t b, uint64_t c)
{
    return (a & b) ^ (a & c) ^ (b & c);
}

void sha::test()
{
//    qDebug() << "test():";
//    QByteArray t("abc");
//    //assert(t.length() == 3);
//    update(t);
//    qDebug() << hexdigest();
}
