#ifndef SHA_H
#define SHA_H

#include <QObject>
#include <gmpxx.h>

#define SHR(x,n)    (x >> n)
#define ROTR(x,n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))

class sha : public QObject
{
    Q_OBJECT
public:
    explicit sha(QObject *parent = nullptr);
    Q_INVOKABLE void updateFile(const QString &path);
    Q_INVOKABLE void update(const QByteArray &bytes);
    Q_INVOKABLE QString hexdigest();
    Q_INVOKABLE void reset();
    void test();

signals:

public slots:

private:
    void blk_proc(size_t blk_start);
    void f(uint64_t *const s, char *const mi);
    void r(uint64_t *const s, uint64_t wt, uint64_t kt);
    inline void add(uint64_t *const s, uint64_t *const a);
    inline uint64_t sigma0(uint64_t x);
    inline uint64_t sigma1(uint64_t x);
    inline uint64_t sigmaa(uint64_t x);
    inline uint64_t sigmae(uint64_t x);
    inline uint64_t ch(uint64_t e, uint64_t f, uint64_t g);
    inline uint64_t maj(uint64_t a, uint64_t b, uint64_t c);

    QByteArray bytes;
    mpz_class len;

    uint64_t s[8];

    static const uint64_t iv[8];
    static const uint64_t k[80];
};

#endif // SHA_H
