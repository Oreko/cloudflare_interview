#include "ristretto_interface.hpp"
#include <cstring>

Ristretto25519 Ristretto25519::fromHash(const hashval_t& h)
{
    Ristretto25519 result;
    crypto_core_ristretto255_from_hash(result.point, h);
    return result;
}

Ristretto25519 Ristretto25519::fromScalar(const Field25519& s)
{
    Ristretto25519 result;
    crypto_scalarmult_ristretto255_base(result.point, s.element);
    return result;
}

Ristretto25519 Ristretto25519::fromPoint(const ristpoint_t& p)
{
    // I don't like using memcpy like this, but for a local project this is ok.
    Ristretto25519 result;
    memcpy(result.point, p, crypto_core_ristretto255_BYTES);
    return result;
}

Ristretto25519 Ristretto25519::operator+(const Ristretto25519& b) const
{
    Ristretto25519 result;
    crypto_core_ristretto255_add(result.point, point, b.point);
    return result;
}

Ristretto25519 Ristretto25519::operator-(const Ristretto25519& b) const
{
    Ristretto25519 result;
    crypto_core_ristretto255_sub(result.point, point, b.point);
    return result;
}

Ristretto25519 operator*(const Field25519& a, const Ristretto25519& b)
{
    Ristretto25519 result;
    crypto_scalarmult_ristretto255(result.point, a.element, b.point);
    return result;
}

bool Ristretto25519::operator==(const Ristretto25519& cmp) const
{
    return sodium_memcmp(point, cmp.point, crypto_core_ristretto255_BYTES) == 0;
}