#pragma once
#include <sodium.h>
#include <cstring>

struct Field25519
{
    static const size_t size = crypto_core_ristretto255_SCALARBYTES;
    unsigned char element[size];

    Field25519() = default;
    Field25519(const unsigned char *serial)
    {
        crypto_core_ristretto255_scalar_reduce(element, serial);
    }

    bool iszero(void) const;

    static Field25519 randomScalar(void);
    Field25519 negate(void) const;
    Field25519 inverse(void) const;

    Field25519 operator+(const Field25519&) const;
    Field25519 operator-(const Field25519&) const;
    Field25519 operator*(const Field25519&) const;
    Field25519 operator/(const Field25519& b) const
    {
        return *this * b.inverse();
    }

    Field25519& operator+=(const Field25519& p)
    {
        *this = *this + p;
        return *this;
    }

    Field25519& operator-=(const Field25519& p)
    {
        *this = *this - p;
        return *this;
    }

    Field25519& operator*=(const Field25519& p)
    {
        *this = *this * p;
        return *this;
    }

    bool operator==(const Field25519& cmp) const;
    bool operator!=(const Field25519& cmp) const
    {
        return !(*this == cmp);
    }
};