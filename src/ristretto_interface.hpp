#pragma once
#include <sodium.h>
#include "fieldscalar_interface.hpp"

typedef unsigned char hashval_t[crypto_hash_sha512_BYTES];
typedef unsigned char ristpoint_t[crypto_core_ristretto255_BYTES];
// It may be a good idea to encapsulate these types. We currently have the constant values running around and we shouldn't as it leads to difficulty in updating.

struct Ristretto25519;

Ristretto25519 operator*(const Field25519&, const Ristretto25519&);

struct Ristretto25519
{
    ristpoint_t point;

    Ristretto25519() : point{0} {};

    static Ristretto25519 fromHash(const hashval_t&);
    static Ristretto25519 fromScalar(const Field25519&);
    static Ristretto25519 fromPoint(const ristpoint_t&);
    static bool isValid(const ristpoint_t& p)
    {
        return crypto_core_ristretto255_is_valid_point(p);
    }

    Ristretto25519 operator+(const Ristretto25519&) const;
    Ristretto25519 operator-(const Ristretto25519&) const;
    Ristretto25519 operator*(const Field25519& b) const
    {
        return b * *this;
    }

    Ristretto25519& operator+=(const Ristretto25519& p)
    {
        *this = *this + p;
        return *this;
    }

    Ristretto25519& operator-=(const Ristretto25519& p)
    {
        *this = *this - p;
        return *this;
    }

    Ristretto25519& operator*=(const Field25519& p)
    {
        *this = *this * p;
        return *this;
    }

    bool operator==(const Ristretto25519& cmp) const;
    bool operator!=(const Ristretto25519& cmp) const
    {
        return !(*this == cmp);
    }
};