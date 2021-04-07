#pragma once
#include <sodium.h>
#include "fieldscalar_interface.hpp"

typedef unsigned char hashval_t[crypto_hash_sha512_BYTES];
typedef unsigned char ristpoint_t[crypto_core_ristretto255_BYTES];

struct Ristretto25519
{
    ristpoint_t point;

    Ristretto25519() = default;

    static Ristretto25519 fromHash(const hashval_t&);
    static Ristretto25519 fromScalar(const Field25519&);
    static Ristretto25519 fromPoint(const ristpoint_t&);
    static bool isValid(const ristpoint_t& p)
    {
        return crypto_core_ristretto255_is_valid_point(p);
    }

    Ristretto25519 operator+(const Ristretto25519&) const;
    Ristretto25519 operator-(const Ristretto25519&) const;
    Ristretto25519 operator*(const Field25519&) const;

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