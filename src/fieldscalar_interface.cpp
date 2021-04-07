#include "fieldscalar_interface.hpp"

Field25519 Field25519::randomScalar(void)
{
    Field25519 return_val;
    crypto_core_ristretto255_scalar_random(return_val.element);
    return return_val;
}

bool Field25519::iszero(void) const
{
    return sodium_is_zero(element, size);
}

Field25519 Field25519::inverse(void) const
{
    Field25519 result;
    crypto_core_ristretto255_scalar_invert(result.element, element);
    return result;
}

Field25519 Field25519::negate(void) const
{
    Field25519 result;
    crypto_core_ristretto255_scalar_negate(result.element, element);
    return result;
}

Field25519 Field25519::operator+(const Field25519& b) const
{
    Field25519 result;
    crypto_core_ristretto255_scalar_add(result.element, element, b.element);
    return result;
}

Field25519 Field25519::operator-(const Field25519& b) const
{
    Field25519 result;
    crypto_core_ristretto255_scalar_sub(result.element, element, b.element);
    return result;
}

Field25519 operator*(const Field25519& a, const Field25519& b)
{
    Field25519 result;
    crypto_core_ristretto255_scalar_mul(result.element, a.element, b.element);
    return result;
}

bool Field25519::operator==(const Field25519& cmp) const
{
    return sodium_memcmp(element, cmp.element, size) == 0;
}