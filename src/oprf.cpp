#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "oprf.hpp"

namespace OPRF
{
    WeakVOprfReceiver::WeakVOprfReceiver(const unsigned int sid, const unsigned int ssid, const unsigned int uid, Ristretto25519 publicKey)
    {
        // This is technically not perfectly aligned with the standard as per the exact form of the domain separation string.
        char context_string_base[27] = "WVOPRF-ristretto255-sha512";
        sprintf(contextString, "%s-%020d-%020d-%020d", context_string_base, sid, ssid, uid);
        contextLength = strlen(contextString);
        pkS = publicKey;
    }

    void sha512helper(hashval_t dst, char const* context, size_t contextlength, unsigned char const* src, size_t srclength)
    {
        crypto_hash_sha512_state state;

        crypto_hash_sha512_init(&state);
        
        // This c style casting is a reinterpret cast under the hood which technically is undefined here, but this is what we see libsodium doing...
        // At some point it would be best to just decompose everything into raw bytes upstream instead. 
        crypto_hash_sha512_update(&state, (const unsigned char *) context, contextlength);
        crypto_hash_sha512_update(&state, src, srclength);

        crypto_hash_sha512_final(&state, dst);
    }

    void WeakVOprfReceiver::blind(const ClientInput& input, size_t length, Blind& blinding, Ristretto25519& blindedElement)
    {
        Field25519 r = Field25519::randomScalar();
        Field25519 a = Field25519::randomScalar();

        char domainSeparation[CONTEXT_MAX + 12]{0};
        sprintf(domainSeparation, "VOPRF-Blind-%s",contextString);

        hashval_t hashOutput;
        sha512helper(hashOutput, domainSeparation, strlen(domainSeparation), input, length);
        Ristretto25519 T = Ristretto25519::fromHash(hashOutput);
        Ristretto25519 A = Ristretto25519::fromScalar(a);
        Ristretto25519 R = (T - A) * r;
        memcpy(blindedElement.point, R.point, crypto_core_ristretto255_BYTES);
        blinding.blind1 = r;
        blinding.blind2 = a;
    }

    Ristretto25519 WeakVOprfReceiver::unblind(const Blind& blind, const Ristretto25519& evaluatedElement)
    {
        Ristretto25519 Z = Ristretto25519::fromPoint(evaluatedElement.point);
        Field25519 r_inv = blind.blind1.inverse();
        Ristretto25519 unblinded_element = (Z * r_inv) + (pkS * blind.blind2);
        return unblinded_element;
    }

    void WeakVOprfReceiver::finalize(const ClientInput &input,
                                     const size_t length,
                                     const Blind& blinding,
                                     const SerializedElement &evaluatedElement,
                                     hashval_t &returnVal)
    {
        Ristretto25519 tempElem = Ristretto25519::fromPoint(evaluatedElement);
        Ristretto25519 unblindedElement = unblind(blinding, tempElem);

        char domainSeparation[CONTEXT_MAX + 16 + 2*crypto_core_ristretto255_BYTES + 1]{'\0'};
        // quick and dirty, I need to write a more robust version of this.
        char unblindedHex[2 * crypto_core_ristretto255_BYTES + 1];
        sodium_bin2hex(unblindedHex, 2 * crypto_core_ristretto255_BYTES + 1, unblindedElement.point, crypto_core_ristretto255_BYTES);
        sprintf(domainSeparation, "%s-VOPRF-Finalize-%s", unblindedHex, contextString);

        sha512helper(returnVal, domainSeparation, strlen(domainSeparation), input, length);
    }

    WeakVOprfSender::WeakVOprfSender(const unsigned int sid, const unsigned int ssid, const unsigned int uid)
    {
        // This is technically not perfectly aligned with the standard as per the exact form of the domain separation string.
        // Also would be better to write a dedicated function for sprintf-malloc and just use move to byte arrays directly. 
        char context_string_base[27] = "WVOPRF-ristretto255-sha512";
        sprintf(contextString, "%s-%020d-%020d-%020d", context_string_base, sid, ssid, uid);
        contextLength = strlen(contextString);
    }

    void WeakVOprfSender::evaluate(const PrivateKey& skS, const SerializedElement& blindedElement, SerializedElement& returnVal)
    {
        Ristretto25519 R = Ristretto25519::fromPoint(blindedElement);
        Ristretto25519 Z = R * skS;
        memcpy(returnVal, Z.point, crypto_core_ristretto255_BYTES);
    }

    void WeakVOprfSender::full_evaluate(const PrivateKey& skS, const ClientInput& input, const size_t length, hashval_t& returnVal)
    {   
        hashval_t hashOutput;
        sha512helper(hashOutput, "", 0, input, length);
        Ristretto25519 P = Ristretto25519::fromHash(hashOutput);

        Ristretto25519 T = P * skS;

        char domainSeparation[CONTEXT_MAX + 16 + crypto_core_ristretto255_BYTES]{'\0'};
        // quick and dirty, I need to write a more robust version of this.
        char THex[2 * crypto_core_ristretto255_BYTES + 1];
        sodium_bin2hex(THex, 2 * crypto_core_ristretto255_BYTES + 1, T.point, crypto_core_ristretto255_BYTES);
        sprintf(domainSeparation, "%s-VOPRF-Finalize-%s", THex, contextString);

        sha512helper(returnVal, domainSeparation, strlen(domainSeparation), input, length);

    }

    bool WeakVOprfSender::verify_finalize(const PrivateKey& skS, const ClientInput& input, const size_t length, const hashval_t& output)
    {
        char blindDomainSeparation[CONTEXT_MAX + 12]{'\0'};
        sprintf(blindDomainSeparation, "VOPRF-Blind-%s",contextString);

        hashval_t hashOutput;
        sha512helper(hashOutput, blindDomainSeparation, strlen(blindDomainSeparation), input, length);
        Ristretto25519 P = Ristretto25519::fromHash(hashOutput);

        ristpoint_t issuedElement;
        evaluate(skS, P.point, issuedElement);

        hashval_t digest;
        char finalizeDomainSeparation[CONTEXT_MAX + 16 + 2 * crypto_core_ristretto255_BYTES + 1]{'\0'};
        // quick and dirty, I need to write a more robust version of this.
        char issuedHex[2 * crypto_core_ristretto255_BYTES + 1];
        sodium_bin2hex(issuedHex, 2 * crypto_core_ristretto255_BYTES + 1, issuedElement, crypto_core_ristretto255_BYTES);
        sprintf(finalizeDomainSeparation, "%s-VOPRF-Finalize-%s", issuedHex, contextString);

        sha512helper(digest, finalizeDomainSeparation, strlen(finalizeDomainSeparation), input, length);

        return (sodium_memcmp(digest, output, crypto_hash_sha512_BYTES) == 0);
    }
}