#pragma once
#include <type_traits>
#include <sodium.h>
#include "ristretto_interface.hpp"

#define CONTEXT_MAX 2000 // Magic number, it's just a rough upper end. The standard requires we have a string of at least 512 bytes 

namespace OPRF
{
    // If we templatize this later, make sure to check if the serialized type (and likely the blind) is a plain old data type / standard-layout.
    typedef unsigned char *ClientInput;
    typedef Field25519 PrivateKey;
    typedef ristpoint_t SerializedElement;
    struct Blind
    {
        Field25519 blind1;
        Field25519 blind2;
    };

    void sha512helper(hashval_t dst, unsigned char const* src, size_t length);
    
    class WeakVOprfReceiver
    {
        public:
            WeakVOprfReceiver(void) = delete;
            WeakVOprfReceiver(const unsigned int sid, const unsigned int ssid, const unsigned int uid, Ristretto25519 publicKey);
            WeakVOprfReceiver(const WeakVOprfReceiver&) = delete;
            // Copy and move assigns purposely left out. Please don't copy an OPRF.
            WeakVOprfReceiver(WeakVOprfReceiver&&) = delete;

            void blind(const ClientInput& input, size_t length, Blind& blinding, Ristretto25519& blindedElement);
            Ristretto25519 unblind(const Blind& blind, const Ristretto25519& evaluatedElement);
            void finalize(const ClientInput& input, const size_t length, const Blind& blinding, const SerializedElement& evaluatedElement, hashval_t& returnVal);

        private:
            Ristretto25519 pkS;
            size_t contextLength;
            char contextString[CONTEXT_MAX] = {0};
    };

    class WeakVOprfSender
    {
        public:
            WeakVOprfSender(void) = delete;
            WeakVOprfSender(const unsigned int sid, const unsigned int ssid, const unsigned int uid);
            WeakVOprfSender(const WeakVOprfSender&) = delete;
            // Copy and move assigns purposely left out. Please don't copy an OPRF.
            WeakVOprfSender(WeakVOprfSender&&) = delete;

            void evaluate(const PrivateKey& skS, const SerializedElement& blindedElement, SerializedElement& returnVal);
            void full_evaluate(const PrivateKey& skS, const ClientInput& input, const size_t length, hashval_t& returnVal); 
            bool verify_finalize(const PrivateKey& skS, const ClientInput& input, const size_t length, const hashval_t& output);

        private:
            size_t contextLength;
            char contextString[CONTEXT_MAX] = {0};
    };
}