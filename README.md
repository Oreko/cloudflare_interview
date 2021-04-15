# cloudflare_interview

## What Is This?
This repository holds a loose implementation of Weak Verifiable Oblivious Psuedorandom Functions from the standard draft [draft-irtf-cfrg-voprf-06](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-06). The code is written in c++ (but written as if it were c :'( ) using libsodium for cryptographic primitives.

**The code contained in this repo has not been hardened (or reviewed even) for security, so other than for educational purposes, do not use this software in any capacity. The code here is also not a perfect replication of the standard, so it may not interact in expected ways with other software implementing the standard.**

### How does it work?
Roughly speaking, the WVOPRF instantiated using SHA512 and Ristretto25519 works as follows:

1. First receive a public key pk from the partnered server. 
2. The client takes some input x and hash it using SHA512 to recieve H(x) = y
3. The client maps y to a point h on the Ristretto curve
4. The client blinds the resulting point by generating two random field elements a,r and creates msg1 = (h - g * a) * r 
5. The client sends msg1 to the server
6. The server receives msg1 and applies the secret key sk corresponding to pk creating msg2 = (msg1) * sk
7. The server sends msg2 back to the client
8. The client then unblinds the recieved message out = (msg2 * -r) + pk * a 
9. The client outputs H(x,out)

Note that as long as the server uses the expected secret key, we get (((h - g * a) * r) * sk * -r) + pk * a = h * sk
If the server uses something other than the expected key, we result in h * b - g * a * b + pk * a which the server can't compute without knowing the blinding value a (or solving a supposed hard problem) as (g * a * b + pk * a) = (g * b + pk) * a is likely psuedorandom given msg1.

Then the server can compute the function as they wish by simply computing H(z,H(z) * sk)
See [iacr/2020/072](https://eprint.iacr.org/2020/072.pdf)

## Where could this OPRF mode be useful?
One thing I would change is that the instantiation of the client requires the public key before sending the first message. In generic protocols this adds an additional flow (client hello - server public). Since the public key is not used in the blinding step, we should let the server send it post blinding along with
their message. Of course, we would need to verify that this mode is secure per the original implementation, but at first glance it seems reasonable. 

In the context of OPAQUE: Generically I don't see this adding any additional security and rather just adding additional communication and computation complexity. 
From the server's point of view, the WVOPRF method doesn't provide any additional tools as if the server were to instead use a different key, they could achieve
the same result by simply sending a uniformly sampled group element instead. Both situations should be identical from the client's perspective, and can be used
in a case similar to the one outlined in the 072 paper regarding silent dropping of a malicious-tagged client. From the client's perspective, a little benefit can be found. In the situation where the server's public key is certified, we are likely in too strong of a situation to see any added security from this mechanism. In the case where the server's public is *not* certified, then if we allow for caching in the client's view, this mechanism can help hedge against server impersonation or man-in-the-middle attacks on the OPRF as the client can check the cache against the server's message. This, of course, is dubious from a proof-based perspective, but maybe not as much in a real life execution. Other than that, in OPAQUE, a server doesn't gain much from using a different key than the one associated with the client's password file.


## Compiling and Running
All compilation tests have been done on a linux environment using gcc/g++ 10.2.0
This project relies on libsodium https://github.com/jedisct1/libsodium and will not compile without it.
When using the code **for educational purposes** the sid,ssid,uid provide domain separation from a UC perspective and should be unique between (static session, specific subsession, user session or user-pair identification).

### To compile:
cd build

cmake ..

make install


To compile with debug flags, instead run *cmake -DCMAKE_BUILD_TYPE=Debug ..* instead of *cmake ..*
### To run:
bin/WVOPRF

The WVOPRF executable is built off of main.cpp and runs two simple tests to make sure that the outputs of the OPRF are consistent from the server and client view.