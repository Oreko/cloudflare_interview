#include <cassert>
#include <cstdio>
#include "oprf.hpp"

using namespace OPRF;

int main(void)
{
    unsigned char inputString[12] = "test string";
    size_t inputLength = 11;

    Field25519 privateKey = Field25519::randomScalar();
    Ristretto25519 publicKey = Ristretto25519::fromScalar(privateKey);
    WeakVOprfReceiver receiver(1,1,1,publicKey);

    Blind blinding;
    Ristretto25519 msg1;
    receiver.blind(inputString, inputLength, blinding, msg1);

    WeakVOprfSender sender(1,1,1);
    SerializedElement msg2;
    sender.evaluate(privateKey, msg1.point, msg2);

    hashval_t result;
    receiver.finalize(inputString, inputLength, blinding, msg2, result);

    bool testPass = sender.verify_finalize(privateKey, inputString, inputLength, result);

    if(testPass)
    {
        printf("passed client-server view\n");
    } else
    {
        printf("failed client-server view\n");
    }

    sender.full_evaluate(privateKey, inputString, inputLength, result);

    testPass = sender.verify_finalize(privateKey, inputString, inputLength, result);

    if(testPass)
    {
        printf("passed server-server view\n");
    } else
    {
        printf("failed server-server view\n");
    }

    // Test vectors for if this is altered to be perfectly aligned with the standard.

    // "vectors": [
    //   {
    //     "Batch": 1,
    //     "Blind": "(7e5bcbf82a46109ee0d24e9bcab41fc830a6ce8b82fc1e9213a043b743b95800,080d0a4d352de92672ab709b1ae1888cb48dfabc2d6ca5b914b335512fe70508)",
    //     "BlindedElement": "141b049553e100af8683e8d1a74753614ce5c76b3a4921b890f04f5405dee35a",
    //     "EvaluationElement": "14061969a9491c27a8c63700e2d31d3b905c978c2f561d077a233eba8c68ed74",
    //     "Input": "00",
    //     "Output": "79e119f5ff6ea18b6572792253570ac1e9a831ce76b01e214c9731f9d2eb5458ccd320855796f5d382b61484c03f263397c81fda5915cf5cbdc0e94c7da625e2"
    //   },
    //   {
    //     "Batch": 1,
    //     "Blind": "(c4d5a15f0d5ffc354e340454ec779f575e4573a3886ab5e57e4da2984bdd5306,de2e98f422bf7b99be19f7da7cac62f1599d35a225ec6340149a0aaff3102003)",
    //     "BlindedElement": "4c88ce1b7ee23ac594788fada249d9d77e69958306a739c3584f4ff485e4e738",
    //     "EvaluationElement": "e043991b777511436f510a97b02141d4e5b8453af8793036bbfe0bfde0b6993f",
    //     "Input": "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
    //     "Output": "92b2f2af62636725420186a41392483a69b36654e61a73c249dcc9487e6be818af094a35cffb710bf57f02c6d38dec162533395c5975ca9ecb2266cf09f484b3"
    //   }
    // ]
}