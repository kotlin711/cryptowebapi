#define DROGON_TEST_MAIN
#include <drogon/drogon_test.h>
#include <drogon/drogon.h>
#include <cryptopp/rsa.h>
#include "cryptopp/osrng.h"
#include <cryptopp/gfpcrypt.h>
#include "cryptopp/eccrypto.h"
#include "cryptopp/oids.h"
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

//DROGON_TEST(BasicTest)
//{
//    // Add your tests here
//}

int main(int argc, char** argv) 
{
    CryptoPP::AutoSeededRandomPool prng;

    using namespace CryptoPP;

    ECDSA<ECP, SHA1>::PrivateKey k1;
    k1.Initialize( prng, ASN1::secp256k1() );
    const Integer& x1 = k1.GetPrivateExponent();
    std::cout << "K1: " << std::hex << x1 << std::endl;

    std::string keystr="c2f3e1d214b736187af2f4aa83b831e0ece63e5c3af6a056967ffac86638c638";

    ByteQueue queue;
    HexDecoder decoder;

    decoder.Attach(new Redirector(queue));
    decoder.Put((const byte*)keystr.data(), keystr.length());
    decoder.MessageEnd();


    ECDSA<ECP, SHA1>::PrivateKey k2;
    k2.DEREncode(queue);
    const Integer& x2 = k2.GetPrivateExponent();
    std::cout << "K2: " << std::hex << x2 << std::endl;


    return 0;
}
