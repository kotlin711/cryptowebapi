#include <cryptopp/rsa.h>
#include "AsymmetricController.h"
#include "cryptopp/osrng.h"
#include <cryptopp/gfpcrypt.h>

char const hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
std::string tohex(const char *bytes, int size) {
    std::string str;
    for (int i = 0; i < size; ++i) {
        const char ch = bytes[i];
        str.append(&hex[(ch & 0xF0) >> 4], 1);
        str.append(&hex[ch & 0xF], 1);
    }
    return str;
}


std::string tohex(const CryptoPP::byte *bytes, int size) {
    std::string str;
    for (int i = 0; i < size; ++i) {
        const char ch = bytes[i];
        str.append(&hex[(ch & 0xF0) >> 4], 1);
        str.append(&hex[ch & 0xF], 1);
    }
    return str;
}

void AsymmetricController::rsa(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,int data) {

    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(prng, data);

    CryptoPP::RSA::PrivateKey privateKey(params);
    CryptoPP::RSA::PublicKey publicKey(params);

    CryptoPP::byte prv[privateKey.GetPrivateExponent().ByteCount()];
    CryptoPP::byte pub[publicKey.GetPublicExponent().ByteCount()];
    privateKey.GetPrivateExponent().Encode(prv, sizeof(prv));
    publicKey.GetPublicExponent().Encode(pub, sizeof(pub));
    Json::Value temp;
    temp["prv"] = tohex(prv, privateKey.GetPrivateExponent().ByteCount());
    temp["pub"] = tohex(pub, publicKey.GetPublicExponent().ByteCount());

    callback(HttpResponse::newHttpJsonResponse(temp));
}


//void AsymmetricController::rsaenc(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
//                               std::string  prv,std::string pub,std::string text) {
//
//    CryptoPP::AutoSeededRandomPool prng;
//
//    CryptoPP::RSA::PrivateKey privateKey;
//    CryptoPP::RSA::PublicKey publicKey;
//    CryptoPP:: StringSource pubsource(pub, true);
//    CryptoPP:: StringSource prvsource(pub, true);
//
//    publicKey.Load(pubsource);
//    privateKey.Load(prvsource);
//    CryptoPP:: RSAES_OAEP_SHA_Encryptor e(publicKey);
//
//
////    CryptoPP::byte prv[privateKey.GetPrivateExponent().ByteCount()];
////    CryptoPP::byte pub[publicKey.GetPublicExponent().ByteCount()];
////    privateKey.GetPrivateExponent().Encode(prv, sizeof(prv));
////    publicKey.GetPublicExponent().Encode(pub, sizeof(pub));
//    Json::Value temp;
////    temp["prv"] = byte_2_str(prv, privateKey.GetPrivateExponent().ByteCount());
////    temp["pub"] = byte_2_str(pub, publicKey.GetPublicExponent().ByteCount());
//
//    callback(HttpResponse::newHttpJsonResponse(temp));
//}

// Add definition of your processing function here
