#include <cryptopp/rsa.h>
#include "AsymmetricController.h"
#include "cryptopp/osrng.h"
#include <cryptopp/gfpcrypt.h>
#include "cryptopp/eccrypto.h"
#include "cryptopp/oids.h"
#include <cryptopp/hex.h>

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

void AsymmetricController::dsa(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,int data) {
    using namespace CryptoPP;
    AutoSeededRandomPool rng;

    // Generate Private Key
    DSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, data);

    // Generate Public Key
    DSA::PublicKey publicKey;
    publicKey.AssignFrom(privateKey);
    Json::Value temp;
    privateKey.GetPrivateExponent();
    publicKey.GetPublicElement();

    CryptoPP::byte prv[privateKey.GetPrivateExponent().ByteCount()];
    CryptoPP::byte pub[publicKey.GetPublicElement().ByteCount()];
    privateKey.GetPrivateExponent().Encode(prv, sizeof(prv));
    publicKey.GetPublicElement().Encode(pub, sizeof(pub));

    temp["prv"] = tohex(prv, privateKey.GetPrivateExponent().ByteCount());
    temp["pub"] = tohex(pub, publicKey.GetPublicElement().ByteCount());

    callback(HttpResponse::newHttpJsonResponse(temp));
}

void  AsymmetricController::ecdsa(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {

    CryptoPP:: AutoSeededRandomPool prng;
    /**
     * 1. create privatekey
     */
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey k1;
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> params(CryptoPP::ASN1::secp256r1());

    k1.Initialize( prng, params );

    auto pr = k1.GetPrivateExponent();
    CryptoPP::byte pkey[pr.ByteCount()] ;
    pr.Encode(pkey, sizeof(pkey));

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publicKey;
    k1.MakePublicKey(publicKey);
    const CryptoPP::ECP::Point& q = publicKey.GetPublicElement();

    CryptoPP:: byte pubx[q.x.ByteCount()] ;
    CryptoPP::  byte puby[q.y.ByteCount()] ;

    q.x.Encode(pubx, sizeof(pubx));
    q.y.Encode(puby, sizeof(puby));
    Json::Value temp;
    temp["prv"] = tohex(pkey, pr.ByteCount());
    temp["pubx"] = tohex(pubx, q.x.ByteCount());
    temp["puby"] = tohex(puby, q.y.ByteCount());
    callback(HttpResponse::newHttpJsonResponse(temp));

}

void AsymmetricController::ecdsa_sign(const HttpRequestPtr &req,
                                      std::function<void(const HttpResponsePtr &)> &&callback, std::string data) {


    CryptoPP::ByteQueue queue;
    CryptoPP::StringSource ss{data.c_str(), true};

    CryptoPP::  HexDecoder decoder;
    decoder.Attach(new   CryptoPP::Redirector(queue));
    ss.TransferTo(decoder);
    decoder.MessageEnd();

;


//   CryptoPP:: StringSource pkey(data, true /*pumpAll*/);
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey k1;
    k1.BERDecode(queue);
    Json::Value temp;

    CryptoPP::  byte puby[k1.GetPrivateExponent().ByteCount()] ;

    k1.GetPrivateExponent().Encode(puby, sizeof(puby));
//    temp["prv"] = tohex(decoded.c_str(), decoded.size());
//    temp["pubx"] = tohex(pubx, q.x.ByteCount());
    temp["puby"] = tohex(puby, sizeof(puby));
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
////    temp["prv"] = tohex(prv, privateKey.GetPrivateExponent().ByteCount());
////    temp["pub"] = tohex(pub, publicKey.GetPublicExponent().ByteCount());
//
//    callback(HttpResponse::newHttpJsonResponse(temp));
//}

// Add definition of your processing function here
