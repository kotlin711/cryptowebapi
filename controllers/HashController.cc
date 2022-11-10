#include "HashController.h"
#include "cryptopp/md5.h"
#include "cryptopp/sha.h"
#include <cryptopp/sha3.h>
#include <cryptopp/shake.h>
#include <cryptopp/sm3.h>
#include <cryptopp/tiger.h>
#include <cryptopp/whrlpool.h>
#include "cryptopp/md2.h"
#include "cryptopp/md4.h"
#include "cryptopp/ripemd.h"
#include <cryptopp/adler32.h>
#include "cryptopp/blake2.h"
#include <cryptopp/crc.h>
#include <cryptopp/keccak.h>
#include <cryptopp/lsh.h>
#include "cryptopp/siphash.h"
// Add definition of your processing function here
char const hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

std::string byte_2_str(char *bytes, int size) {
    std::string str;
    for (int i = 0; i < size; ++i) {
        const char ch = bytes[i];
        str.append(&hex[(ch & 0xF0) >> 4], 1);
        str.append(&hex[ch & 0xF], 1);
    }
    return str;
}


void HashController::adler32(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                             std::string data) {
    CryptoPP::Adler32 hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::blake2b(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                             std::string data) {
    CryptoPP::BLAKE2b hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::blake2s(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                             std::string data) {
    CryptoPP::BLAKE2s hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::crc32(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                           std::string data) {
    CryptoPP::CRC32 hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::crc32c(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                            std::string data) {
    CryptoPP::CRC32C hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::keccak224(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                               std::string data) {
    CryptoPP::Keccak_224 hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::keccak256(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                               std::string data) {
    CryptoPP::Keccak_256 hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}


void HashController::lsh224(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                            std::string data) {
    CryptoPP::LSH224 hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}


void HashController::lsh256(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                            std::string data) {
    CryptoPP::LSH256 hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::lsh384(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                            std::string data) {
    CryptoPP::LSH384 hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::lsh512(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                            std::string data) {
    CryptoPP::LSH512 hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}


void HashController::md2(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                         std::string data) {
    CryptoPP::MD2 hash;
    CryptoPP::byte digest_hash[CryptoPP::Weak1::MD2::DIGESTSIZE];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), CryptoPP::Weak1::MD2::DIGESTSIZE);
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::md4(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                         std::string data) {
    CryptoPP::MD4 hash;
    CryptoPP::byte digest_hash[CryptoPP::Weak1::MD5::DIGESTSIZE];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), CryptoPP::Weak1::MD5::DIGESTSIZE);
    callback(HttpResponse::newHttpJsonResponse(temp));
}
void HashController::md5(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                         std::string data) {
    CryptoPP::MD5 hash;
    CryptoPP::byte digest_hash[CryptoPP::Weak1::MD5::DIGESTSIZE];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), CryptoPP::Weak1::MD5::DIGESTSIZE);
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::sha1(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                          std::string data) {
    CryptoPP::SHA1 hash;
    CryptoPP::byte digest_hash[CryptoPP::SHA1::DIGESTSIZE];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), CryptoPP::SHA1::DIGESTSIZE);
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::sha256(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                            std::string data) {
    CryptoPP::SHA256 hash;
    CryptoPP::byte digest_hash[CryptoPP::SHA256::DIGESTSIZE];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), CryptoPP::SHA256::DIGESTSIZE);
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::sha224(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                            std::string data) {
    CryptoPP::SHA224 hash;
    CryptoPP::byte digest_hash[CryptoPP::SHA224::DIGESTSIZE];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), CryptoPP::SHA224::DIGESTSIZE);
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::sha384(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                            std::string data) {
    CryptoPP::SHA384 hash;
    CryptoPP::byte digest_hash[CryptoPP::SHA384::DIGESTSIZE];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), CryptoPP::SHA384::DIGESTSIZE);
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::sha512(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                            std::string data) {
    CryptoPP::SHA512 hash;
    CryptoPP::byte digest_hash[CryptoPP::SHA512::DIGESTSIZE];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), CryptoPP::SHA512::DIGESTSIZE);
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::sha3224(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                             std::string data) {
    CryptoPP::SHA3_224 hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::sha3256(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                             std::string data) {
    CryptoPP::SHA3_256 hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::sha3384(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                             std::string data) {
    CryptoPP::SHA3_384 hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::sha3512(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                             std::string data) {
    CryptoPP::SHA3_512 hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::shake128(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                              std::string data) {
    CryptoPP::SHAKE128 hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::shake256(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                              std::string data) {
    CryptoPP::SHAKE256 hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::sm3(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                         std::string data) {
    CryptoPP::SM3 hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}


void HashController::ripemd128(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                              std::string data) {
    CryptoPP::RIPEMD128 hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}
void HashController::ripemd160(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                               std::string data) {
    CryptoPP::RIPEMD160 hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}
void HashController::ripemd256(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                               std::string data) {
    CryptoPP::RIPEMD256 hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}
void HashController::ripemd320(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                               std::string data) {
    CryptoPP::RIPEMD320 hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}

void HashController::tiger(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                           std::string data) {
    CryptoPP::Tiger hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}


void HashController::whirlpool(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                               std::string data) {
    CryptoPP::Whirlpool hash;
    CryptoPP::byte digest_hash[hash.DigestSize()];
    hash.CalculateDigest(digest_hash, (const CryptoPP::byte *) data.c_str(), data.size());
    Json::Value temp;
    temp["data"] = byte_2_str(reinterpret_cast<char *>(digest_hash), hash.DigestSize());
    callback(HttpResponse::newHttpJsonResponse(temp));
}