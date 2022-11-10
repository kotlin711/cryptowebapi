#pragma once

#include <drogon/HttpController.h>

using namespace drogon;

class HashController : public drogon::HttpController<HashController>
{
  public:
    METHOD_LIST_BEGIN
        ADD_METHOD_TO(HashController::adler32,"/hash/adler32?data={1}",Get);
        ADD_METHOD_TO(HashController::adler32,"/hash/adler32?data={1}",Get);

        ADD_METHOD_TO(HashController::blake2b,"/hash/blake2b?data={1}",Get);
        ADD_METHOD_TO(HashController::blake2s,"/hash/blake2s?data={1}",Get);

        ADD_METHOD_TO(HashController::crc32,"/hash/crc32?data={1}",Get);
        ADD_METHOD_TO(HashController::crc32c,"/hash/crc32c?data={1}",Get);


        ADD_METHOD_TO(HashController::keccak224,"/hash/keccak224?data={1}",Get);
        ADD_METHOD_TO(HashController::keccak256,"/hash/keccak256?data={1}",Get);



        ADD_METHOD_TO(HashController::lsh224,"/hash/lsh224?data={1}",Get);
        ADD_METHOD_TO(HashController::lsh256,"/hash/lsh256?data={1}",Get);
        ADD_METHOD_TO(HashController::lsh384,"/hash/lsh384?data={1}",Get);
        ADD_METHOD_TO(HashController::lsh512,"/hash/lsh512?data={1}",Get);




        ADD_METHOD_TO(HashController::md2,"/hash/md2?data={1}",Get);
        ADD_METHOD_TO(HashController::md4,"/hash/md5?data={1}",Get);

        ADD_METHOD_TO(HashController::md5,"/hash/md5?data={1}",Get);

        ADD_METHOD_TO(HashController::sha1,"/hash/sha1?data={1}",Get);
        ADD_METHOD_TO(HashController::sha256,"/hash/sha256?data={1}",Get);
        ADD_METHOD_TO(HashController::sha224,"/hash/sha224?data={1}",Get);
        ADD_METHOD_TO(HashController::sha384,"/hash/sha384?data={1}",Get);
        ADD_METHOD_TO(HashController::sha512,"/hash/sha512?data={1}",Get);



        ADD_METHOD_TO(HashController::sha3224,"/hash/sha3224?data={1}",Get);
        ADD_METHOD_TO(HashController::sha3256,"/hash/sha3256?data={1}",Get);
        ADD_METHOD_TO(HashController::sha3384,"/hash/sha3384?data={1}",Get);
        ADD_METHOD_TO(HashController::sha3512,"/hash/sha3512?data={1}",Get);


        ADD_METHOD_TO(HashController::shake128,"/hash/shake128?data={1}",Get);
        ADD_METHOD_TO(HashController::shake256,"/hash/shake256?data={1}",Get);


        ADD_METHOD_TO(HashController::ripemd128,"/hash/ripemd128?data={1}",Get);
        ADD_METHOD_TO(HashController::ripemd160,"/hash/ripemd160?data={1}",Get);
        ADD_METHOD_TO(HashController::ripemd256,"/hash/ripemd256?data={1}",Get);
        ADD_METHOD_TO(HashController::ripemd320,"/hash/ripemd320?data={1}",Get);


        ADD_METHOD_TO(HashController::sm3,"/hash/sm3?data={1}",Get);
        ADD_METHOD_TO(HashController::tiger,"/hash/tiger?data={1}",Get);

        ADD_METHOD_TO(HashController::whirlpool,"/hash/whirlpool?data={1}",Get);

        // use METHOD_ADD to add your custom processing function here;
    // METHOD_ADD(HashController::get, "/{2}/{1}", Get); // path is /HashController/{arg2}/{arg1}
    // METHOD_ADD(HashController::your_method_name, "/{1}/{2}/list", Get); // path is /HashController/{arg1}/{arg2}/list
    // ADD_METHOD_TO(HashController::your_method_name, "/absolute/path/{1}/{2}/list", Get); // path is /absolute/path/{arg1}/{arg2}/list

    METHOD_LIST_END
    void adler32(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);

    void blake2b(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);
    void blake2s(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);

    void crc32(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);
    void crc32c(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);

    void keccak224(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);
    void keccak256(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);

    void lsh224(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);
    void lsh256(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);
    void lsh384(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);
    void lsh512(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);

    void md2(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);
    void md4(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);
    void md5(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);

    void sha1(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);
    void sha256(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);
    void sha224(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);
    void sha384(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);
    void sha512(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);

    void sha3224(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);
    void sha3256(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);
    void sha3384(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);
    void sha3512(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);

    void shake128(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);
    void shake256(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);

    void ripemd128(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);
    void ripemd160(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);
    void ripemd256(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);
    void ripemd320(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);




    void sm3(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);

    void tiger(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);

    void whirlpool(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  std::string data);

    // void your_method_name(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, double p1, int p2) const;
};
