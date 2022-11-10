#pragma once

#include <drogon/HttpController.h>

using namespace drogon;

class AsymmetricController : public drogon::HttpController<AsymmetricController>
{
  public:
    METHOD_LIST_BEGIN
    // use METHOD_ADD to add your custom processing function here;
        ADD_METHOD_TO(AsymmetricController::rsa,"/asym/rsa?data={1}",Get);
        ADD_METHOD_TO(AsymmetricController::dsa,"/asym/dsa?data={1}",Get);
        ADD_METHOD_TO(AsymmetricController::ecdsa,"/ecdsa",Get);
        ADD_METHOD_TO(AsymmetricController::ecdsa_sign,"/ecdsa/sign?data={1}",Get);


    // METHOD_ADD(AsymmetricController::your_method_name, "/{1}/{2}/list", Get); // path is /AsymmetricController/{arg1}/{arg2}/list
    // ADD_METHOD_TO(AsymmetricController::your_method_name, "/absolute/path/{1}/{2}/list", Get); // path is /absolute/path/{arg1}/{arg2}/list

    METHOD_LIST_END
    void rsa(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  int data);
    void dsa(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,  int data);
    void ecdsa(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback);

    void ecdsa_sign(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback,std::string data);

    // your declaration of processing function maybe like this:
    // void get(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, int p1, std::string p2);
    // void your_method_name(const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, double p1, int p2) const;
};
