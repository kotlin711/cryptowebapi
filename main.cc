#include <drogon/drogon.h>
int main() {
    //Set HTTP listener address and port
    //Load config file
//    drogon::app().loadConfigFile("../config.json");
    drogon::app().addListener("0.0.0.0",8080);

//    for (const auto &item : drogon::app().getCustomConfig().getMemberNames()){
//        std::cout<<  "端口"<<item<<std::endl;
//
//    }

    //Run HTTP framework,the method will block in the internal event loop
    drogon::app().run();
//    std::cout<<drogon::app
    return 0;
}
