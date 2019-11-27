/*
    autogw.cpp
    AutoGW
    2019-11-24
    Push Chen

    Copyright 2015-2019 MeetU Infomation and Technology Inc. All rights reserved.
*/

#include <peutils.h>
using namespace pe;

#include <cotask.h>
#include <conet.h>
using namespace pe::co;

void co_main( int argc, char * argv[] ) {
    std::string _listen_info = "0.0.0.0:9902";
    std::string _gw_info = "0.0.0.0:4300";
    std::string _redis_info = "s.127.0.0.1:6379,p.password,db.1";
    utils::argparser::set_parser("listen", "l", _listen_info);
    utils::argparser::set_parser("redis", "r", _redis_info);
    utils::argparser::set_parser("gateway", "g", _gw_info);

    if ( !utils::argparser::parse(argc, argv) ) {
        exit(1);
    }

    // Start the manager
}

int main( int argc, char * argv[] ) {
    ON_DEBUG(
        net::enable_conet_trace();
    )


    // Check if this is client or server or command line tools
    loop::main.do_job(std::bind(&co_main, argc, argv));
    loop::main.run();
    return 0;
}

// Push Chen
//