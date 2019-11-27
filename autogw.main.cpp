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
    net::SOCKET_T _uso = net::udp::create(net::peer_t("0.0.0.0:53"));
    if ( _uso == INVALIDATE_SOCKET ) {
        std::cerr << "failed to listen on port 53" << std::endl;
        exit(2);
    }

    loop::main.do_job(_uso, []() {
        net::udp::listen([](const net::peer_t & iaddr, std::string&& data) {

            loop::main.do_job([iaddr, data]() {
                net::proto::dns::dns_packet _ipkt;
                std::string _cdata = data;
                _ipkt.packet = &_cdata[0];
                _ipkt.length = _cdata.size();
                _ipkt.buflen = 0;
                _ipkt.header = (net::proto::dns::dns_packet_header *)(_ipkt.packet);
                _ipkt.dsize = 0;

                net::proto::dns::prepare_for_reading(&_ipkt);
                std::string _d = net::proto::dns::domain(&_ipkt);
                ON_DEBUG(
                    std::cout << "-> " << iaddr << ": " << _d << std::endl;
                )
                auto _qs = net::match_query_server(_d);
                net::ip_t _r = net::get_hostname(_d);
                // if ( !_r.is_valid() ) {

                // }
                if ( _qs.second ) {
                    ON_DEBUG(
                        std::cout << "§ " << _d << ": " << _r << " will be route through proxy" << std::endl;
                    )
                }

                net::proto::dns::dns_packet _rpkt;
                net::proto::dns::init_dns_packet(&_rpkt);
                _rpkt.header->trans_id = _ipkt.header->trans_id;
                net::proto::dns::set_ips(&_rpkt, std::list<net::ip_t>{_r});
                net::proto::dns::prepare_for_sending(&_rpkt);

                net::udp::write_to(
                    parent_task::get_task(), 
                    net::proto::dns::pkt_begin(&_rpkt),
                    _rpkt.length,
                    (struct sockaddr_in)iaddr
                );

                net::proto::dns::release_dns_packet(&_rpkt);
            });
        });
    });
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