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

// Redis group point
std::shared_ptr< net::redis::group >            g_rg;
std::shared_ptr< net::redis::group >            g_cmdrg;
std::map< net::ip_t, net::peer_t >              g_proxy_cache;

void dns_restore_query_server( ) {
    int _offset = 0;
    do {
        auto _r = g_rg->query("HSCAN", "query_filter", _offset);
        if ( _r.size() < 2 ) break;
        ON_DEBUG(
            std::cout << _r << std::endl;
        )
        _offset = std::stoi(_r[0].content);
        auto _fs = _r[1].subObjects;
        for ( size_t i = 0; i < _fs.size(); i += 2 ) {
            std::string _domain = _fs[i].content;
            std::string _fstr = _fs[i + 1].content;
            auto _ss = utils::split(_fstr, "@");
            net::peer_t _dsvr(_ss[0]);
            net::peer_t _socks5 = net::peer_t::nan;
            if ( _ss.size() == 2 ) _socks5 = _ss[1];
            net::set_query_server(_domain, _dsvr, _socks5);
        }
    } while ( _offset != 0 );
}

void dns_restore_proxy_cache( ) {
    int _offset = 0;
    do {
        auto _r = g_rg->query("HSCAN", "proxy_cache", _offset);
        if ( _r.size() < 2 ) break;
        ON_DEBUG(
            std::cout << _r << std::endl;
        )
        _offset = std::stoi(_r[0].content);
        auto _ps = _r[1].subObjects;
        for ( size_t i = 0; i < _ps.size(); i += 2 ) {
            net::ip_t _targetip(_ps[i].content);
            net::peer_t _proxyserver(_ps[i + 1].content);
            g_proxy_cache[_targetip] = _proxyserver;
        }
    } while ( _offset != 0 );
}

void gw_wait_for_command() {
    loop::main.do_job([]() {
        while ( this_task::get_task()->status != task_status_stopped ) {
            auto _r = g_cmdrg->query("BLPOP", "autogw.command", 0);
            if ( _r.size() != 2 ) continue;
            if ( _r[0].content == "0" ) continue;
            // Todo
            std::string _cmdstr(_r[1].content);
            auto _cmds = utils::split(_cmdstr, "@");
            if ( _cmds[0] == "addqs" ) {
                std::string _domain = _cmds[1];
                net::peer_t _dsvr(_cmds[2]);
                net::peer_t _socks5;
                if ( _cmds.size() == 4 ) {
                    _socks5 = _cmds[3];
                }
                net::set_query_server(_domain, _dsvr, _socks5);
            } else if ( _cmds[0] == "delqs" ) {
                std::string _domain = _cmds[1];
                net::clear_query_server(_domain);
            } else if ( _cmds[0] == "addip" ) {
                net::ip_t _targetip(_cmds[1]);
                net::peer_t _socks5(_cmds[2]);
                g_proxy_cache[_targetip] = _socks5;
            } else if ( _cmds[0] == "delip" ) {
                net::ip_t _targetip(_cmds[1]);
                g_proxy_cache.erase(_targetip);
            } else {
                std::cerr << "invalidate command: " << _cmds[0] << std::endl;
            }
        }
    });
}

void dns_server_handler( net::peer_t in, std::string& idata, net::proto::dns::dns_packet& rpkt ) {
    net::proto::dns::dns_packet _ipkt;
    _ipkt.packet = &idata[0];
    _ipkt.length = idata.size();
    _ipkt.buflen = 0;
    _ipkt.header = (net::proto::dns::dns_packet_header *)(_ipkt.packet);
    _ipkt.dsize = 0;

    net::proto::dns::prepare_for_reading(&_ipkt);
    std::string _d = net::proto::dns::domain(&_ipkt);
    ON_DEBUG(
        std::cout << "-> " << in << ": " << _d << std::endl;
    )
    auto _qs = net::match_query_server(_d);
    net::ip_t _r = net::get_hostname(_d);

    if ( _qs.second && _r.is_valid() ) {
        ON_DEBUG(
            std::cout << "§ " << _d << ": " << _r << " will be route through proxy" << std::endl;
        )
        if ( g_proxy_cache.find(_r) == g_proxy_cache.end() ) {
            g_proxy_cache[_r] = _qs.second;
            g_rg->query("HSET", "proxy_cache", _r.str(), _qs.second.str());
        }
    }

    rpkt.header->trans_id = _ipkt.header->trans_id;
    rpkt.header->is_recursive_available = 1;
    net::proto::dns::set_domain(&rpkt, _d);
    net::proto::dns::set_qtype(&rpkt, net::proto::dns::dns_qtype_host);
    net::proto::dns::set_qclass(&rpkt, net::proto::dns::dns_qclass_in);
    net::proto::dns::set_ips(&rpkt, std::list<net::ip_t>{_r});
    net::proto::dns::prepare_for_sending(&rpkt);
}

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

    net::SOCKET_T _tso = net::tcp::create(net::peer_t("0.0.0.0:53"));
    if ( _tso == INVALIDATE_SOCKET ) {
        std::cerr << "failed to listen on port 53" << std::endl;
        exit(2);
    }

    auto _gw = net::tcp_factory::server & net::peer_t(_gw_info);
    if ( _gw.conn_obj == INVALIDATE_SOCKET ) {
        std::cerr << "failed to listen on " << _gw_info << std::endl;
        exit(2);
    }

    auto _rinfos = utils::split(_redis_info, ",");
    std::map< std::string, std::string > _rinfom;
    for ( auto & i : _rinfos ) {
        auto _kv = utils::split(i, ".");
        _rinfom[_kv[0]] = utils::join(_kv.begin() + 1, _kv.end(), ".");
    }
    if ( _rinfom.find("s") == _rinfom.end() ) {
        std::cerr << "no redis server address" << std::endl;
        exit(3);
    }
    net::peer_t _rsvr(_rinfom["s"]);
    std::string _rpwd;
    if ( _rinfom.find("p") != _rinfom.end() ) {
        _rpwd = _rinfom["p"];
    }
    int _rdb = 0;
    if ( _rinfom.find("db") != _rinfom.end() ) {
        _rdb = std::stoi(_rinfom["db"]);
    }

    g_rg = std::make_shared< net::redis::group >(_rsvr, _rpwd, 2);
    if ( !g_rg->lowest_load_connector().connection_test() ) {
        std::cerr << "cannot connect to redis server" << std::endl;
        exit(4);
    }
    if ( _rdb != 0 ) {
        // Change the database
        g_rg->query("SELECT", _rdb);
    }
    g_cmdrg = std::make_shared< net::redis::group >(_rsvr, _rpwd, 1);
    if ( _rdb != 0 ) {
        g_cmdrg->query("SELECT", _rdb);
    }

    dns_restore_query_server();
    dns_restore_proxy_cache();
    gw_wait_for_command();

    loop::main.do_job(_uso, []() {
        net::udp::listen([](const net::peer_t & iaddr, std::string&& data) {

            loop::main.do_job([iaddr, data]() {
                net::proto::dns::dns_packet _rpkt;
                net::proto::dns::init_dns_packet(&_rpkt);
                std::string _idata = data;
                dns_server_handler(iaddr, _idata, _rpkt);

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

    loop::main.do_job(_tso, []() {
        net::tcp::listen([]() {
            net::tcpadapter _adapter;
            auto _r = _adapter.read_enough(sizeof(uint16_t));
            if ( _r.first != net::op_done ) return;
            uint16_t _l = *(const uint16_t *)_r.second.c_str();
            _l = net::n2h(_l);

            // Read more data
            _r = _adapter.read_enough(_l);
            if ( _r.first != net::op_done ) return;

            net::proto::dns::dns_packet _rpkt;
            net::proto::dns::init_dns_packet(&_rpkt);
            dns_server_handler(net::rawf::socket_peerinfo(this_task::get_task()->id), _r.second, _rpkt);

            _adapter.write(std::string(_rpkt.packet, _rpkt.length + sizeof(uint16_t)));
            net::proto::dns::release_dns_packet(&_rpkt);
        });
    });

    // Start GW
    _gw += [](net::tcp_factory::item&& incoming) {
        net::peer_t _opeer;

        #if PZC_TARGET_LINUX
        struct sockaddr_in _daddr;
        socklen_t _slen = sizeof(_daddr);
        int _error = getsockopt( incoming.conn_obj, SOL_IP, SO_ORIGINAL_DST, &_daddr, &_slen );
        if ( _error ) return;
        _opeer = _daddr;
        #endif

        if ( !_opeer ) return;

        // Check the original peer if match any cache
        net::netadapter *_padapter = NULL;
        auto _pit = g_proxy_cache.find(_opeer.ip);
        if ( _pit != g_proxy_cache.end() ) {
            ON_DEBUG(
                std::cout << "* " << _opeer.ip << " will use socks5 " << _pit->second 
                    << " to build connection" << std::endl;
            )
            _padapter = new net::socks5adapter(_pit->second);
        } else {
            ON_DEBUG(
                std::cout << "* " << _opeer.ip << " will connect directly" << std::endl;
            )
            _padapter = new net::tcpadapter;
        }
        std::shared_ptr< net::netadapter > _ptr_adapter(_padapter);
        if ( ! _ptr_adapter->connect(_opeer.str()) ) return;

        net::tcp_serveradapter _svr_adapter;
        _svr_adapter.switch_data(_padapter);
    };
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