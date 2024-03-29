/*
    autogw.cpp
    AutoGW
    2019-11-24
    Push Chen
*/

/*
MIT License

Copyright (c) 2019 Push Chen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <peutils.h>
using namespace pe;

#include <cotask.h>
#include <conet.h>
using namespace pe::co;

int g_return = 0;
// Redis group point
std::shared_ptr< net::redis::group >            g_rg;
std::shared_ptr< net::redis::group >            g_cmdrg;
std::map< net::ip_t, net::peer_t >              g_proxy_cache;
net::peer_t                                     g_master;
std::string                                     g_gwname;
std::string                                     g_gwport;
std::map< net::ip_t, bool >                     g_ignore;

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
            if ( _ss[0].find(":") == std::string::npos ) {
                _ss[0] += ":53";
            }
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
            if ( g_ignore.find(_targetip) != g_ignore.end() ) continue;
            g_proxy_cache[_targetip] = _proxyserver;
        }
    } while ( _offset != 0 );
}

void dns_add_proxy_cache( net::ip_t& ip, net::peer_t& socks5 ) {
    if ( g_proxy_cache.find(ip) != g_proxy_cache.end() ) return;
    if ( g_ignore.find(ip) != g_ignore.end() ) return;   // Ignore
    g_proxy_cache[ip] = socks5;

    loop::main.do_job([ip, socks5]() {
        g_rg->query("HSET", "proxy_cache", ip.str(), socks5.str());

        // Dynamically add iptables rule
        int _ret = 0;
        do {
            process _iptable("iptables");
            _iptable << "-t" << "nat" << "-A" << g_gwname << "-p" << "tcp" << "-d" 
                << ip.str() + "/32" << "-j" << "REDIRECT" << "--to-ports"
                << g_gwport;
            _iptable.stderr = [](std::string&& d) { std::cerr << d; };

            _ret = _iptable.run();
            if ( _ret != 0 ) {
                std::cerr << "failed to add new proxy rule for ip: " << ip 
                    << ", return " << _ret << std::endl;
                this_task::sleep(std::chrono::seconds(1));
            } else {
                std::cout << "new iptables rule for ip: " << ip << " was added." << std::endl;
            }
        } while ( _ret != 0 );
    });
}

void dns_del_proxy_cache( net::ip_t& ip ) {
    if ( g_proxy_cache.find(ip) == g_proxy_cache.end() ) return;
    g_proxy_cache.erase(ip);

    loop::main.do_job([ip]() {
        g_rg->query("HDEL", "proxy_cache", ip.str());
        process _iptable("iptables");
        _iptable << "-t" << "nat" << "-A" << g_gwname << "-p" << "tcp" << "-d"
            << ip.str() + "/32" << "-j" << "RETURN";
        _iptable.run();
    });
}

void dns_restore_iptables( 
    const std::string& init_script, 
    const std::string& nat_name, 
    const std::string& gwport 
) {
    process _init_p(init_script);
    if ( 0 != _init_p.run() ) return;   // init failed

    // Load now saved iptable rules
    process _save_p("iptables-save");
    std::stringstream _saved_rules;
    _save_p.stdout = [&_saved_rules](std::string&& d) {
        _saved_rules << d;
    };
    _save_p.run();

    ON_DEBUG(
        std::cout << "Saved Iptable Rules: " << std::endl;
        std::cout << _saved_rules.str() << std::endl;
    )

    process *_pres = new process("iptables-restore");
    ON_DEBUG(
        _pres->stdout = [](std::string&& d) {
            std::cout << d;
        };
        _pres->stderr = [](std::string&& d) {
            std::cerr << d;
        };
    )
    loop::main.do_job([_pres]() {
        parent_task::guard _pg;
        int _ret = _pres->run();
        std::cout << "iptable-restore return " << _ret << std::endl;
    });

    std::string _rule;
    bool _already_in_nat = false;
    while ( std::getline(_saved_rules, _rule) ) {
        if ( _already_in_nat && _rule == "COMMIT" ) {
            for ( auto& pitem : g_proxy_cache ) {
                std::stringstream _ruless;
                _ruless 
                    << "-A " << nat_name << " "
                    << "-p tcp -d " << pitem.first.str() << "/32 "
                    << "-j REDIRECT --to-ports " << gwport
                    << std::endl;
                ON_DEBUG(
                    std::cout << _ruless.str();
                )
                _pres->input(_ruless.str());
            }
            _already_in_nat = false;
        }
        if ( _rule == "*nat" ) _already_in_nat = true;
        ON_DEBUG(
            std::cout << _rule << std::endl;
        )
        _pres->input(_rule + "\n");
    }
    _pres->send_eof();
    // Holding until iptables-restore return
    this_task::holding();
    delete _pres;
    std::cout << "restore gateway rules done." << std::endl;
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
                if ( _cmds[2].find(":") == std::string::npos ) {
                    _cmds[2] += ":53";
                }
                net::peer_t _dsvr(_cmds[2]);
                std::string _s = _cmds[2];
                net::peer_t _socks5;
                if ( _cmds.size() == 4 ) {
                    _socks5 = _cmds[3];
                    _s += "@";
                    _s += _cmds[3];
                }
                net::set_query_server(_domain, _dsvr, _socks5);
                g_rg->query("HSET", "query_filter", _domain, _s);
            } else if ( _cmds[0] == "delqs" ) {
                std::string _domain = _cmds[1];
                net::clear_query_server(_domain);
                g_rg->query("HDEL", "query_filter", _cmds[1]);
            } else if ( _cmds[0] == "addip" ) {
                net::ip_t _targetip(_cmds[1]);
                net::peer_t _socks5(_cmds[2]);
                dns_add_proxy_cache(_targetip, _socks5);
            } else if ( _cmds[0] == "delip" ) {
                net::ip_t _targetip(_cmds[1]);
                dns_del_proxy_cache(_targetip);
            } else {
                std::cerr << "invalidate command: " << _cmds[0] << std::endl;
            }
        }
    });
}

std::string dns_server_handler( net::peer_t in, std::string&& data, bool force_tcp ) {
    net::proto::dns::dns_packet _ipkt;
    _ipkt.packet = &data[0];
    _ipkt.length = data.size();
    _ipkt.buflen = 0;
    _ipkt.header = (net::proto::dns::dns_packet_header *)(_ipkt.packet);
    _ipkt.dsize = 0;

    _ipkt.header->trans_id = ntohs(_ipkt.header->trans_id);
    _ipkt.header->qdcount = ntohs(_ipkt.header->qdcount);
    _ipkt.header->ancount = ntohs(_ipkt.header->ancount);
    _ipkt.header->nscount = ntohs(_ipkt.header->nscount);
    _ipkt.header->arcount = ntohs(_ipkt.header->arcount);

    // net::proto::dns::prepare_for_reading(&_ipkt);
    std::string _d = net::proto::dns::domain(&_ipkt);

    // Roll back the data
    _ipkt.header->trans_id = htons(_ipkt.header->trans_id);
    _ipkt.header->qdcount = htons(_ipkt.header->qdcount);
    _ipkt.header->ancount = htons(_ipkt.header->ancount);
    _ipkt.header->nscount = htons(_ipkt.header->nscount);
    _ipkt.header->arcount = htons(_ipkt.header->arcount);

    ON_DEBUG(
        std::cout << "-> " << in << ": " << _d << std::endl;
    )
    auto _qs = net::match_query_server(_d);
    net::netadapter *_pradapter = NULL;

    bool _add_tcp_length = (force_tcp);
    net::peer_t _master = g_master;

    if ( _qs.first ) {
        if ( _qs.second ) {
            // Redirect as Socks5 on TCP
            _pradapter = new net::socks5adapter(_qs.second);
            _add_tcp_length = true;
        } else {
            // Redirect to specified DNS server
            if ( force_tcp ) {
                _pradapter = new net::tcpadapter;
            } else {
                _pradapter = new net::udpadapter;
            }
        }
        _master = _qs.first;
    } else {
        // Redirect to the uplevel
        if ( force_tcp ) {
            _pradapter = new net::tcpadapter;
        } else {
            _pradapter = new net::udpadapter;
        }
    }

    std::shared_ptr< net::netadapter > _ptr_adapter(_pradapter);
    if ( !_ptr_adapter->connect(_master.str()) ) return std::string("");
    if ( _add_tcp_length ) {
        std::string _ls;
        _ls.resize(sizeof(uint16_t));
        uint16_t *_pls = (uint16_t *)&_ls[0];
        *_pls = net::h2n((uint16_t)data.size());
        _ptr_adapter->write(std::move(_ls));
    }
    if ( !_ptr_adapter->write(std::move(data)) ) return std::string("");

    auto _r = _ptr_adapter->read(std::chrono::seconds(3));
    if ( _r.first != net::op_done ) return std::string("");

    ON_DEBUG(
        std::cout << "get resposne from " << _master << " on domain " << _d << std::endl;
    )

    // Just return the response from master if the domain is not match any query filter
    if ( !_qs.second ) {
        if ( _add_tcp_length ) {
            return _r.second.substr(sizeof(uint16_t));
        }
        return _r.second;
    }

    ON_DEBUG(
        std::cout << "domain " << _d << " matchs a filter, will check result" << std::endl;
    )

    net::proto::dns::dns_packet _rpkt;
    _rpkt.packet = &_r.second[0];
    _rpkt.buflen = 0;
    _rpkt.dsize = 0;
    _rpkt.length = _r.second.size() - sizeof(uint16_t);
    _rpkt.header = (net::proto::dns::dns_packet_header *)(_rpkt.packet + sizeof(uint16_t));

    // parse the response and update the cache
    _rpkt.header->trans_id = ntohs(_rpkt.header->trans_id);
    _rpkt.header->qdcount = ntohs(_rpkt.header->qdcount);
    _rpkt.header->ancount = ntohs(_rpkt.header->ancount);
    _rpkt.header->nscount = ntohs(_rpkt.header->nscount);
    _rpkt.header->arcount = ntohs(_rpkt.header->arcount);

    auto _ips = net::proto::dns::ips( &_rpkt );
    if ( _ips.size() > 0 ) {
        for ( auto& ir : _ips ) {
            ON_DEBUG(
                std::cout << "will add iptable rule for <" << _d << "> on ip " << ir.ip << std::endl;
            )
            dns_add_proxy_cache(ir.ip, _qs.second);
        }
    }
    auto _cname = net::proto::dns::cname( &_rpkt );
    do {
        if ( _cname.domain.size() == 0 ) break;
        auto _cqs = net::match_query_server(_cname.domain);
        if ( _cqs.first ) break;
        // Make the whole domain in the query filter
        auto _ds = utils::split(_cname.domain, ".");
        if ( _ds.size() == 1 ) break;
        auto _l1 = _ds.rbegin();
        auto _l2 = _l1 + 1;
        std::string _fdomain = "." + *_l2 + "." + *_l1;
        net::set_query_server(_fdomain, _qs.first, _qs.second);
        std::string _fstring = _qs.first.str() + "@" + _qs.second.str();
        loop::main.do_job([_fdomain, _fstring]() {
            g_rg->query("HSET", "query_filter", _fdomain, _fstring);
        });
    } while ( false );

    _rpkt.header->trans_id = htons(_rpkt.header->trans_id);
    _rpkt.header->qdcount = htons(_rpkt.header->qdcount);
    _rpkt.header->ancount = htons(_rpkt.header->ancount);
    _rpkt.header->nscount = htons(_rpkt.header->nscount);
    _rpkt.header->arcount = htons(_rpkt.header->arcount);

    return _r.second.substr(sizeof(uint16_t));
}

void co_main( int argc, char * argv[] ) {
    std::string _gw_info = "4300";
    std::string _redis_info = "s.127.0.0.1:6379,p.password,db.1";
    std::string _master = "114.114.114.114:53";
    std::string _initfw;
    std::string _gwname;
    bool _normal_exit = false;
    utils::argparser::set_parser("redis", "r", _redis_info);
    utils::argparser::set_parser("gw-port", "p", _gw_info);
    utils::argparser::set_parser("master", "m", _master);
    utils::argparser::set_parser("initfw", "f", _initfw);
    utils::argparser::set_parser("gwname", "n", _gwname);
    utils::argparser::set_parser("ignore", "i", [&_normal_exit](std::string&& ip) {
        net::ip_t _ip(ip);
        if ( !_ip ) {
            std::cerr << "Invalidate IP: " << ip << std::endl;
            g_return = 100;
            _normal_exit = true;
            return;
        }
        g_ignore[_ip] = true;
    });
    utils::argparser::set_parser("help", "h", [&_normal_exit](std::string&&) {
        std::cout
            << "Usage: autogw [OPTION]..." << std::endl
            << "Listen on DNS Port(TCP/UDP 53) and connects to a redis server which" << std::endl
            << "contains the domain query filters and ip proxy rules." << std::endl
            << "autogw will add new iptable redirect rules according to the dns query" << std::endl
            << "result. And will use the query filter's socks5 proxy as the redirect tunnel." << std::endl
            << std::endl
            << "  -r, --redis               Redis server url string" << std::endl
            << "  -p, --gw-port             Gateway listening port number, default is 4300" << std::endl
            << "  -n, --gw-name             Gateway nat chain name" << std::endl
            << "  -i, --ignore              Ignore certain IP address, can be repeated" << std::endl
            << "  -m, --master              The uplevel dns query server, default " << std::endl
            << "                              is 114.114.114.114, default port number" << std::endl
            << "                              is 53 if not specified" << std::endl
            << "  -f, --initfw              Firewall init script" << std::endl
            << "  -h, --help                Display this message" << std::endl
            << "  -v, --version             Display version number" << std::endl
            << "  --enable-conet-trace      In debug version only, display net log" << std::endl
            << "  --enable-cotask-trace     In debug version only, display task log" << std::endl
            << std::endl
            << "Redis Server URL String Format: " << std::endl
            << "  redis://[password@]<server_address>[:port][/dbindex]" << std::endl
            << "Example: " << std::endl
            << "  redis://mypassword@127.0.0.1/1" << std::endl
            << std::endl
            << "Powered By Push Chen <littlepush@gmail.com>, as a sub project of PECo framework." << std::endl;
        _normal_exit = true;
    });
    utils::argparser::set_parser("version", "v", [&_normal_exit](std::string&&) {
        std::cout << "autogw, ";
        #ifdef DEBUG
            std::cout << "Debug Version, ";
        #else
            std::cout << "Release Version, ";
        #endif
        std::cout << "v" << VERSION << std::endl;
        std::cout 
            << "Powered By Push Chen <littlepush@gmail.com>, as a sub project of PE framework." << std::endl;
        _normal_exit = true;
    });
    ON_DEBUG(
        utils::argparser::set_parser("enable-conet-trace", [](std::string&&) {
            net::enable_conet_trace();
        });
        utils::argparser::set_parser("enable-cotask-trace", [](std::string&&) {
            enable_cotask_trace();
        });
    )

    // Do arg parser
    if ( !utils::argparser::parse(argc, argv) ) {
        g_return = 1;
        return;
    }

    // Just return
    if ( _normal_exit ) return;

    if ( _initfw.size() == 0 || _gwname.size() == 0 ) {
        std::cerr << "missing arguments" << std::endl;
        g_return = 2;
        return;
    }

    // Format the master address
    if ( _master.find(":") == std::string::npos ) {
        _master += ":53";
    }
    g_master = _master;

    // Start the manager
    net::SOCKET_T _uso = net::udp::create(net::peer_t("0.0.0.0:53"));
    if ( _uso == INVALIDATE_SOCKET ) {
        std::cerr << "failed to listen on port 53" << std::endl;
        g_return = 3;
        return;
    }

    net::SOCKET_T _tso = net::tcp::create(net::peer_t("0.0.0.0:53"));
    if ( _tso == INVALIDATE_SOCKET ) {
        std::cerr << "failed to listen on port 53" << std::endl;
        g_return = 3;
        return;
    }

    auto _gw = net::tcp_factory::server & net::peer_t(net::ip_t(0), (uint16_t)std::stoi(_gw_info));
    if ( _gw.conn_obj == INVALIDATE_SOCKET ) {
        std::cerr << "failed to listen on " << _gw_info << std::endl;
        g_return = 3;
        return;
    }

    g_rg = std::make_shared< net::redis::group >(_redis_info, 2);
    if ( !g_rg->lowest_load_connector().connection_test() ) {
        std::cerr << "cannot connect to redis server" << std::endl;
        g_return = 5;
        return;
    }
    g_cmdrg = std::make_shared< net::redis::group >(_redis_info, 1);

    dns_restore_query_server();
    dns_restore_proxy_cache();
    dns_restore_iptables(_initfw, _gwname, _gw_info);
    g_gwname = _gwname;
    g_gwport = _gw_info;
    gw_wait_for_command();

    loop::main.do_job(_uso, []() {
        net::udp::listen([](const net::peer_t & iaddr, std::string&& data) {

            loop::main.do_job([iaddr, data]() {
                std::string _idata = data;
                std::string _resp = dns_server_handler( iaddr, std::move(_idata), false );
                if ( _resp.size() == 0 ) return;

                net::udp::write_to(
                    parent_task::get_task(), 
                    _resp.c_str(),
                    _resp.size(),
                    (struct sockaddr_in)iaddr
                );
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

            std::string _resp = dns_server_handler( 
                net::rawf::socket_peerinfo(this_task::get_task()->id), 
                std::move(_r.second), 
                true
            );
            if ( _resp.size() == 0 ) return;
            std::string _ls;
            _ls.resize(2);
            uint16_t *_pls = (uint16_t *)&_ls[0];
            *_pls = net::h2n((uint16_t)_resp.size());
            _adapter.write( std::move(_ls) );
            _adapter.write( std::move(_resp) );
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
        if ( g_ignore.find(_opeer.ip) != g_ignore.end() ) return;   // Ignore

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
    // Check if this is client or server or command line tools
    loop::main.do_job(std::bind(&co_main, argc, argv));
    loop::main.run();
    return g_return;
}

// Push Chen
//