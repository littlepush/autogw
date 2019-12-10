/*
    loadpac.cpp
    AutoGW
    2019-11-28
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
using namespace pe::co::net;

void co_main( int argc, char * argv[] ) {
    std::string _pac_file;
    std::string _redis_info = "s.127.0.0.1:6379,p.password,db.1";
    std::string _proxy;
    utils::argparser::set_parser("redis", "r", _redis_info);
    utils::argparser::set_parser("pac", "p", _pac_file);
    utils::argparser::set_parser("master", "m", _proxy);

    if ( !utils::argparser::parse(argc, argv) ) {
        exit(1);
    }

    if ( _pac_file.size() == 0 || !utils::is_file_existed(_pac_file) ) {
        std::cerr << "pac not existed: " << _pac_file << std::endl;
        exit(1);
    }
    if ( _proxy.size() == 0 ) {
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

    std::shared_ptr< net::redis::group > g_rg;
    g_rg = std::make_shared< net::redis::group >(_rsvr, _rpwd, 2);
    if ( !g_rg->lowest_load_connector().connection_test() ) {
        std::cerr << "cannot connect to redis server" << std::endl;
        exit(4);
    }
    if ( _rdb != 0 ) {
        // Change the database
        g_rg->query("SELECT", _rdb);
    }

    Json::Value _pacroot;
    Json::Reader _pacreader;
    std::ifstream _fpac(_pac_file);
    if ( !_pacreader.parse(_fpac, _pacroot, false) ) {
        std::cerr << "invalidate pac file" << std::endl;
        exit(5);
    }

    Json::Value &_jdomains = _pacroot["domains"];
    for ( auto f = _jdomains.begin(); f != _jdomains.end(); ++f ) {
        std::string _s = f.key().asString();
        if ( _s[0] != '*' ) {
            _s = "*" + _s;
        }
        _s = "addqs@" + _s;
        _s += "@";
        _s += _proxy;
        g_rg->query("RPUSH", "autogw.command", _s);
        std::cout << "Added: " << f.key().asString() << std::endl;
    }
    std::cout << "Done" << std::endl;
    g_rg = nullptr;
}

int main( int argc, char * argv[] ) {
    // Check if this is client or server or command line tools
    loop::main.do_job(std::bind(&co_main, argc, argv));
    loop::main.run();
    return 0;
}

// Push Chen
//