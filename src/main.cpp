/*
 * This file is part of mcproxy.
 *
 * mcproxy is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or (at your
 * option) any later version.
 *
 * mcproxy is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with mcproxy; see the file COPYING.LESSER.
 *
 * written by Sebastian Woelke, in cooperation with:
 * INET group, Hamburg University of Applied Sciences,
 * Website: http://mcproxy.realmv6.org/
 */

#include "include/hamcast_logging.h"
#include "include/utils/if_prop.hpp"
#include "include/utils/mc_socket.hpp"
#include "include/utils/mroute_socket.hpp"
#include "include/utils/mc_tables.hpp"
#include "include/utils/addr_storage.hpp"
#include "include/proxy/proxy.hpp"
#include "include/proxy/timing.hpp"
#include "include/proxy/check_if.hpp"
#include "include/utils/if_prop.hpp"


#include <iostream>
using namespace std;

void test_log();
void test_mctables();
void test_MC_TestTool();
void test_mcproxy(int arg_count, char* args[]);
void test_test();

int main(int arg_count, char* args[]) {
     hc_set_default_log_fun(HC_LOG_TRACE_LVL);

     //test_MC_Tables();
     //test_MC_TestTool();

     test_mcproxy(arg_count,args);


     //test_test();
     return 0;
}

void test_log(){
     hc_set_default_log_fun(HC_LOG_TRACE_LVL);
     HC_LOG_TRACE("");

     HC_LOG_DEBUG("HC_LOG_DEBUG");
     HC_LOG_INFO("HC_LOG_INFO");
     HC_LOG_WARN("HC_LOG_WARN");
     HC_LOG_ERROR("HC_LOG_ERROR");
     HC_LOG_FATAL("HC_LOG_FATAL");
}

void test_mctables(){
     mroute_socket m4;
     mroute_socket m6;
     if(!m4.create_raw_ipv4_socket()){
          cout << "m4.create_RAW_IPv4_Socket FAILED!" << endl;
          return;
     }

     if(!m6.create_raw_ipv6_socket()){
          cout << "m6.create_RAW_IPv6_Socket FAILED!" << endl;
          return;
     }

     if(!m4.set_mrt_flag(true)){
          cout << "m4.setMRouter_flag FAILED!" << endl;
          return;
     }

     if(!m6.set_mrt_flag(true)){
          cout << "m6.setMRouter_flag FAILED!" << endl;
          return;
     }

     cout << "##-- joined groups ipv4 -- ##" << endl;
     mc_tables::test_joined_groups(AF_INET);

     cout << endl << "##-- print vifs ipv4 --##" << endl;
     mroute_socket::test_add_vifs(&m4);
     mc_tables::test_vifs(AF_INET);

     cout << endl << "##-- print cache ipv4 --##" << endl;
     mroute_socket::test_add_route(&m4);
     mc_tables::test_mr_cache(AF_INET);
     mroute_socket::test_del_route(&m4);
     mroute_socket::test_del_vifs(&m4);

     cout << endl <<"##-- joined groups ipv6 -- ##" << endl;
     mc_tables::test_joined_groups(AF_INET6);

     cout << endl <<"##-- print vifs ipv6 --##" << endl;
     mroute_socket::test_add_vifs(&m6);
     mc_tables::test_vifs(AF_INET6);

     cout << endl << "##-- print cache ipv6 --##" << endl;
     mroute_socket::test_add_route(&m6);
     mc_tables::test_mr_cache(AF_INET6);

     mroute_socket::test_del_route(&m6);
     mroute_socket::test_del_vifs(&m6);
}

void test_mcproxy(int arg_count, char* args[]){
     hc_set_default_log_fun(HC_LOG_ERROR_LVL);

     proxy p;
     if(p.init(arg_count, args)){
          cout << "mcproxy started" << endl;
          cout << p.get_state_table() << endl;
          p.start();
          p.end();
     }else{
          cout << "mcproxy stoped" << endl;
     }

}

void test_test(){
    mc_socket::test_join_leave_send();
}
