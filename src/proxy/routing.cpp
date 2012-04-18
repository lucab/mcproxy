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
#include "include/proxy/routing.hpp"
#include "include/utils/addr_storage.hpp"

#include <net/if.h>
#include <linux/mroute.h>
#include <linux/mroute6.h>
#include <iostream>

routing::routing():
     worker(ROUTING_MSG_QUEUE_SIZE)
{
     HC_LOG_TRACE("");

}

routing* routing::getInstance(){
     HC_LOG_TRACE("");
     static routing instance;
     return &instance;
}

bool routing::init(int addr_family, int version, mroute_socket* mrt_sock){
     HC_LOG_TRACE("");

     m_addr_family = addr_family;
     m_version = version;
     m_mrt_sock = mrt_sock;

     if(!init_if_prop()) return false;

     return false;
}

bool routing::init_if_prop(){
     HC_LOG_TRACE("");

     if(!m_if_prop.refresh_network_interfaces()) return false;

     return true;
}

bool routing::add_vif(routing_msg* msg){
     HC_LOG_TRACE("");

     char cstr[IF_NAMESIZE];
     struct ifaddrs* item=NULL;
     string if_name(if_indextoname(msg->if_index,cstr));

     if(m_addr_family == AF_INET){
          if((item = m_if_prop.get_ip4_if(if_name))== NULL){
               HC_LOG_ERROR("interface not found: " << if_name);
               return false;
          }
     }else if(m_addr_family == AF_INET6){
          if((item = m_if_prop.get_ip6_if(if_name)->front()) == NULL){
               HC_LOG_ERROR("interface not found: " << if_name);
               return false;
          }
     }else{
          HC_LOG_ERROR("wrong addr_family: " << m_addr_family);
          return false;
     }

     if((item->ifa_flags & IFF_POINTOPOINT) && (item->ifa_dstaddr != NULL)) { //tunnel

          addr_storage p2p_addr(*(item->ifa_dstaddr));

          if(!m_mrt_sock->add_vif(msg->vif,if_name.c_str(),p2p_addr.to_string().c_str())){
               return false;
          }

     }else{ //phyint
          if(!m_mrt_sock->add_vif(msg->vif,if_name.c_str(), NULL)){
               return false;
          }

     }

     HC_LOG_DEBUG("added interface: " << if_name << " to vif_table with vif number:" << msg->vif);
     return true;
}

bool routing::add_route(routing_msg* msg){
     HC_LOG_TRACE("");

     if(m_addr_family == AF_INET){
          if(msg->output_vif.size() > MAXVIFS) return false;
     }else if(m_addr_family == AF_INET6){
          if(msg->output_vif.size() > MAXMIFS) return false;
     }else{
          HC_LOG_ERROR("wrong addr_family: " << m_addr_family);
          return false;
     }

     list<int>::iterator iter_out;
     unsigned int out_vif[msg->output_vif.size()];

     int i=0;
     for(iter_out = msg->output_vif.begin(); iter_out != msg->output_vif.end(); iter_out++){
              out_vif[i++] = *iter_out;
     }

     if(!m_mrt_sock->add_mroute(msg->vif, msg->src_addr.to_string().c_str(), msg->g_addr.to_string().c_str(), out_vif,msg->output_vif.size())){
          return false;
     }

     return true;
}

bool routing::del_route(routing_msg* msg){
     HC_LOG_TRACE("");

     if(!m_mrt_sock->del_mroute(msg->vif, msg->src_addr.to_string().c_str(), msg->g_addr.to_string().c_str())){
          return false;
     }

     return true;
}

bool routing::del_vif(routing_msg* msg){
     HC_LOG_TRACE("");

     if(!m_mrt_sock->del_vif(msg->vif)){
          return false;
     }

     HC_LOG_DEBUG("removed interface with vif number: " << msg->vif) ;
     return true;
}

routing::~routing(){

}

void routing::worker_thread(){
     HC_LOG_TRACE("");

     while(m_running){
          proxy_msg m = m_job_queue.dequeue();
          HC_LOG_DEBUG("received new job. type: " << m.msg_type_to_string());
          switch(m.type){
          case proxy_msg::TEST_MSG: {
               struct test_msg* t= (struct test_msg*) m.msg.get();
               t->test();
               break;
          }
          case proxy_msg::ROUTING_MSG: {
               struct routing_msg* t= (struct routing_msg*) m.msg.get();

               switch(t->type){
               case routing_msg::ADD_VIF: add_vif(t); break;
               case routing_msg::DEL_VIF: del_vif(t); break;
               case routing_msg::ADD_ROUTE: add_route(t); break;
               case routing_msg::DEL_ROUTE: del_route(t); break;
               default: HC_LOG_ERROR("unknown routing action format");
               }
               break;
          }
          case proxy_msg::EXIT_CMD: m_running = false; break;
          default: HC_LOG_ERROR("unknown message format");
          }

     }
     HC_LOG_DEBUG("worker thread routing end");
}
