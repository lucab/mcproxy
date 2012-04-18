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
#include "include/utils/addr_storage.hpp"

#include <cstring>
#include <errno.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <iostream>

//using namespace std;

if_prop::if_prop():
     m_if_addrs(0)
{
     HC_LOG_TRACE("");
}

bool if_prop::refresh_network_interfaces(){
     HC_LOG_TRACE("");

     //clean
     if(is_getaddrs_valid()){
          freeifaddrs(m_if_addrs);
     }

     m_if_map.clear();

     //create
     if(getifaddrs(&m_if_addrs) < 0){
          HC_LOG_ERROR("getifaddrs failed! Error: " << strerror(errno) );
          return false;
     }

     struct ifaddrs* ifEntry=NULL;
     for(ifEntry=m_if_addrs; ifEntry!=NULL; ifEntry=ifEntry->ifa_next) {
          if(ifEntry->ifa_addr->sa_data == NULL) {
               continue;
          }


          if(ifEntry->ifa_addr->sa_family==AF_INET) {
               if_prop_map::iterator iter = m_if_map.find(ifEntry->ifa_name);
               if(iter != m_if_map.end()){ //existing interface
                    if(iter->second.first != NULL){
                        HC_LOG_WARN("more than one ipv4 address for one interface configurated! used:" << addr_storage(*(iter->second.first->ifa_addr)) << "; don't used:" << addr_storage(*(ifEntry->ifa_addr)) << ";");
                        //return false;
                    }else{
                         iter->second.first = ifEntry;
                    }
               }else{ //new interface
                    m_if_map.insert(if_prop_pair(ifEntry->ifa_name, ipv4_6_pair(ifEntry,list<struct ifaddrs*>())));
               }
          } else if(ifEntry->ifa_addr->sa_family==AF_INET6) {
               if_prop_map::iterator iter = m_if_map.find(ifEntry->ifa_name);
               if(iter != m_if_map.end()){ //existing interface
                    list<struct ifaddrs*>* l = &iter->second.second;
                    l->push_back(ifEntry);
               }else{ //new interface
                    list<struct ifaddrs*> l;
                    l.push_back(ifEntry);
                    m_if_map.insert(if_prop_pair(ifEntry->ifa_name, ipv4_6_pair(NULL,l)));
               }
          } else {
               //It isn't IPv4 or IPv6
               continue;
          }

     }
     return true;
}

if_prop_map* if_prop::get_if_props(){
     HC_LOG_TRACE("");

     if (!is_getaddrs_valid()) {
          HC_LOG_ERROR("data invalid");
          return NULL;
     }

     return &m_if_map;
}

struct ifaddrs* if_prop::get_ip4_if(const string &if_name) {
     HC_LOG_TRACE("");

     if (!is_getaddrs_valid()) {
          HC_LOG_ERROR("data invalid");
          return NULL;
     }

     if_prop_map::iterator if_prop_iter = m_if_map.find(if_name);
     if(if_prop_iter == m_if_map.end()) return NULL;

     return if_prop_iter->second.first;
}

list<struct ifaddrs*>* if_prop::get_ip6_if(const string &if_name){
     HC_LOG_TRACE("");

     if (!is_getaddrs_valid()) {
          HC_LOG_ERROR("data invalid");
          return NULL;
     }

     if_prop_map::iterator if_prop_iter = m_if_map.find(if_name);
     if(if_prop_iter == m_if_map.end()) return NULL;

     return &(if_prop_iter->second.second);
}

void if_prop::print_if_addr(const struct ifaddrs* if_p){
     cout << "\tif name: " << if_p->ifa_name << endl;
     cout << "\t- addr: " << addr_storage(*if_p->ifa_addr) << endl;
     cout << "\t- netmask: " << addr_storage(*if_p->ifa_netmask) << endl;

     cout << "\t- flags:";
     if(if_p->ifa_flags & IFF_UP) cout << "IFF_UP ";
     if(if_p->ifa_flags & IFF_RUNNING) cout << "IFF_RUNNING ";
     if(if_p->ifa_flags & IFF_LOOPBACK) cout << "IFF_LOOPBACK ";
     if(if_p->ifa_flags & IFF_BROADCAST) cout << "IFF_BROADCAST ";
     if(if_p->ifa_flags & IFF_ALLMULTI) cout << "IFF_ALLMULTI ";
     if(if_p->ifa_flags & IFF_MULTICAST) cout << "IFF_MULTICAST ";
     if(if_p->ifa_flags & IFF_PROMISC) cout << "IFF_PROMISCIFF_PROMISC ";
     if(if_p->ifa_flags & IFF_POINTOPOINT) cout << "IFF_POINTOPOINT ";

     cout << endl;

     if(if_p->ifa_flags & IFF_POINTOPOINT){
          if(if_p->ifa_dstaddr != NULL){
               cout << "\t- dstaddr: " << addr_storage(*if_p->ifa_dstaddr) << endl;
          }
     }else if(if_p->ifa_addr->sa_family == AF_INET){ //broadcast addr
          cout << "\t- broadaddr: " << addr_storage(*if_p->ifa_broadaddr) << endl;
     }
}

void if_prop::print_if_info(){
     HC_LOG_TRACE("");

     if (!is_getaddrs_valid()) {
          HC_LOG_ERROR("data invalid");
          return;
     }

     if_prop_map* prop = get_if_props();
     if(prop == NULL){
          HC_LOG_ERROR("data struct not found");
          return;
     }

     struct ifaddrs* if_p;
     list<struct ifaddrs*>* if_p_list;

     cout << "##-- IPv4 [count:" << prop->size() << "]--##" << endl;
     for(if_prop_map::iterator iter = prop->begin(); iter != prop->end(); iter++){
          if_p = get_ip4_if(iter->first);
          if(if_p == NULL){
               HC_LOG_ERROR("interface name not found: " << iter->first);
               continue;
          }

          print_if_addr(if_p);
     }

     cout << "##-- IPv6 [count:" << prop->size() << "]--##" << endl;
     for(if_prop_map::iterator iter = prop->begin(); iter != prop->end(); iter++){
          if_p_list = get_ip6_if(iter->first);

          if(if_p_list == NULL){
               HC_LOG_ERROR("interface name not found: " << iter->first);
               continue;
          }

          for(list<struct ifaddrs*>::iterator itera = if_p_list->begin(); itera != if_p_list->end(); itera++){
               print_if_addr(*itera);
          }
     }
}

if_prop::~if_prop(){
     HC_LOG_TRACE("");

     if(is_getaddrs_valid()){
          freeifaddrs(m_if_addrs);
     }
}

void if_prop::test_if_prop(){
     HC_LOG_TRACE("");

     if_prop p;
     cout << "##-- refresh --##" << endl;
     if(!p.refresh_network_interfaces()){
          cout << "refresh faild" << endl;
          return;
     }
     p.print_if_info();
     cout << "##-- refresh --##" << endl;
     sleep(1);
     if(!p.refresh_network_interfaces()){
          cout << "refresh faild" << endl;
          return;
     }
     p.print_if_info();
}
