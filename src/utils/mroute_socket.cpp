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
#include "include/utils/mroute_socket.hpp"

#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <netinet/in.h>
//#include <linux/in6.h>
#include <net/if.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/mroute.h>
#include <linux/mroute6.h>

#include <cstring>
#include <iostream>

using namespace std;

mroute_socket::mroute_socket(){
     HC_LOG_TRACE("");
}


bool mroute_socket::create_raw_ipv4_socket(){
     HC_LOG_TRACE("");

     if (is_udp_valid()) {
          close(m_sock);
     }

     //			IP-Protokollv4, UDP,	Protokoll
     m_sock = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);
     if (m_sock < 0) {
          HC_LOG_ERROR("failed to create! Error: " << strerror(errno) << " errno: " << errno);
          return false; // failed
     } else {
          HC_LOG_DEBUG("get socket discriptor number: " << m_sock);
          m_addrFamily = AF_INET;
          m_own_socket = true;
          return true;
     }

}

bool mroute_socket::create_raw_ipv6_socket(){
     HC_LOG_TRACE("");

     if (is_udp_valid()) {
          close(m_sock);
     }

     //			IP-Protokollv6, UDP,	Protokoll
     m_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6); //SOCK_DGRAM //IPPROTO_IP
     if (m_sock < 0) {
          HC_LOG_ERROR("failed to create! Error: " << strerror(errno) << " errno: " << errno);
          return false; // failed
     } else {
          HC_LOG_DEBUG("get socket discriptor number: " << m_sock);
          m_addrFamily = AF_INET6;
          m_own_socket = true;
          return true;
     }
}

bool mroute_socket::set_no_ip_hdr(){
     HC_LOG_TRACE("");

     if (!is_udp_valid()) {
          HC_LOG_ERROR("raw_socket invalid");
          return false;
     }

     int proto;
     if(m_addrFamily == AF_INET){
          proto = IPPROTO_IP;
     }else if(m_addrFamily == AF_INET6){
          proto =IPPROTO_IPV6;
     }else{
          HC_LOG_ERROR("wrong address family");
          return false;
     }
     int one = 1;
     if (setsockopt (m_sock, proto, IP_HDRINCL, &one, sizeof (one)) < 0){
          HC_LOG_ERROR("failed to set no ip header! Error: " << strerror(errno) << " errno: " << errno);
     }

     return true;
}

u_int16_t mroute_socket::calc_checksum(const unsigned char* buf, int buf_size){
     HC_LOG_TRACE("");

     u_int16_t* b=(u_int16_t*)buf;
     int sum=0;

     for(int i=0; i<buf_size/2;i++){
          ADD_SIGNED_NUM_U16(sum,b[i]);
          //sum +=b[i];
     }

     if(buf_size%2==1){
          //sum += buf[buf_size-1];
          ADD_SIGNED_NUM_U16(sum,buf[buf_size-1]);
     }

     return ~sum;
}

bool mroute_socket::set_default_icmp6_checksum_calc(bool enable){
     HC_LOG_TRACE("");

     if (!is_udp_valid()) {
          HC_LOG_ERROR("raw_socket invalid");
          return false;
     }

     if(m_addrFamily == AF_INET){
          HC_LOG_ERROR("this funktion is only available vor IPv6 sockets ");
          return false;
     }else if(m_addrFamily == AF_INET6){
          int offset = enable? 2 : -1;
          if (setsockopt (m_sock, IPPROTO_IPV6, IP_HDRINCL, &offset, sizeof (offset)) < 0){
               HC_LOG_ERROR("failed to set default ICMP6 checksum! Error: " << strerror(errno) << " errno: " << errno);
               return false;
          }

          return true;
     }else{
          HC_LOG_ERROR("wrong address family");
          return false;
     }

}

bool mroute_socket::add_extension_header(const unsigned char* buf, unsigned int buf_size){
     HC_LOG_TRACE("");

     if (!is_udp_valid()) {
          HC_LOG_ERROR("raw_socket invalid");
          return false;
     }

     if(m_addrFamily == AF_INET){
          HC_LOG_ERROR("this funktion is only available vor IPv6 sockets ");
          return false;
     }else if(m_addrFamily == AF_INET6){
          int rc= setsockopt(m_sock,IPPROTO_IPV6, IPV6_HOPOPTS, buf, buf_size);

          if(rc == -1){
               HC_LOG_ERROR("failed to add extension header! Error: " << strerror(errno) << " errno: " << errno);
               return false;
          }else{
               return true;
          }
     }else{
          HC_LOG_ERROR("wrong address family");
          return false;
     }
}

bool mroute_socket::set_recv_icmpv6_msg(){
     HC_LOG_TRACE("");

     if (!is_udp_valid()) {
          HC_LOG_ERROR("raw_socket invalid");
          return false;
     }

     if(m_addrFamily == AF_INET){
          HC_LOG_ERROR("this funktion is only available vor IPv6 sockets ");
          return false;
     }else if(m_addrFamily == AF_INET6){
          struct icmp6_filter myfilter;

          //ICMP6_FILTER_SETPASSALL(&myfilter);
          ICMP6_FILTER_SETBLOCKALL(&myfilter);
          ICMP6_FILTER_SETPASS(MLD_LISTENER_REPORT, &myfilter);
          ICMP6_FILTER_SETPASS(MLD_LISTENER_REDUCTION, &myfilter);


          if(setsockopt(m_sock,IPPROTO_ICMPV6,ICMP6_FILTER, &myfilter,sizeof(myfilter)) < 0){
               HC_LOG_ERROR("failed to set ICMP6 filter! Error: " << strerror(errno) << " errno: " << errno);
               return false;
          }

          return true;
     }else{
          HC_LOG_ERROR("wrong address family");
          return false;
     }


     //############ ka scheint wichtig zu sein
     //     IPV6_RECVPKTINFO
     //         Enables a SOCK_RAW socket to receive the send and receive interfaces
     //         and the source and destination addresses, for example:

     //           int on = 1;

     //           if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO,
     //                    &on, sizeof(on)) == -1)
     //                     perror("setsockopt IPV6_RECVPKTINFO");


     //###########set icmpv6 filter
     //	ICMP6_FILTER_SETBLOCKALL(&filter);

     //	for (handlers::const_iterator i =
     //		m_handlers.begin(); i != m_handlers.end(); ++i) {
     //		ICMP6_FILTER_SETPASS(i->first, &filter);
     //	}

     //	g_mrd->icmp().register_handler(MLD_LISTENER_REPORT, this);
     //	g_mrd->icmp().register_handler(MLD_LISTENER_REDUCTION, this);
     //	g_mrd->icmp().register_handler(MLD_LISTENER_QUERY, this);
     //	g_mrd->icmp().register_handler(MLDv2_LISTENER_REPORT, this);
     //	g_mrd->icmp().register_handler(MLDv2_LISTENER_REPORT_OLD, this);

     //#######################################
     /*     struct icmp6_filter myfilter;

     ICMP6_FILTER_SETPASSALL(&myfilter);

     rc = setsockopt(m_sock,IPPROTO_ICMPV6,ICMP6_FILTER, &myfilter,sizeof(myfilter));

     if(rc == -1){
          HC_LOG_ERROR("failed to add extension header! Error: " << strerror(errno));
          return false;
     }else{
          return true;
     }
*/
}

bool mroute_socket::set_recv_pkt_info(){

     if (!is_udp_valid()) {
          HC_LOG_ERROR("raw_socket invalid");
          return false;
     }

     if(m_addrFamily == AF_INET){
          HC_LOG_ERROR("this funktion is only available vor IPv6 sockets ");
          return false;
     }else if(m_addrFamily == AF_INET6){
          int on = 1;

          if(setsockopt(m_sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0){
               HC_LOG_ERROR("failed to set IPV6_RECVPKTINFO! Error: " << strerror(errno) << " errno: " << errno);
               return false;
          }

          return true;
     }else{
          HC_LOG_ERROR("wrong address family");
          return false;
     }
}

bool mroute_socket::set_recv_hop_by_hop_msg(){
     HC_LOG_TRACE("");

     if (!is_udp_valid()) {
          HC_LOG_ERROR("raw_socket invalid");
          return false;
     }

     if(m_addrFamily == AF_INET){
          HC_LOG_ERROR("this funktion is only available vor IPv6 sockets ");
          return false;
     }else if(m_addrFamily == AF_INET6){
          int on = 1;
          if(setsockopt(m_sock, IPPROTO_IPV6, IPV6_RECVHOPOPTS, &on, sizeof(on)) < 0){
               HC_LOG_ERROR("failed to set IPV6_RECVHOPOPTS! Error: " << strerror(errno) << " errno: " << errno);
               return false;
          }

          return true;
     }else{
          HC_LOG_ERROR("wrong address family");
          return false;
     }
}

bool mroute_socket::set_mrt_flag(bool enable){
     HC_LOG_TRACE("enable: " << enable);

     if (!is_udp_valid()) {
          HC_LOG_ERROR("raw_socket invalid");
          return false;
     }

     int rc;
     int proto;
     int mrt_cmd;

     if(enable){
          if(m_addrFamily == AF_INET){
               proto = IPPROTO_IP;
               mrt_cmd = MRT_INIT;
          }else if(m_addrFamily == AF_INET6){
               proto = IPPROTO_IPV6;
               mrt_cmd = MRT6_INIT;
          }else{
               HC_LOG_ERROR("wrong address family");
               return false;
          }

          int val=1;
          rc = setsockopt(m_sock,proto, mrt_cmd, (void*)&val, sizeof(val));

          if(rc == -1){
               HC_LOG_ERROR("failed to set MRT flag! Error: " << strerror(errno) << " errno: " << errno);
               return false;
          }else{
               return true;
          }
     }else{
          if(m_addrFamily == AF_INET){
               proto = IPPROTO_IP;
               mrt_cmd = MRT_DONE;
          }else if(m_addrFamily == AF_INET6){
               proto = IPPROTO_IPV6;
               mrt_cmd = MRT6_DONE;
          }else{
               HC_LOG_ERROR("wrong address family");
               return false;
          }

          rc = setsockopt(m_sock,proto, mrt_cmd, NULL, 0);

          if(rc == -1){
               HC_LOG_ERROR("failed to reset MRT flag! Error: " << strerror(errno) << " errno: " << errno);
               return false;
          }else{
               return true;
          }
     }
}

//vifNum musst the same uniqueName  on delVIF (0 > vifNum < MAXVIF ==32)
//iff_register = true if used for PIM Register encap/decap
bool mroute_socket::add_vif(int vifNum, const char* ifName, const char* ipTunnelRemoteAddr){
     HC_LOG_TRACE("");

     if (!is_udp_valid()) {
          HC_LOG_ERROR("raw_socket invalid");
          return false;
     }

     int rc;

     if(m_addrFamily == AF_INET){
          struct vifctl vc;
          vifi_t index=if_nametoindex(ifName);

          //VIFF_TUNNEL   /* vif represents a tunnel end-point */
          //VIFF_SRCRT    /* tunnel uses IP src routing */
          //VIFF_REGISTER /* used for PIM Register encap/decap */
          unsigned char flags;
          flags = VIFF_USE_IFINDEX;

          memset(&vc, 0, sizeof(vc));
          vc.vifc_vifi = vifNum;
          vc.vifc_flags = flags;
          vc.vifc_threshold = MROUTE_TTL_THRESHOLD;
          vc.vifc_rate_limit = MROUTE_RATE_LIMIT_ENDLESS;
          vc.vifc_lcl_ifindex =index;

          if(ipTunnelRemoteAddr != NULL){
               if(!inet_pton(AF_INET, ipTunnelRemoteAddr, (void*)&vc.vifc_rmt_addr)>0){
                    HC_LOG_ERROR("cannot convert ipTunnelRemoteAddr: " << ipTunnelRemoteAddr);
               }
          }

          rc = setsockopt(m_sock,IPPROTO_IP,MRT_ADD_VIF,(void *)&vc,sizeof(vc));
          if (rc == -1) {
               HC_LOG_ERROR("failed to add VIF! Error: " << strerror(errno) << " errno: " << errno);
               return false;
          } else {
               return true;
          }

     }else if(m_addrFamily == AF_INET6){
          struct mif6ctl mc;
          mifi_t index=if_nametoindex(ifName);

          unsigned char flags;
          flags = 0;

          memset(&mc, 0, sizeof(mc));
          mc.mif6c_mifi = vifNum;
          mc.mif6c_flags = flags;
          mc.vifc_rate_limit = MROUTE_RATE_LIMIT_ENDLESS;
          mc.vifc_threshold = MROUTE_TTL_THRESHOLD;
          mc.mif6c_pifi = index;

          rc = setsockopt(m_sock, IPPROTO_IPV6, MRT6_ADD_MIF, (void *)&mc,sizeof(mc));
          if (rc == -1) {
               HC_LOG_ERROR("failed to add VIF! Error: " << strerror(errno) << " errno: " << errno);
               return false;
          } else {
               return true;
          }

     }else{
          HC_LOG_ERROR("wrong address family");
          return false;
     }
}

bool mroute_socket::del_vif(int vifNum){
     HC_LOG_TRACE("");

     if (!is_udp_valid()) {
          HC_LOG_ERROR("raw_socket invalid");
          return false;
     }

     int rc;

     if(m_addrFamily == AF_INET){
          struct vifctl vifc;
          memset(&vifc, 0, sizeof(vifc));

          vifc.vifc_vifi= vifNum;
          rc = setsockopt(m_sock, IPPROTO_IP, MRT_DEL_VIF, (char *)&vifc, sizeof(vifc));
          if (rc == -1) {
               HC_LOG_ERROR("failed to del VIF! Error: " << strerror(errno) << " errno: " << errno);
               return false;
          } else {
               return true;
          }
     }else if(m_addrFamily == AF_INET6){
          struct mif6ctl mc;
          memset(&mc, 0, sizeof(mc));

          mc.mif6c_mifi = vifNum;
          rc = setsockopt(m_sock, IPPROTO_IPV6, MRT6_DEL_MIF, (char *)&mc, sizeof(mc));
          if (rc == -1) {
               HC_LOG_ERROR("failed to del VIF! Error: " << strerror(errno) << " errno: " << errno);
               return false;
          } else {
               return true;
          }
     }else{
          HC_LOG_ERROR("wrong address family");
          return false;
     }
}

//source_addr is the source address of the received multicast packet
//group_addr group address of the received multicast packet
bool mroute_socket::add_mroute(int input_vifNum, const char* source_addr, const char* group_addr, unsigned int* output_vifTTL, unsigned int output_vifTTL_Ncount){
     HC_LOG_TRACE("");

     if (!is_udp_valid()) {
          HC_LOG_ERROR("raw_socket invalid");
          return false;
     }

     int rc;

     if(m_addrFamily == AF_INET){
          struct mfcctl mc;
          memset(&mc, 0, sizeof(mc));

          if(!inet_pton(m_addrFamily, source_addr, &mc.mfcc_origin)>0){
               HC_LOG_ERROR("cannot convert source_addr: " << source_addr);
               return false;
          }

          if(!inet_pton(m_addrFamily, group_addr, &mc.mfcc_mcastgrp)>0){
               HC_LOG_ERROR("cannot convert group_addr: " << group_addr);
               return false;
          }

          mc.mfcc_parent = input_vifNum;

          if(output_vifTTL_Ncount >= MAXVIFS){
               HC_LOG_ERROR("output_vifNum_size to large: " << output_vifTTL_Ncount);
               return false;
          }

          for (unsigned int i = 0; i < output_vifTTL_Ncount; i++){
               mc.mfcc_ttls[output_vifTTL[i]] = MROUTE_DEFAULT_TTL;
          }

          rc = setsockopt(m_sock, IPPROTO_IP, MRT_ADD_MFC,(void *)&mc, sizeof(mc));
          if (rc == -1) {
               HC_LOG_ERROR("failed to add multicast route! Error: " << strerror(errno) << " errno: " << errno);
               return false;
          } else {
               return true;
          }

     }else if(m_addrFamily == AF_INET6){
          struct mf6cctl mc;
          memset(&mc, 0, sizeof(mc));

          if(!inet_pton(m_addrFamily, source_addr, &mc.mf6cc_origin.sin6_addr)>0){
               HC_LOG_ERROR("cannot convert source_addr: " << source_addr);
               return false;
          }

          if(!inet_pton(m_addrFamily, group_addr, &mc.mf6cc_mcastgrp.sin6_addr)>0){
               HC_LOG_ERROR("cannot convert group_addr: " << group_addr);
               return false;
          }

          mc.mf6cc_parent = input_vifNum;

          if(output_vifTTL_Ncount >= MAXMIFS){
               HC_LOG_ERROR("output_vifNum_size to large: " << output_vifTTL_Ncount);
               return false;
          }

          for (unsigned int i = 0; i < output_vifTTL_Ncount; i++){
               IF_SET(output_vifTTL[i],&mc.mf6cc_ifset);
          }

          rc = setsockopt(m_sock, IPPROTO_IPV6, MRT6_ADD_MFC, (void*)&mc, sizeof(mc));
          if (rc == -1) {
               HC_LOG_ERROR("failed to add multicast route! Error: " << strerror(errno) << " errno: " << errno);
               return false;
          } else {
               return true;
          }

     }else{
          HC_LOG_ERROR("wrong address family");
          return false;
     }

}

bool mroute_socket::del_mroute(int input_vifNum, const char* source_addr, const char* group_addr){
     HC_LOG_TRACE("");

     if (!is_udp_valid()) {
          HC_LOG_ERROR("raw_socket invalid");
          return false;
     }

     int rc;

     if(m_addrFamily == AF_INET){
          struct mfcctl mc;
          memset(&mc, 0, sizeof(mc));

          if(!inet_pton(m_addrFamily, source_addr, &mc.mfcc_origin)>0){
               HC_LOG_ERROR("cannot convert source_addr: " << source_addr);
               return false;
          }

          if(!inet_pton(m_addrFamily, group_addr, &mc.mfcc_mcastgrp)>0){
               HC_LOG_ERROR("cannot convert group_addr: " << group_addr);
               return false;
          }

          mc.mfcc_parent = input_vifNum;

          rc = setsockopt(m_sock, IPPROTO_IP, MRT_DEL_MFC,(void *)&mc, sizeof(mc));
          if (rc == -1) {
               HC_LOG_ERROR("failed to add multicast route! Error: " << strerror(errno) << " errno: " << errno);
               return false;
          } else {
               return true;
          }

     }else if(m_addrFamily == AF_INET6){
          struct mf6cctl mc;
          memset(&mc, 0, sizeof(mc));

          if(!inet_pton(m_addrFamily, source_addr, &mc.mf6cc_origin.sin6_addr)>0){
               HC_LOG_ERROR("cannot convert source_addr: " << source_addr);
               return false;
          }

          if(!inet_pton(m_addrFamily, group_addr, &mc.mf6cc_mcastgrp.sin6_addr)>0){
               HC_LOG_ERROR("cannot convert group_addr: " << group_addr);
               return false;
          }

          mc.mf6cc_parent = input_vifNum;

          rc = setsockopt(m_sock, IPPROTO_IPV6, MRT6_DEL_MFC,(void *)&mc, sizeof(mc));
          if (rc == -1) {
               HC_LOG_ERROR("failed to add multicast route! Error: " << strerror(errno) << " errno: " << errno);
               return false;
          } else {
               return true;
          }
     }else{
          HC_LOG_ERROR("wrong address family");
          return false;
     }
     return false;
}

void mroute_socket::print_struct_mf6cctl(struct mf6cctl* mc){
     HC_LOG_TRACE("");

     char addressBuffer[INET6_ADDRSTRLEN];

     cout << "##-- mf6cctl --##" << endl;
     cout << " -mf6cc_parent: " << mc->mf6cc_parent << endl;
     cout << " -mcastgrp: " << inet_ntop(AF_INET6, &mc->mf6cc_mcastgrp.sin6_addr, addressBuffer, sizeof(addressBuffer)) << endl;
     cout << " -mcastorigin: " << inet_ntop(AF_INET6, &mc->mf6cc_origin.sin6_addr, addressBuffer, sizeof(addressBuffer)) << endl;

     cout << " -mf6cc_ifset: ";
     for (int i = 0; i < MAXMIFS; i++) {
          if (IF_ISSET(i, &mc->mf6cc_ifset)){
               cout << i << "; ";
          }
     }
     cout << endl;
}

void mroute_socket::test_mcrouter_mrt_flag(){
     HC_LOG_TRACE("");

     int sleepTime = 1;
     mroute_socket m;
     mroute_socket m1;

     cout << "--<1> set MRT flag ipv4 --" << endl;
     m.create_raw_ipv4_socket();
     if(m.set_mrt_flag(true)){
          cout << "set OK!" << endl;
     }else{
          cout << "set FAILED!" << endl;
     }

     sleep(sleepTime);

     cout << "-- reset MRT flag ipv4 --" << endl;
     if(m.set_mrt_flag(false)){
          cout << "reset OK!" << endl;
     }else{
          cout << "reset FAILED!" << endl;
     }

     sleep(sleepTime);

     cout << "-- set MRT flag ipv4 again --" << endl;
     m.create_raw_ipv4_socket();
     if(m.set_mrt_flag(true)){
          cout << "set OK!" << endl;
     }else{
          cout << "set FAILED!" << endl;
     }

     cout << "--<2> set MRT flag ipv6 --" << endl;
     m.create_raw_ipv6_socket();
     if(m.set_mrt_flag(true)){
          cout << "set OK!" << endl;
     }else{
          cout << "set FAILED!" << endl;
     }

     sleep(sleepTime);

     cout << "-- reset MRT flag ipv6 --" << endl;
     if(m.set_mrt_flag(false)){
          cout << "reset OK!" << endl;
     }else{
          cout << "reset FAILED!" << endl;
     }

     sleep(sleepTime);

     cout << "--<3> error test set 2x MRT flag ipv4 --" << endl;
     m.create_raw_ipv4_socket();
     m1.create_raw_ipv4_socket();
     if(m.set_mrt_flag(true)){
          cout << "set 1 OK!" << endl;
     }else{
          cout << "set 1 FAILED!" << endl;
     }

     if(m1.set_mrt_flag(true)){
          cout << "set 2 OK! ==> FAILED!" << endl;
     }else{
          cout << "set 2 FAILED! ==> OK!" << endl;
     }

     sleep(sleepTime);

     if(m.set_mrt_flag(false)){
          cout << "reset 1 OK!" << endl;
     }else{
          cout << "reset 1 FAILED!" << endl;
     }

     if(m1.set_mrt_flag(false)){
          cout << "reset 2 OK! ==> FAILED!" << endl;
     }else{
          cout << "reset 2 FAILED! ==> OK!" << endl;
     }

     sleep(sleepTime);

     cout << "--<4> error test set 2x MRT flag ipv6 --" << endl;
     m.create_raw_ipv6_socket();
     m1.create_raw_ipv6_socket();
     if(m.set_mrt_flag(true)){
          cout << "set 1 OK!" << endl;
     }else{
          cout << "set 1 FAILED!" << endl;
     }

     if(m1.set_mrt_flag(true)){
          cout << "set 2 OK! ==> FAILED" << endl;
     }else{
          cout << "set 2 FAILED! ==> OK!" << endl;
     }

     sleep(sleepTime);

     if(m.set_mrt_flag(false)){
          cout << "reset 1 OK!" << endl;
     }else{
          cout << "reset 1 FAILED!" << endl;
     }

     if(m1.set_mrt_flag(false)){
          cout << "reset 2 OK! ==> FAILED!" << endl;
     }else{
          cout << "reset 2 FAILED! ==> OK!" << endl;
     }

     sleep(sleepTime);

     cout << "--<5> error test set 2x MRT flag ipv4&ipv6 --" << endl;
     m.create_raw_ipv4_socket();
     m1.create_raw_ipv6_socket();
     if(m.set_mrt_flag(true)){
          cout << "set 1 OK!" << endl;
     }else{
          cout << "set 1 FAILED!" << endl;
     }

     if(m1.set_mrt_flag(true)){
          cout << "set 2 OK!" << endl;
     }else{
          cout << "set 2 FAILED!" << endl;
     }

     sleep(sleepTime);

     if(m.set_mrt_flag(false)){
          cout << "reset 1 OK!" << endl;
     }else{
          cout << "reset 1 FAILED!" << endl;
     }

     if(m1.set_mrt_flag(false)){
          cout << "reset 2 OK!" << endl;
     }else{
          cout << "reset 2 FAILED!" << endl;
     }

}

void mroute_socket::test_add_vifs(mroute_socket* m){
     HC_LOG_TRACE("");

     int if_one = MROUTE_SOCKET_IF_NUM_ONE;
     string str_if_one = MROUTE_SOCKET_IF_STR_ONE;
     int if_two = MROUTE_SOCKET_IF_NUM_TWO;
     string str_if_two = MROUTE_SOCKET_IF_STR_TWO;


     cout << "-- addVIFs test --" << endl;
     if(m->add_vif(if_one, str_if_one.c_str(),NULL)){
          cout << "addVIF " << str_if_one << " OK!" << endl;
     }else{
          cout << "addVIF " << str_if_one << " FAILED!" << endl;
     }

     if(m->add_vif(if_two, str_if_two.c_str(),NULL)){
          cout << "addVIF " << str_if_two << " OK!" << endl;
     }else{
          cout << "addVIF " << str_if_two << " FAILED!" << endl;
     }


     /*if(m->addVIF(if_three, str_if_three.c_str(),false,false,false,NULL)){
          cout << "addVIF " << str_if_three << " OK!" << endl;
     }else{
          cout << "addVIF " << str_if_three << " FAILED!" << endl;
     }*/

}


void mroute_socket::test_del_vifs(mroute_socket* m){
     HC_LOG_TRACE("");

     int if_one = MROUTE_SOCKET_IF_NUM_ONE;
     int if_two = MROUTE_SOCKET_IF_NUM_TWO;

     cout << "-- delVIFs test--" << endl;
     if(m->del_vif(if_one)){
          cout << "delVIF OK!" << endl;
     }else{
          cout << "delVIF FAILED!" << endl;
     }

     if(m->del_vif(if_two)){
          cout << "delVIF OK!" << endl;
     }else{
          cout << "delVIF FAILED!" << endl;
     }
}

void mroute_socket::test_add_route(mroute_socket* m){
     HC_LOG_TRACE("");

     const char* src_addr;
     const char* g_addr;
     int if_one = MROUTE_SOCKET_IF_NUM_ONE;
     string str_if_one = MROUTE_SOCKET_IF_STR_ONE;
     int if_two = MROUTE_SOCKET_IF_NUM_TWO;
     string str_if_two = MROUTE_SOCKET_IF_STR_TWO;

     //int if_three = MROUTE_SOCKET_IF_NUM_THREE;

     if(m->get_addr_family() == AF_INET){
          src_addr= MROUTE_SOCKET_SRC_ADDR_V4;
          g_addr = MROUTE_SOCKET_G_ADDR_V4;
     }else if(m->get_addr_family() == AF_INET6){
          src_addr =  MROUTE_SOCKET_SRC_ADDR_V6;
          g_addr = MROUTE_SOCKET_G_ADDR_V6;
     }else{
          cout << "FAILED to start test wrong addrFamily: "<< m->get_addr_family() << endl;
          return;
     }

     cout << "-- addRoute test --" << endl;
     unsigned int output_vifs[]={/*if_three,*/ if_two}; //if_two
     if(m->add_mroute(if_one, src_addr, g_addr ,output_vifs, sizeof(output_vifs)/sizeof(output_vifs[0]))){
          cout << "addRoute (" << str_if_one << " ==> " << str_if_two << ") OK!" << endl;
     }else{
          cout << "addRoute (" << str_if_one << " ==> " << str_if_two << ") FAILED!" << endl;
     }
}

void mroute_socket::test_del_route(mroute_socket* m){
     HC_LOG_TRACE("");

     const char* src_addr;
     const char* g_addr;
     int if_one = MROUTE_SOCKET_IF_NUM_ONE;
     string str_if_one = MROUTE_SOCKET_IF_STR_ONE;
     string str_if_two = MROUTE_SOCKET_IF_STR_TWO;

     if(m->get_addr_family() == AF_INET){
          src_addr= MROUTE_SOCKET_SRC_ADDR_V4;
          g_addr = MROUTE_SOCKET_G_ADDR_V4;
     }else if(m->get_addr_family() == AF_INET6){
          src_addr =  MROUTE_SOCKET_SRC_ADDR_V6;
          g_addr = MROUTE_SOCKET_G_ADDR_V6;
     }else{
          cout << "FAILED to start test wrong addrFamily: "<< m->get_addr_family() << endl;
          return;
     }

     cout << "-- delRoute test --" << endl;
     if(m->del_mroute(if_one, src_addr, g_addr)){
          cout << "delMRoute (" << str_if_one << " ==> " << str_if_two << ") OK!" << endl;
     }else{
          cout << "delMRoute (" << str_if_one << " ==> " << str_if_two << ") FAILED!" << endl;
     }
}

void mroute_socket::test_mcrouter_vifs_routes(int addrFamily){
     HC_LOG_TRACE("");

     mroute_socket m;

     int sleepTime = 1;

     if(addrFamily == AF_INET){
          m.create_raw_ipv4_socket();
     }else if(addrFamily == AF_INET6){
          m.create_raw_ipv6_socket();
     }else{
          cout << "FAILED to start test wrong addrFamily: "<< addrFamily << endl;
          return;
     }

     cout << "-- set mrt flag --" << endl;
     if(m.set_mrt_flag(true)){
          cout << "set MRT flag OK!" << endl;
     }else{
          cout << "set MRT flag FAILED!" << endl;
     }

     m.test_add_vifs(&m);

     sleep(sleepTime);

     m.test_add_route(&m);

     m.test_del_route(&m);

     m.test_del_vifs(&m);

     cout << "-- reset mrt flag --" << endl;
     if(m.set_mrt_flag(false)){
          cout << "reset MRT flag OK!" << endl;
     }else{
          cout << "reset MRT flag FAILED!" << endl;
     }

     sleep(sleepTime);
}

mroute_socket::~mroute_socket() {
     HC_LOG_TRACE("");
}
