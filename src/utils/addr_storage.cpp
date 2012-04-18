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
#include "include/utils/addr_storage.hpp"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <endian.h>
#include <string>

addr_storage::addr_storage(){
     HC_LOG_TRACE("");

     memset(&m_addr,0, sizeof(m_addr));
     m_addr.ss_family = INIT_ADDR_FAMILY;
}

addr_storage::addr_storage(int addr_family){
     HC_LOG_TRACE("");

     memset(&m_addr,0, sizeof(m_addr));
     m_addr.ss_family = addr_family;
}

addr_storage::addr_storage(const std::string& addr){
     HC_LOG_TRACE("");

     *this = addr;
}

addr_storage::addr_storage(const struct sockaddr_storage& addr){
     HC_LOG_TRACE("");

     *this = addr;
}

addr_storage::addr_storage(const addr_storage& addr){
     HC_LOG_TRACE("");

     *this = addr;
}

addr_storage::addr_storage(const struct in_addr& addr){
     HC_LOG_TRACE("");

     *this = addr;
}

addr_storage::addr_storage(const struct in6_addr& addr){
     HC_LOG_TRACE("");

     *this = addr;
}

addr_storage::addr_storage(const struct sockaddr& addr){
     HC_LOG_TRACE("");

     *this = addr;
}

std::ostream& operator <<(std::ostream& s, const addr_storage a){
     HC_LOG_TRACE("");

     char addressBuffer[INET6_ADDRSTRLEN];
     if(inet_ntop(a.m_addr.ss_family, (void*)&a.m_addr.__ss_align, addressBuffer, sizeof(addressBuffer)) != NULL){
          s << addressBuffer;
     }else{
          HC_LOG_ERROR("failed to convert sockaddr_storage");
          s << "??";
     }

     return s;
}

struct sockaddr_storage& operator<<=(struct sockaddr_storage& l, const struct addr_storage& r){
     HC_LOG_TRACE("");

     l = r.m_addr;
     return l;
}

struct in_addr& operator<<=(struct in_addr& l,const addr_storage& r){
     HC_LOG_TRACE("");

     l = *(struct in_addr*)&r.m_addr.__ss_align;
     return l;
}

struct in6_addr& operator<<=(struct in6_addr& l,const addr_storage& r){
     HC_LOG_TRACE("");

     l = *(struct in6_addr*)&r.m_addr.__ss_align;
     return l;
}

addr_storage& addr_storage::operator=(const addr_storage& s){
     HC_LOG_TRACE("");

     if(this != &s){
          this->m_addr = s.m_addr;
     }

     return *this;
}

addr_storage& addr_storage::operator=(const struct sockaddr_storage& s){
     HC_LOG_TRACE("");

     this->m_addr = s;
     return *this;
}

addr_storage& addr_storage::operator=(const std::string& s){
     HC_LOG_TRACE("");

     if(s.find_first_of(':')==std::string::npos){ //==> IPv4
          m_addr.ss_family=AF_INET;
     }else{ //==> IPv6
     m_addr.ss_family=AF_INET6;
}

if(inet_pton(m_addr.ss_family, s.c_str(), &m_addr.__ss_align)<1){
     HC_LOG_ERROR("failed to convert string to sockaddr_storage:" << s);
}

return *this;
}

addr_storage& addr_storage::operator=(const struct in_addr& s){
     HC_LOG_TRACE("");

     m_addr.ss_family = AF_INET;
     *(struct in_addr*)&m_addr.__ss_align = s;
     return *this;
}

addr_storage& addr_storage::operator=(const struct in6_addr& s){
     HC_LOG_TRACE("");

     m_addr.ss_family = AF_INET6;
     *(struct in6_addr*)&m_addr.__ss_align = s;
     return *this;
}

addr_storage& addr_storage::operator=(const struct sockaddr& s){
     HC_LOG_TRACE("");

     m_addr.ss_family = s.sa_family;
     if(s.sa_family == AF_INET){
          *(struct in_addr*)&m_addr.__ss_align = ((struct sockaddr_in*)&s)->sin_addr;
     }else if(s.sa_family == AF_INET6){
          *(struct in6_addr*)&m_addr.__ss_align =  ((struct sockaddr_in6*)&s)->sin6_addr;
     }else{
          HC_LOG_ERROR("failed to convert sockaddr_storage: unknown address family");
     }

     return *this;
}

bool addr_storage::operator==(const addr_storage& addr) const{
     HC_LOG_TRACE("");

     std::string a, b;
     a = this->to_string();
     b = addr.to_string();

     if(a.compare("??")==0){ //|| b.compare("??")==0
          return false;
     }else if(a.compare(b) == 0){
          return true;
     }else{
          return false;
     }
}

bool addr_storage::operator!=(addr_storage& addr) const{
     HC_LOG_TRACE("");

     return !(*this == addr);
}

bool operator< (const addr_storage& addr1, const addr_storage& addr2){
     HC_LOG_TRACE("");

     if(addr1.m_addr.ss_family == AF_INET && addr2.m_addr.ss_family == AF_INET){
          return  ntohl(*((in_addr_t*) &addr1.m_addr.__ss_align)) < ntohl(*((in_addr_t*) &addr2.m_addr.__ss_align));
     }else if(addr1.m_addr.ss_family == AF_INET6 && addr2.m_addr.ss_family == AF_INET6){
          const uint8_t* a1 = ((in6_addr*)&addr1.m_addr.__ss_align)->__in6_u.__u6_addr8;
          const uint8_t* a2 = ((in6_addr*)&addr2.m_addr.__ss_align)->__in6_u.__u6_addr8;
# if __BYTE_ORDER == __BIG_ENDIAN
          for(int i= sizeof(struct in6_addr)/sizeof(uint8_t)-1; i >= 0; i--){
# else
#  if __BYTE_ORDER == __LITTLE_ENDIAN
          for(unsigned int i=0; i< sizeof(struct in6_addr)/sizeof(uint8_t); i++){
#  endif
# endif
               if(a1[i]> a2[i]){
                    return false;
               }else if(a1[i]<a2[i]){
                    return true;
               }
          }
          return false;
     }else{
          HC_LOG_ERROR("incompatible ip versions");
          return false;
     }
}

struct sockaddr_storage addr_storage::get_sockaddr_storage(){
     HC_LOG_TRACE("");

     return this->m_addr;
}

int addr_storage::get_addr_family() const{
     HC_LOG_TRACE("");

     return this->m_addr.ss_family;
}

std::string addr_storage::to_string() const{
     HC_LOG_TRACE("");

     char addressBuffer[INET6_ADDRSTRLEN];
     if(inet_ntop(m_addr.ss_family, (void*)&m_addr.__ss_align, addressBuffer, sizeof(addressBuffer)) != NULL){
          return std::string(addressBuffer);
     }else{
     HC_LOG_ERROR("failed to convert sockaddr_storage");
     return std::string("??");
}
}

addr_storage& addr_storage::mask(const addr_storage& s){
     HC_LOG_TRACE("");

     if(this->m_addr.ss_family == AF_INET && s.m_addr.ss_family == AF_INET){
          *((in_addr_t*) &this->m_addr.__ss_align) = *((in_addr_t*) &this->m_addr.__ss_align) & *((in_addr_t*) &s.m_addr.__ss_align);
          return *this;
     }else {
     HC_LOG_ERROR("incompatible ip versions");
}

return *this;
}

void addr_storage::test_addr_storage(){
     HC_LOG_TRACE("");
     using namespace std;
     std::string addr4 = "251.0.0.224";
     std::string addr6 = "ff02:231:abc::1";

     struct sockaddr_storage sockaddr4;
     struct sockaddr_storage sockaddr6;
     struct in_addr in_addr4;
     struct in6_addr in_addr6;
     struct in6_addr in_addr6tmp;

     addr_storage s4;
     addr_storage s6;
     addr_storage s4_tmp;
     addr_storage s6_tmp;
     addr_storage s4_1;
     addr_storage s6_1;



     cout << "-- string in addr_storage, cout stream, sockaddr_storage to string --" << endl;
     s4 = addr4;
     s6 = addr6;

     cout <<"addr4: str<" << addr4 << "> addr_storage<" << s4 << "> ==>" << (addr4.compare(s4.to_string())==0? "OK!" : "FAILED!") << endl;
     cout << "addr6: str<" << addr6 << "> addr_storage<" << s6 << "> ==>" << (addr6.compare(s6.to_string())==0? "OK!" : "FAILED!") << endl;

     cout << "-- sockaddr_storage to addr_storage --" << endl;
     sockaddr4 <<= s4;
     sockaddr6 <<= s6;
     s4_1 = sockaddr4;
     s6_1 = sockaddr6;
     cout << "addr4: str<" << addr4 << "> addr_storage<" << s4_1 << "> ==>" << (addr4.compare(s4_1.to_string())==0? "OK!" : "FAILED!") << endl;
     cout << "addr6: str<" << addr6 << "> addr_storage<" << s6_1 << "> ==>" << (addr6.compare(s6_1.to_string())==0? "OK!" : "FAILED!") << endl;

     cout << "-- equivalent addresses --" << endl;
     s4_tmp = "Hallo ich bin bob";
     s6_tmp = "ich: auch";

     cout << "s4_tmp: str<" << s4_tmp << "> == s6_tmp<" << s6_tmp << "> ==>" << ((s4_tmp != s6_tmp)? "OK!" : "FAILED!") << endl;
     cout << "s6_1: str<" << s6_1 << "> s6_1<" << s6_1 << "> ==>" << (s6_1 == s6_1? "OK!" : "FAILED!") << endl;


     cout << "-- struct in_addr and in6_addr --" << endl;
     in_addr4 <<= s4;
     in_addr6 <<= s6;

     if(!inet_pton(AF_INET6, addr6.c_str(),(void*)&in_addr6tmp.__in6_u)>0){
          cout << "Error convert " << addr6 <<" to in6_addr FAILED! " << endl;
     }

     cout << "addr_storage to struct in_addr ==>" << (in_addr4.s_addr == inet_addr(addr4.c_str())? "OK!": "FAILED!") << endl;
     cout << "addr_storage to struct in6_addr ==>" << (IN6_ARE_ADDR_EQUAL(&in_addr6,&in_addr6tmp)? "OK!": "FAILED!") << endl;
     cout << "struct in_addr to addr_storage ==>" << ((addr_storage(in_addr4).to_string().compare(addr4)==0)? "OK!": "FAILED!") <<endl;
     cout << "struct in6_addr to addr_storage ==>" << ((addr_storage(in_addr6).to_string().compare(addr6)==0)? "OK!": "FAILED!") <<endl;

     cout << "-- ipv4 mask --" << endl;
     s6_tmp = "141.22.26.0";
     s4 = "141.22.26.249";
     s6 = "255.255.254.0";
     s4_tmp = s4;
     s4_tmp.mask(s6);
     cout << s4 << " mask with " << s6 << " ==> " << s4_tmp << " ==>"  << (s4_tmp == s6_tmp? "OK!" : "FAILED!") << endl;
     s4 = "141.22.27.155";
     s6 = "255.255.254.0";
     s4_tmp = s4;
     s4_tmp.mask(s6);
     cout << s4 << " mask with " << s6 << " ==> " << s4_tmp << " ==>"  << (s4_tmp == s6_tmp? "OK!" : "FAILED!")<< endl;
     s4 = "141.22.27.142";
     s6 = "255.255.254.0";
     s4_tmp = s4;
     s4_tmp.mask(s6);
     cout << s4 << " mask with " << s6 << " ==> " << s4_tmp << " ==>"  << (s4_tmp == s6_tmp? "OK!" : "FAILED!")<< endl;

     cout << "-- less then --" << endl;
     s4 = "141.22.26.249";
     s6 = "255.255.254.0";
     cout << s4 << " is less then " << s6  << ": " << (s4<s6? "true ==>OK!" : "false ==>FAILED!") << endl;
     cout << s6 << " is less then " << s4  << ": " << (s6<s4? "true ==>FAILED!" : "false ==>OK!") << endl;
     s4 = "fe80::5e26:aff:fe23:8dc0";
     s6 = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
     cout << s4 << " is less then " << s6  << ": " << (s4<s6? "true ==>OK!" : "false ==>FAILED!") << endl;
     cout << s6 << " is less then " << s4  << ": " << (s6<s4? "true ==>FAILED!" : "false ==>OK!") << endl;
     s4 = "0:0:0:0:ffff:ffff:ffff:ffff";
     s6 = "ffff:ffff:ffff:ffff::0";
     cout << s4 << " is less then " << s6  << ": " << (s4<s6? "true ==>OK!" : "false ==>FAILED!") << endl;
     cout << s6 << " is less then " << s4  << ": " << (s6<s4? "true ==>FAILED!" : "false ==>OK!") << endl;

}


