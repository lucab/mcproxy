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
#include "include/proxy/check_source.hpp"

bool check_source::init(int addr_family){
     HC_LOG_TRACE("");

     this->m_addr_family = addr_family;
     m_check_src_a.init_tables(m_addr_family);
     m_check_src_b.init_tables(m_addr_family);
     if(!m_check_src_a.refresh_routes()) return false;
     m_current_check = &m_check_src_a;

     return true;
}

bool check_source::check(){
     HC_LOG_TRACE("");

     if(m_current_check == &m_check_src_a){
          m_current_check = &m_check_src_b;
     }else{
          m_current_check = &m_check_src_a;
     }
     if(!m_current_check->refresh_routes()) return false;

     return true;

}

bool check_source::is_src_unused(int vif, addr_storage src_addr, addr_storage g_addr){
     HC_LOG_TRACE("");

     int current_n_packets= -1;
     int old_n_packets = -1;
     mc_tables* old_mc_table= (m_current_check == &m_check_src_a)? &m_check_src_b : &m_check_src_a;

     for(unsigned int i=0; (i < m_current_check->get_routes_count()) && (current_n_packets < 0); i++){
          if(m_current_check->get_route(i).i_if == vif && m_current_check->get_route(i).group == g_addr && m_current_check->get_route(i).origin == src_addr){
               current_n_packets=  m_current_check->get_route(i).pkts;

          }
     }

     for(unsigned int i=0; (i < old_mc_table->get_routes_count()) && (old_n_packets < 0); i++){
          if(old_mc_table->get_route(i).i_if == vif && old_mc_table->get_route(i).group == g_addr && old_mc_table->get_route(i).origin == src_addr){
               old_n_packets=  old_mc_table->get_route(i).pkts;
          }
     }

     if(current_n_packets < 0){
          HC_LOG_ERROR("can't find route! if_index: " << vif << " group address: " << g_addr);
          return true;
     }

     if(old_n_packets < 0){
          if(current_n_packets == 0){
               return true;
          }else{ //greater 0
               return false;
          }
     }else{
          if(current_n_packets == old_n_packets){
               return true;
          }else{
               return false;
          }
     }

}
