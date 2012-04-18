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

/**
 * @addtogroup mod_proxy_instance Proxy Instance
 * @{
 */

#ifndef CHECK_SOURCE_H
#define CHECK_SOURCE_H

#include "include/utils/mc_tables.hpp"

/**
 * @brief Monitored the forwarding rules in the Linux kernel table. If a source is unused for
 * a long time it can be removed.
 */
class check_source{
private:
     int m_addr_family;

     mc_tables m_check_src_a;
     mc_tables m_check_src_b;
     mc_tables* m_current_check;
public:

     /**
      * @brief Initialize check_source.
      * @param addr_family used IP version (AF_INET or AF_INET6)
      * @return Return true on success.
      */
     bool init(int addr_family);

     /**
      * @brief Trigger the monitoring.
      * @return Return true on success.
      */
     bool check();

     /**
      * @brief Check wether an unique forwarding rule is unused since the last monitoring trigger.
      * @param vif virutal interface of the forwarding rule
      * @param src_addr source address of the forwarding rule
      * @param g_addr multicast group address of the forwarding rule
      */
     bool is_src_unused(int vif, addr_storage src_addr, addr_storage g_addr);

};

#endif // CHECK_IF_H
/** @} */
