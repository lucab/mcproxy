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
 * @defgroup mod_routing Routing
 * @brief The module Routing set/delete virtual interfaces and multicast forwarding rules.
 * @{
 */

#ifndef ROUTING_HPP
#define ROUTING_HPP

#include "include/utils/mroute_socket.hpp"
#include "include/utils/if_prop.hpp"
#include "include/proxy/message_queue.hpp"
#include "include/proxy/message_format.hpp"
#include "include/proxy/worker.hpp"

#include <map>
#include <list>

/**
 * @brief Maximum size of the job queue.
 */
#define ROUTING_MSG_QUEUE_SIZE 1000

/**
 * @brief Set and delete virtual interfaces and forwarding rules in the Linux kernel.
 */
class routing: public worker{
private:
     int m_addr_family; //AF_INET or AF_INET6
     int m_version; //for AF_INET (1,2,3) to use IGMPv1/2/3, for AF_INET6 (1,2) to use MLDv1/2

     mroute_socket* m_mrt_sock;
     if_prop m_if_prop; //return interface properties

     void worker_thread();

     //init
     bool init_if_prop();

     //routing
     /**
      * @brief return a free vif number, if no number free -1
      */
     bool add_vif(routing_msg* msg);
     bool del_vif(routing_msg* msg);
     bool add_route(routing_msg* msg);
     bool del_route(routing_msg* msg);

     //GOF singleton
     routing();
     routing(const routing&);
     routing& operator=(const routing&);
     ~routing();
public:

     /**
      * @brief Get an instance of the Routing module (GOF singleton).
      */
     static routing* getInstance();

     /**
      * @brief initialize the Routing module.
      * @param addr_family AF_INET or AF_INET6
      * @param version used group membership version
      * @return Return true on success.
      */
     bool init(int addr_family, int version, mroute_socket* mrt_sock);

};

#endif // ROUTING_HPP
/** @} */
