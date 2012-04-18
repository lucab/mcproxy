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
 * @addtogroup mod_receiver Receiver
 * @{
 */

#ifndef MLD_RECEIVER_HPP
#define MLD_RECEIVER_HPP

#include "include/proxy/receiver.hpp"

/**
 * @brief Cache Miss message received form the Linux Kernel identified by this ip verion.
 */
#define MLD_RECEIVER_KERNEL_MSG 0

/**
 * @brief Receive MLD messages.
 */
class mld_receiver : public receiver {
private:
     int get_ctrl_min_size();
     int get_iov_min_size();
     void analyse_packet(struct msghdr* msg, int info_size);
public:
     bool init(int addr_family, int version, mroute_socket* mrt_sock);

     mld_receiver();
};

#endif // MLD_RECEIVER_HPP
/** @} */
