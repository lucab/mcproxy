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


#ifndef IF_PROP_NEW_HPP
#define IF_PROP_NEW_HPP

#include <list>
#include <map>
#include <ifaddrs.h>
using namespace std;

typedef pair<struct ifaddrs* , list<struct ifaddrs*> > ipv4_6_pair;

//map<if_name, <ipv4 struct, ipv6 struct list> >
typedef map<string, ipv4_6_pair > if_prop_map;
typedef pair<string, ipv4_6_pair >if_prop_pair;

/**
 * @brief Prepare and organized the interface properties to a map data structure.
 */
class if_prop{
private:
     if_prop_map m_if_map;
     struct ifaddrs* m_if_addrs;
public:
    /**
     * @brief Create the class if_prop.
     */
    if_prop();

    /**
     * @brief Return the whole data structure.
     */
    if_prop_map* get_if_props();

    /**
     * @brief Refresh all information of all interfaces.
     * @return Return true on success.
     */
    bool refresh_network_interfaces();

    /**
     * @brief Get the ipv4 interface properties for a specific interface name.
     */
    struct ifaddrs* get_ip4_if(const string &if_name);

    /**
     * @brief Get the ipv6 interface properties for a specific interface name.
     */
    list<struct ifaddrs*>* get_ip6_if(const string &if_name);

    /**
     * @brief Print all available network interface information.
     */
    void print_if_info();

    /**
     * @brief Print interface information for a specific interface.
     * @param if_p interface properties for a specific inerface.
     */
    void print_if_addr(const struct ifaddrs* if_p);

    /**
     * @brief Release all allocated resources.
     */
    ~if_prop();

    /**
     * @brief Check for a valid data structure.
     */
    bool is_getaddrs_valid() {
         return m_if_addrs > 0;
    }

    /**
     * @brief Test the class if_prop.
     */
    static void test_if_prop();
};

#endif // IF_PROP_NEW_HPP
