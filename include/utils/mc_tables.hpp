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


#ifndef MC_TABLES_HPP
#define MC_TABLES_HPP

#include "include/utils/addr_storage.hpp"

#include <netinet/in.h>
#include <map>
#include <vector>
#include <iostream>
#include <linux/mroute.h>
#include <linux/mroute6.h>
using namespace std;

#define MAX_N_LINE_LENGTH 200
#define JOINED_GROUP_PATH_V6 "/proc/net/igmp6"
#define JOINED_GROUP_PATH_V4 "/proc/net/igmp"
#define VIF_PATH_V4 "/proc/net/ip_mr_vif"
#define VIF_PATH_V6 "/proc/net/ip6_mr_vif"
#define MR_CACHE_PATH_V4 "/proc/net/ip_mr_cache"
#define MR_CACHE_PATH_V6 "/proc/net/ip6_mr_cache"
#define SNMP6_PATH "/proc/net/dev_snmp6"

typedef vector<addr_storage> MGroup_value;
typedef map<string, MGroup_value > MGroup_map;
typedef pair<string, MGroup_value > MGroup_pair;

typedef struct snmp6 SNMP6_value;
typedef map<string, SNMP6_value > SNMP6_map;
typedef pair<string, SNMP6_value > SNMP6_pair;

/**
 * @brief Represent a raw in the Linux kernel table ipX_mr_vif
 */
struct mr_vif{
     int addr_family;
     int vifi; //virutuell interface index
     string ifname;
     int bytesIn;
     int pktsIn;
     int bytesOut;
     int pktsOut;
     int flags;
     int lcl_index; //use for AF_INET
     addr_storage lcl_addr; //only for AF_INET
     addr_storage remote; //only for AF_INET
};

/**
 * @brief Represent a raw in the Linux kernel table ipX_mr_cache
 */
struct mr_cache{
     int addr_family;
     addr_storage group;
     addr_storage origin;
     int i_if;
     int pkts;
     int bytes;
     int wrong;
     vector<int> o_if;
};

/**
 * @brief Represent a raw in the Linux kernel table snmp6
 */
struct snmp6 {
     int Icmp6InGroupMembQueries;
     int Icmp6InGroupMembResponses;
     int Icmp6OutGroupMembQueries;
     int Icmp6OutGroupMembResponses;

     int Icmp6InMLDv2Reports;
     int Icmp6OutMLDv2Reports;
};

/**
 * @brief Represent the first raw in the Linux kernel table igmpX
 */
struct igmp_dev{
     int index; //inteface index
     string if_name; //interface name
     int g_count; //count joined groups on this interface
     int querier_version; //querier version (default V3)
     vector<struct igmp_group> groups;
};

/**
 * @brief Represent the second raw in the Linux kernel table igmpX
 */
struct igmp_group{
     addr_storage group; //joined group
     int users; //number of user on this pc joined this group
     bool timer_run;
     int timer; //current respons time
     bool reporter; //i am the reporter of this group only V2
};

/**
 * @brief Parse ipv4 and ipv6 kernel tables to usable data structures
 */
class mc_tables
{
private:
     int m_addr_family;
     //--filesystem access--
     MGroup_map m_mgroup_map;

     vector<struct mr_vif> m_mr_vif;
     vector<struct mr_cache> m_mr_cache;

     SNMP6_map m_snmp6_map;

     vector<struct igmp_dev> m_igmp_table;

     //--general--
     string int2str(int x);
     addr_storage hexCharAddr_To_ipFormart(string& ipAddr, int addrFamily);
     int str2int(string x);
     int hexChar_To_int(char x);

     //trim fist and last white_spaces

public:

     /**
      * @brief Remove spaces beforeand behind a string.
      * @param str string to trim
      * @param size size of the string
      */
     static void trim(char* str, unsigned int size);

     /**
      * @brief Create mc_tables.
      */
     mc_tables();

     /**
     * @brief Set the address family.
     */
     void init_tables(int addrFamily);

     //#######################
     //##-- joined groups --##
     //#######################
     /**
     * @brief Refresh all devices and their joined groups.
     * @return Return true on success.
     */
     bool refresh_joined_groups();

     /**
     * @brief Get the number of joined groups for a specificnetwork interface.
     * @param ifName name of the interface
     */
     unsigned int get_joined_groups_count(string& ifName);

     /**
     * @brief Get a multicastgroup address for a specificinterface.
     * @param ifName name of the interface
     * @param index number of the joined group for this interface
     */
     addr_storage get_joined_group(string& ifName, unsigned int index);

     /**
     * @brief Print all available devices and their joined groups.
     */
     void print_all_joined_groups();

     //###############
     //##-- vifs -- ##
     //###############
     /**
      * @brief Refresh the virtual interfaces.
      */
     bool refresh_vifs();

     /**
      * @brief Get the number of configured virtual interfaces.
      */
     unsigned int get_vifs_count();

     /**
      * @brief Get a virtual interface and there properties.
      * @param index number of the virtual interface in the Linux kernel table
      */
     const struct mr_vif& get_vif(unsigned int index);

     /**
      * @brief Print the properties of a virtual interface.
      * @param mr_vif virtual interface struct
      */
     void print_vif_info(struct mr_vif& t);

     /**
      * @brief Print all virtual interface infos
      */
     void print_all_vif_infos();

     //################
     //##-- routes --##
     //################
     /**
      * @brief Refresh the multicast forwarding routes.
      * @return Return true on success.
      */
     bool refresh_routes();

     /**
      * @brief Get the number of configured multicastforwarding routes.
      */
     unsigned int get_routes_count();

     /**
      * @brief Get a mutlciast struct mr_cache
      * @param index number of the multicast forwarding route in the Linux kernel table
      */
     const struct mr_cache& get_route(unsigned int index);

     /**
      * @brief Print a multicast forwarding route
      * @param mr_cache multicast forwarding route
      */
     void print_route_info(struct mr_cache& t);

     /**
      * @brief Print all multicast route infos
      */
     void print_all_route_infos();

     //###############
     //##-- snmp6 --##
     //###############
     /**
      * @brief Refresh the snmp6 table.
      * @return Return true on success.
      */
     bool refresh_snmp6();

     /**
      * @brief Get snmp6 infos for a specific interface.
      * @param if_name name of the interface
      * @return Return the snmp6 infos or if the interface name not found an empty struct.
      */
     struct snmp6 get_snmp6(string if_name);

     /**
      * @brief Get an empty snmp6 structure.
      */
     struct snmp6 get_snmp6_empty_struct();

     /**
      * @brief Get all available interfaces watched by snmp6.
      */
     vector<string> get_snmp6_all_interfaces();

     /**
      * @brief Print snmp6 infos for a specificinterface.
      * @param snmp6 snmp6 struture for a specificinterface
      */
     void print_snmp6_infos(const struct snmp6* s);

     /**
      * @brief Print all snmp6 infos.
      */
     void print_all_snmp6_infos();

     //####################
     //##-- igmp table --##
     //####################
     /**
      * @brief Refresh the igmp table.
      * @return Return true on success.
      */
     bool refresh_igmp_table();

     /**
      * @brief Get an empty igmp device structure.
      */
     struct igmp_dev get_igmp_table_empty_dev();

     /**
      * @brief Get igmp infos for a specific interface.
      * @param if_name interface name for the interface
      * @return Return the structure igmp_dev or on error an empty_igmp_dev structure.
      */
     struct igmp_dev get_igmp_table_dev(string if_name);

     /**
      * @brief Get the whole igmp table.
      */
     vector<struct igmp_dev> get_igmp_table_all();

     /**
      * @return Get all available interfaces seen in the igmp table.
      */
     vector<string> get_igmp_table_all_interfaces();

     /**
      * @brief Print igmp infos for a specific interface.
      * @param igmp_dev device raw of the igmp table
      */
     void print_igmp_table_dev(const struct igmp_dev* s);

     /**
      * @brief Print the whole igmp table.
      */
     void print_all_igmp_table();

     //################
     //##-- tests -- ##
     //################
     /**
     * @brief Test joined groups for an ip version (AF_INET or AF_INET6).
     */
     static void test_joined_groups(int addrFamily);

     /**
      * @brief Test virtual interfaces for an ip version (AF_INET or AF_INET6).
      */
     static void test_vifs(int addrFamily);

     /**
      * @brief Test the multicast routing cache for an ip version (AF_INET or AF_INET6).
      */
     static void test_mr_cache(int addrFamily);

     /**
      * @brief Test the snmp6 table for an ip version (AF_INET or AF_INET6).
      */
     static void test_snmp6();

     /**
      * @brief Test the igmp table.
      */
     static void test_igmp_table();

};

#endif // MC_TABLES_HPP
