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


#ifndef ADDR_STORAGE_HPP
#define ADDR_STORAGE_HPP

#include <iostream>
#include <sys/socket.h>
#include <string>
#include <netinet/in.h>

/**
 * @brief Address family on start up
 */
#define INIT_ADDR_FAMILY -1

/**
 * @brief Wrapper for ip an IP address storage.
 */
class addr_storage
{
private:
     struct sockaddr_storage m_addr;
public:
    /**
     * @brief Create a zero addr_storage.
     */
    addr_storage();

    /**
     * @brief Create a zero address specific storage.
     */
    addr_storage(int addr_family);

    /**
     * @brief Create an addr_storage based on a clear text ip.
     */
    addr_storage(const std::string& m_addr);

    /**
     * @brief Create an addr_storage based on the struct sockaddr_storage.
     */
    addr_storage(const struct sockaddr_storage& m_addr);

    /**
     * @brief Copy constructor
     */
    addr_storage(const addr_storage& m_addr);

    /**
     * @brief Create an addr_storage based on struct in_add.
     */
    addr_storage(const struct in_addr& m_addr);

    /**
     * @brief Create an addr_storage based on struct in6_addr.
     */
    addr_storage(const struct in6_addr& m_addr);

    /**
     * @brief Create an addr_storage based on struct sockaddr.
     */
    addr_storage(const struct sockaddr& m_addr);

//-----------------------------------------------------------

    /**
     * @brief default copy operator
     */
    addr_storage& operator=(const addr_storage& s);

    /**
     * @brief copy operator struct sockaddr_storage to class addr_storage
     */
    addr_storage& operator=(const struct sockaddr_storage& s);

    /**
     * @brief copy operator string to class addr_storage
     */
    addr_storage& operator=(const std::string& s);

    /**
     * @brief copy operator struct in_addr to class addr_storage
     */
    addr_storage& operator=(const struct in_addr& s);

    /**
     * @brief copy operator struct in6_addr to class addr_storage
     */
    addr_storage& operator=(const struct in6_addr& s);

    /**
     * @brief copy operator struct sockaddr to class addr_storage
     */
    addr_storage& operator=(const struct sockaddr& s);

    /**
     * @brief compare two addresses if one of this addresses unknown the function returns false
     */
    bool operator==(const addr_storage& addr) const;

    /**
     * @brief disjunction to operator==
     */
    bool operator!=(addr_storage& addr) const;

    /**
     * @return struct sockaddr_storage
     */
    struct sockaddr_storage get_sockaddr_storage();

    /**
     * @return current address family AF_INET or AF_INET6 or INIT_ADDR_FAMILY
     */
    int get_addr_family() const;

    /**
     * @return current address as string or "??" for unknown address
     */
    std::string to_string() const;

    /**
     * @brief mask an addr with a netmask
     */
    addr_storage& mask(const addr_storage& s);

    /**
     * @brief simple test output
     */
    static void test_addr_storage();

    /**
     * @brief lower then operator (only for IPv4 implemented)
     */
    friend bool operator< (const addr_storage& addr1, const addr_storage& addr2);

    /**
     * @brief cout output operator
     */
    friend std::ostream& operator <<(std::ostream& s, const addr_storage a);

    /**
     * @brief copy operator "<<=" class addr_storage& to struct sockaddr_storage
     */
    friend struct sockaddr_storage& operator<<=(struct sockaddr_storage& l,const addr_storage& r);

    /**
     * @brief copy operator "<<=" class addr_storage& to struct in_addr
     */
    friend struct in_addr& operator<<=(struct in_addr& l,const addr_storage& r);

    /**
     * @brief copy operator "<<=" class addr_storage& to struct in6_addr
     */
    friend struct in6_addr& operator<<=(struct in6_addr& l,const addr_storage& r);
};



#endif // ADDR_STORAGE_HPP

