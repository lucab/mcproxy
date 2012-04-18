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
#include <fstream>
#include <boost/thread.hpp>
#include <boost/date_time.hpp>

#include <boost/thread/pthread/shared_mutex.hpp>
#include <boost/thread/pthread/mutex.hpp>


namespace
{
	hc_log_fun_t m_log_fun = 0;
	boost::shared_mutex m_log_fun_mtx;

	boost::mutex m_next_id_mtx;
	boost::uint32_t m_next_id = 0;

	boost::uint32_t next_session_id()
	{
		boost::mutex::scoped_lock lock(m_next_id_mtx);
		return m_next_id++;
	}

	class logger
	{

		bool m_enabled;
		boost::uint32_t m_id;
		std::fstream m_stream;

	 public:

		logger(bool enabled = true)
			: m_enabled(enabled), m_id(next_session_id())
		{
			std::ostringstream oss;
			oss << "thread" << m_id << ".log";
			std::string filename = oss.str();
			m_stream.open(filename.c_str(), std::fstream::out);
		}

		inline void enable() { m_enabled = true; }

		inline void disable() { m_enabled = false; }

		void log(int lvl, const char* fun, const char* what)
		{
			using boost::get_system_time;
			using boost::posix_time::to_iso_extended_string;
			std::string time_stamp = to_iso_extended_string(get_system_time());
			std::ostringstream os;
			os.width(28);
			os << std::left << time_stamp;
			os.width(7);
			os << std::left;
			switch (lvl)
			{
			 case HC_LOG_TRACE_LVL: os << "TRACE"; break;
			 case HC_LOG_DEBUG_LVL: os << "DEBUG"; break;
			 case HC_LOG_INFO_LVL:  os << "INFO"; break;
			 case HC_LOG_WARN_LVL:  os << "WARN"; break;
			 case HC_LOG_ERROR_LVL: os << "ERROR"; break;
			 case HC_LOG_FATAL_LVL: os << "FATAL"; break;
			 default: break;
			}
			os.width(80);
			os << std::left << fun;
			os.width(0);
			os << what;
			os << "\n";
			std::string oss = os.str();
			m_stream << oss;
			m_stream.flush();
		}

		~logger()
		{
			m_stream.flush();
			m_stream.close();
		}

	};

	boost::thread_specific_ptr<logger> m_logger;

	logger& thread_logger()
	{
		if (!(m_logger.get())) m_logger.reset(new logger);
		return *(m_logger.get());
	}

        //hc_log_fun_t m_logger_fun = 0;

	void log_all_fun(int lvl, const char *fun_name, const char* line)
	{
		thread_logger().log(lvl, fun_name, line);
	}

	void log_debug_fun(int lvl, const char* fun_name, const char* line)
	{
		if (lvl >= HC_LOG_DEBUG_LVL) log_all_fun(lvl, fun_name, line);
	}

	void log_info_fun(int lvl, const char* fun_name, const char* line)
	{
		if (lvl >= HC_LOG_INFO_LVL) log_all_fun(lvl, fun_name, line);
	}

	void log_warn_fun(int lvl, const char* fun_name, const char* line)
	{
		if (lvl >= HC_LOG_INFO_LVL) log_all_fun(lvl, fun_name, line);
	}

	void log_error_fun(int lvl, const char* fun_name, const char* line)
	{
		if (lvl >= HC_LOG_ERROR_LVL) log_all_fun(lvl, fun_name, line);
	}

	void log_fatal_fun(int lvl, const char* fun_name, const char* line)
	{
		if (lvl >= HC_LOG_FATAL_LVL) log_all_fun(lvl, fun_name, line);
	}
}

hc_log_fun_t hc_get_log_fun()
{
	boost::shared_lock<boost::shared_mutex> guard(m_log_fun_mtx);
	return m_log_fun;
}

void hc_set_log_fun(hc_log_fun_t function_ptr)
{
	boost::lock_guard<boost::shared_mutex> guard(m_log_fun_mtx);
	m_log_fun = function_ptr;
}

void hc_log(int loglvl, const char* func_name, const char *msg)
{
	boost::shared_lock<boost::shared_mutex> guard(m_log_fun_mtx);
	if (m_log_fun) m_log_fun(loglvl, func_name, msg);
}

void hc_set_default_log_fun(int log_lvl)
{
	switch (log_lvl)
	{
	 case HC_LOG_DEBUG_LVL: hc_set_log_fun(log_debug_fun); break;
	 case HC_LOG_INFO_LVL:  hc_set_log_fun(log_info_fun);  break;
	 case HC_LOG_WARN_LVL:  hc_set_log_fun(log_warn_fun);  break;
	 case HC_LOG_ERROR_LVL: hc_set_log_fun(log_error_fun); break;
	 case HC_LOG_FATAL_LVL: hc_set_log_fun(log_fatal_fun); break;
	 default: hc_set_log_fun(log_all_fun);
	}
}
