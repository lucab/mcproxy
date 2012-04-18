TARGET = mcproxy

target.path = /usr/local/bin
INSTALLS += target

doc.commands = doxygen ../doxygen/Doxyfile
QMAKE_EXTRA_TARGETS += doc

CONFIG -= qt

SOURCES += src/main.cpp \
           src/hamcast_logging.cpp \
                #utils
           src/utils/mc_socket.cpp \
           src/utils/mc_tables.cpp \
           src/utils/addr_storage.cpp \
           src/utils/mroute_socket.cpp \
           src/utils/if_prop.cpp \
                #proxy
           src/proxy/proxy.cpp \
           src/proxy/sender.cpp \
           src/proxy/receiver.cpp \
           src/proxy/mld_receiver.cpp \
           src/proxy/igmp_receiver.cpp \
           src/proxy/mld_sender.cpp \
           src/proxy/igmp_sender.cpp \
           src/proxy/proxy_instance.cpp \
           src/proxy/routing.cpp \
           src/proxy/worker.cpp \
           src/proxy/timing.cpp \
           src/proxy/check_if.cpp \
           src/proxy/check_source.cpp

HEADERS += include/hamcast_logging.h \
                #utils
           include/utils/mc_socket.hpp \
           include/utils/mc_tables.hpp \
           include/utils/addr_storage.hpp \
           include/utils/mc_timers_values.hpp \
           include/utils/mroute_socket.hpp \
           include/utils/if_prop.hpp \
               #proxy
           include/proxy/proxy.hpp \
           include/proxy/sender.hpp \
           include/proxy/receiver.hpp \
           include/proxy/mld_receiver.hpp \
           include/proxy/igmp_receiver.hpp \
           include/proxy/mld_sender.hpp \
           include/proxy/igmp_sender.hpp \
           include/proxy/proxy_instance.hpp \
           include/proxy/message_queue.hpp \
           include/proxy/message_format.hpp \
           include/proxy/routing.hpp \
           include/proxy/worker.hpp \
           include/proxy/timing.hpp \
	      include/proxy/check_if.hpp \
           include/proxy/check_source.hpp

LIBS += -L/usr/lib -lboost_thread \
        -lboost_date_time \
        -lboost_system

