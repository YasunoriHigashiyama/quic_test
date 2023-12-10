PROGRAM = quic_test
SRCS    = \
	main.cpp \
	common.cpp \
	log.cpp \
	application.cpp \
	udp_server.cpp \
	quic_functions.cpp \
	http2_util.cpp \
	http2_huffman.cpp \
	http3_static_headers_table.cpp \
	http3_common.cpp
ifndef CFLAGS
	CFLAGS = -std=c++23 -O0 -g -pg -W -Wall -Wcast-align -Wcast-qual -Wcomment -Wconversion -Wformat -Wlong-long -Wno-import -Wparentheses -Wpointer-arith -Wreturn-type -Wshadow -Wswitch -Wtrigraphs -Wunused -Wwrite-strings  -I quicly/include/ -I quicly/deps/picotls/include/ -I quicly/deps/picotls/
endif
ifndef LDFLAGS
	LDFLAGS = -pg -lboost_program_options -lboost_system -lssl -lcrypto -lmagic -lyaml-cpp  -L quicly/ -lquicly -L quicly/deps/picotls -lpicotls-core -lpicotls-fusion -lpicotls-openssl
endif
INCLUDES   = $(SRCS:.cpp=.hpp)
OBJS       = $(SRCS:.cpp=.o)
CC         = g++
MAKEFILE   = Makefile
RM         = rm
RMFLAGS	   = -f
TOUCH      = touch
DEPS       = .deps

.PHONY: all clean dep

all: dep $(PROGRAM)

clean:
	$(RM) $(RMFLAGS) $(OBJS) $(PROGRAM) $(DEPS) $(PROGRAM).log core core.[0-9]* gmon.out

dep: $(OBJS:.o=.cpp)
	-@ $(TOUCH) $(DEPS)
	-@ $(RM) $(DEPS)
	-@ for i in $^; do \
		cpp -std=c++2a -MM $$i | sed "s/\ [_a-zA-Z0-9][_a-zA-Z0-9]*\.cpp//g" >> $(DEPS); \
	done

$(PROGRAM): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

.cpp.o:
	$(CC) $(CFLAGS) -c $< -o $@

check-syntax:
	$(CC) -o nul $(CFLAGS) $(INCLUDES) -S ${CHK_SOURCES}

-include $(DEPS)

html:
	gtags -v
	htags -ansx

pch:
	clang++ -cc1 -fcxx-exceptions -x c++-header *.hpp -emit-pch -o .pch
