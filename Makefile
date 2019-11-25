DEFINES = --std=c++11 -pthread -Werror -DVERSION="\"1.0.1\"" -Wall -fPIC -O3 -DRELEASE=1

ifeq '$(findstring ;,$(PATH))' ';'
    detected_OS := Windows
else
    detected_OS := $(shell uname 2>/dev/null || echo Unknown)
    detected_OS := $(patsubst CYGWIN%,Cygwin,$(detected_OS))
    detected_OS := $(patsubst MSYS%,MSYS,$(detected_OS))
    detected_OS := $(patsubst MINGW%,MSYS,$(detected_OS))
endif

ifeq ($(detected_OS),Darwin)
	LIB_EXT = dylib
	INSTALL_INC_ROOT = /usr/local/include/pe
	INSTALL_LIB_ROOT = /usr/local/lib
	CC = clang++
	EX_DEFINES = -I/usr/local/opt/openssl/include/
	EX_FLAGS = -L/usr/local/opt/openssl/lib
else
	LIB_EXT = so
	INSTALL_INC_ROOT = /usr/include/pe
	INSTALL_LIB_ROOT = /usr/lib64
	CC = g++
	EX_DEFINES = 
	EX_FLAGS =
endif

PECO_NT_DEFINES = $(EX_DEFINES) -I$(INSTALL_INC_ROOT)/utils -I$(INSTALL_INC_ROOT)/cotask -I$(INSTALL_INC_ROOT)/conet -I./
PECO_NT_CFLAGS = $(EX_FLAGS) -lcotask -lssl -lresolv -lpeutils -lconet

PECO_NT_CGW_CPP_FILES = ./cgw/cgw.cpp
PECO_NT_CGW_OBJ_FILES = $(PECO_NT_CGW_CPP_FILES:.cpp=.o)
PECO_NT_RSMS_CPP_FILES = ./rsms/rsms.cpp ./rsms/rsms-protocol.cpp ./rsms/rsms-client.cpp ./rsms/rsms-server.cpp ./rsms/rsms-manager.cpp ./rsms/rsms-jsonstorage.cpp ./rsms/rsms-redisstorage.cpp
PECO_NT_RSMS_OBJ_FILES = $(PECO_NT_RSMS_CPP_FILES:.cpp=.o)
PECO_NT_UPSTREAM_CPP_FILES = ./upstream/upstream.cpp
PECO_NT_UPSTREAM_OBJ_FILES = $(PECO_NT_UPSTREAM_CPP_FILES:.cpp=.o)

all : 
	@mkdir -p bin
	$(MAKE) cgw 
	$(MAKE) rsms 
	$(MAKE) upstream

%.o : %.cpp
	$(CC) $(DEFINES) $(PECO_NT_DEFINES) -c $< -o $@

cgw : $(PECO_NT_CGW_OBJ_FILES)
	$(CC) -o bin/cgw $^ $(PECO_NT_CFLAGS)

rsms : $(PECO_NT_RSMS_OBJ_FILES)
	$(CC) -o bin/rsms $^ $(PECO_NT_CFLAGS)

upstream : $(PECO_NT_UPSTREAM_OBJ_FILES)
	$(CC) -o bin/upstream $^ $(PECO_NT_CFLAGS)

install : 
	@mkdir -p /usr/local/var/rsms
	@rm -rf /usr/local/var/rsms/*
	@cp -vrf ./rsms/web/* /usr/local/var/rsms/
	@cp -vrf ./bin/* /usr/local/bin/

clean :
	@rm -vrf */*.o
	@rm -vrf bin/cgw
	@rm -vrf bin/rsms
	@rm -vrf bin/upstream
