# Builds credential_manager

# Output executable name
OUTPUT_EXE_NAME=credential_manager

# Includes
INCLUDES=-Iinclude -Ithird_party/rapidjson/include/ -Ithird_party/openssl/include -Ithird_party/curl/include

# Source Directory
SOURCE_DIR=src

# Object Files (source .c extension) 
OBJECT_FILES_C= \
	${OBJECT_DIR}/base64.o

# Object Files (source .cc extension) 
OBJECT_FILES_CC=

# Object Files (source .cpp extension)
OBJECT_FILES_CXX= \
	${OBJECT_DIR}/asset_manager.o \
	${OBJECT_DIR}/apm_asset_processor.o \
	${OBJECT_DIR}/app_utils.o \
	${OBJECT_DIR}/async_exec_script.o \
	${OBJECT_DIR}/account.o \
	${OBJECT_DIR}/event_manager.o \
	${OBJECT_DIR}/ssl_wrapper.o \
	${OBJECT_DIR}/timehelper.o \
	${OBJECT_DIR}/opensslhelper.o \
	${OBJECT_DIR}/configuration.o \
	${OBJECT_DIR}/log.o \
	${OBJECT_DIR}/dacryptor.o \
	${OBJECT_DIR}/deviceauthority.o \
	${OBJECT_DIR}/dahttpclient.o \
	${OBJECT_DIR}/bytestring.o \
	${OBJECT_DIR}/utils.o \
	${OBJECT_DIR}/jsonparse.o \
	${OBJECT_DIR}/jsonpath.o \
	${OBJECT_DIR}/policy.o \
	${OBJECT_DIR}/policystore.o \
	${OBJECT_DIR}/cache.o \
	${OBJECT_DIR}/da.o \
	${OBJECT_DIR}/message_factory.o \
	${OBJECT_DIR}/http_worker_loop.o \
	${OBJECT_DIR}/http_asset_messenger.o \
	${OBJECT_DIR}/script_asset_processor.o \
	${OBJECT_DIR}/script_utils.o \
	${OBJECT_DIR}/certificate_data_asset_processor.o \
	${OBJECT_DIR}/certificate_asset_processor.o \
	${OBJECT_DIR}/group_asset_processor.o \
	${OBJECT_DIR}/tpm_wrapper.o \
	${OBJECT_DIR}/main.o

# Environment
MKDIR=mkdir
RANLIB=${CROSS_COMPILE}ranlib
CC=${CROSS_COMPILE}gcc
CCC=${CROSS_COMPILE}g++
CXX=${CROSS_COMPILE}g++
AS=${CROSS_COMPILE}as
AR=${CROSS_COMPILE}ar

# Macros
CND_PLATFORM=GNU-Linux-x86
CND_DLIB_EXT=so
CND_DISTDIR=dist
CND_BUILDDIR=build

# Defines
DEFINES=-DDISABLE_MQTT -DDISABLE_TPM

# Libraries
LIBRARIES=-lssl -lcrypto -lcurl -lpthread -ldl
LIBRARY_PATH=-L${DIST_DIR} -Lthird_party/openssl/lib -Ithird_party/curl/lib -L${DEVKIT}/usr/lib -L/usr/local/lib 

# Object Directory
OBJECT_DIR=${CND_BUILDDIR}/${OUTPUT_EXE_NAME}/${CND_CONF}/${CND_PLATFORM}

# C Compiler Flags
CFLAGS=${CROSS_CFLAGS} -fPIC

# CC Compiler Flags
CCFLAGS=${CROSS_CXXFLAGS} -fPIC
CXXFLAGS=${CROSS_CXXFLAGS} -fPIC

# Linker flags
LDFLAGS=${CROSS_LDFLAGS} -Wl,-Map,${DIST_DIR}/$(OUTPUT_EXE_NAME).map

# Set debug build if not defined
BUILD_TARGET ?= debug

# Configure build for specific target
ifeq ($(BUILD_TARGET),debug)
	CFLAGS += -g
	CCFLAGS += -g
	CXXFLAGS += -g 
	CND_CONF := Debug
else
	CFLAGS += -O2 -ffunction-sections -fdata-sections -flto
	CCFLAGS += -O2 -ffunction-sections -fdata-sections -flto
	CXXFLAGS += -O2 -ffunction-sections -fdata-sections -flto
	CND_CONF := Release
endif

# Output destination directory
DIST_DIR=${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}

.PHONY: all
all: ${DIST_DIR}/${OUTPUT_EXE_NAME}

clean:
	${RM} -r ${CND_BUILDDIR}/${OUTPUT_EXE_NAME}/${CND_CONF}
	${RM} ${DIST_DIR}/${OUTPUT_EXE_NAME}

${DIST_DIR}/${OUTPUT_EXE_NAME}: ${OBJECT_FILES_C} ${OBJECT_FILES_CC} ${OBJECT_FILES_CXX}
	${MKDIR} -p ${DIST_DIR}
	${CROSS_COMPILE}g++ -o ${DIST_DIR}/${OUTPUT_EXE_NAME} ${OBJECT_FILES_C} ${OBJECT_FILES_CC} ${OBJECT_FILES_CXX} ${LIBRARY_PATH} ${LIBRARIES} ${LDFLAGS} -o $@

${OBJECT_FILES_C}: ${OBJECT_DIR}/%.o: ${SOURCE_DIR}/%.c
	${MKDIR} -p ${OBJECT_DIR}
	${RM} $@.d
	${CROSS_COMPILE}$(COMPILE.c) ${CFLAGS} ${DEFINES} ${INCLUDES} ${LIBRARY_PATH} -MMD -MP -MF $@.d -o $@ $<

${OBJECT_FILES_CC}: ${OBJECT_DIR}/%.o: ${SOURCE_DIR}/%.cc
	${MKDIR} -p ${OBJECT_DIR}
	${RM} $@.d
	${CROSS_COMPILE}$(COMPILE.cc) ${CCFLAGS} ${DEFINES} ${INCLUDES} ${LIBRARY_PATH} -MMD -MP -MF $@.d -o $@ $<

${OBJECT_FILES_CXX}: ${OBJECT_DIR}/%.o: ${SOURCE_DIR}/%.cpp
	${MKDIR} -p ${OBJECT_DIR}
	${RM} $@.d
	${CROSS_COMPILE}$(COMPILE.cpp) ${CXXFLAGS} ${DEFINES} ${INCLUDES} ${LIBRARY_PATH} -MMD -MP -MF $@.d -o $@ $<
