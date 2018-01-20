CMAKE_MINIMUM_REQUIRED(VERSION 2.8.12)

PROJECT(client)

SET(CMAKE_INCLUDE_CURRENT_DIR ON)

IF(WIN32)
    INCLUDE_DIRECTORIES("../common" "c:/OpenSSL-Win32/include")
    LINK_DIRECTORIES("c:/OpenSSL-Win32/lib/VC/")
    LINK_LIBRARIES(libeay32MD libeay32MT ssleay32MD ssleay32MT)
ENDIF(WIN32)

IF(UNIX)
    INCLUDE_DIRECTORIES("../common")
    LINK_LIBRARIES(ssl pthread crypto)
ENDIF(UNIX)

ADD_EXECUTABLE(${PROJECT_NAME}
    "main.cpp"
    "../common/thread.h"
    "../common/common.h"
    "../common/thread.cpp"
    "../common/common.cpp")
