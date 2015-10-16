#-------------------------------------------------
#
# Project created by QtCreator 2013-10-02T15:55:22
#
#-------------------------------------------------

QT       -= core

QT       -= gui

TARGET = client
CONFIG   += console
CONFIG   -= app_bundle
DESTDIR = ../build

win32 {

    LIBS += -Lc:/OpenSSL-Win32/lib/VC/ -llibeay32MD -llibeay32MT \
    -lssleay32MD -lssleay32MT

    # DEPENDPATH += .
    INCLUDEPATH += c:/OpenSSL-Win32/include
}

unix {
    LIBS += -lssl -lpthread -lcrypto
}

INCLUDEPATH += ../common
TEMPLATE = app

HEADERS += ../common/thread.h \
    ../common/common.h

SOURCES +=  main.cpp \
    ../common/thread.cpp \
    ../common/common.cpp


