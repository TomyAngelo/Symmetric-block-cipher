QMAKE_CFLAGS += -std=c99 -pedantic -Wall -Wextra
TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c

LIBS += -LC:/OpenSSL-Win32/lib -llibeay32
INCLUDEPATH += C:/OpenSSL-Win32/include

include(deployment.pri)
qtcAddDeployment()

