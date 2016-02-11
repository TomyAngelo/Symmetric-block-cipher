QMAKE_CFLAGS += -std=c99 -pedantic -Wall -Wextra
TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c \
    aes_xts/aescrypt.c \
    aes_xts/aeskey.c \
    aes_xts/aestab.c \
    aes_xts/xts.c

LIBS += -LC:/OpenSSL-Win32/lib -llibeay32
INCLUDEPATH += C:/OpenSSL-Win32/include

#INCLUDEPATH += C:/Users/TomyAngelo/Desktop/aes_xts

include(deployment.pri)
qtcAddDeployment()

