QMAKE_CXXFLAGS += -std=c++11 -pedantic -Wall -Wextra
TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c

include(deployment.pri)
qtcAddDeployment()

