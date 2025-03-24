TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -lnet

SOURCES += \
	arphdr.cpp \
	ethhdr.cpp \
	ip.cpp \
	mac.cpp \
	main.cpp

HEADERS += \
	arphdr.h \
	ethhdr.h \
	ip.h \
	mac.h

DEFINES += _BSD_SOURCE
DEFINES += _DEFAULT_SOURCE

INCLUDEPATH += /usr/include/netinet
INCLUDEPATH += /usr/include/net
