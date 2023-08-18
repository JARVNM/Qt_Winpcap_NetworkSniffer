#-------------------------------------------------
#
# Project created by QtCreator 2023-06-02T23:53:39
#
#-------------------------------------------------

QT       += core gui
QT       += network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = NetworkSniffer
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
        main.cpp \
        mainwindow.cpp \
    flatui.cpp \
    recourse.cpp \
    listenthread.cpp \
    packettools.cpp

HEADERS += \
        mainwindow.h \
    flatui.h \
    protocol.h \
    recourse.h \
    listenthread.h \
    packettools.h

FORMS += \
        mainwindow.ui

LIBS        += D:/QtProject/NetworkSniffer/NetworkSniffer/Packet.lib
LIBS        += D:/QtProject/NetworkSniffer/NetworkSniffer/wpcap.lib
LIBS        += -lws2_32

RESOURCES += \
    icon.qrc
