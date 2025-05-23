#!/bin/bash

# Function to check and install a package
check_and_install() {
    PACKAGE=$1
    if ! dpkg -s $PACKAGE >/dev/null 2>&1; then
        echo "$PACKAGE is not installed. Installing..."
        sudo apt-get install -y $PACKAGE
    else
        echo "$PACKAGE is already installed."
    fi
}

# Check and install required packages
check_and_install libglfw3
check_and_install libglfw3-dev
check_and_install libgl1-mesa-dev
check_and_install libx11-dev

# g++ -o main ./main.cpp CustomPacket.cpp Peer.cpp -lglfw -lGL -pthread
g++ -o main main.cpp Peer.cpp CustomPacket.cpp \
    imgui/imgui.cpp imgui/imgui_draw.cpp imgui/imgui_tables.cpp imgui/imgui_widgets.cpp \
    imgui/backends/imgui_impl_glfw.cpp imgui/backends/imgui_impl_opengl3.cpp \
    -Iimgui -Iimgui/backends -lglfw -lGL -pthread
# sudo ./main
XDG_RUNTIME_DIR=/tmp/$USER-runtime-dir sudo ./main
rm main