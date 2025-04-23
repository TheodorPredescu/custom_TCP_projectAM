#!/bin/bash

# Check if libglfw3-dev is installed
if ! dpkg -s libglfw3-dev >/dev/null 2>&1; then
    echo "libglfw3-dev is not installed. Installing..."
    sudo apt-get install -y libglfw3-dev
else
    echo "libglfw3-dev is already installed."
fi

# Check if libgl1-mesa-dev is installed
if ! dpkg -s libgl1-mesa-dev >/dev/null 2>&1; then
    echo "libgl1-mesa-dev is not installed. Installing..."
    sudo apt-get install -y libgl1-mesa-dev
else
    echo "libgl1-mesa-dev is already installed."
fi

# Check if XDG_RUNTIME_DIR is set
if [ -z "$XDG_RUNTIME_DIR" ]; then
    echo "XDG_RUNTIME_DIR is not set. Setting it to /tmp/$USER-runtime-dir..."
    export XDG_RUNTIME_DIR=/tmp/$USER-runtime-dir
    mkdir -p $XDG_RUNTIME_DIR
    chmod 700 $XDG_RUNTIME_DIR
else
    echo "XDG_RUNTIME_DIR is already set to $XDG_RUNTIME_DIR."
fi

# g++ -o main ./main.cpp CustomPacket.cpp Peer.cpp -lglfw -lGL -pthread
g++ -o main main.cpp Peer.cpp CustomPacket.cpp \
    imgui/imgui.cpp imgui/imgui_draw.cpp imgui/imgui_tables.cpp imgui/imgui_widgets.cpp \
    imgui/backends/imgui_impl_glfw.cpp imgui/backends/imgui_impl_opengl3.cpp \
    -Iimgui -Iimgui/backends -lglfw -lGL -pthread
# sudo ./main
XDG_RUNTIME_DIR=/tmp/$USER-runtime-dir ./main
rm main