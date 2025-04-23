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


# g++ -o main ./main.cpp CustomPacket.cpp Peer.cpp -lglfw -lGL -pthread
g++ -o main main.cpp Peer.cpp CustomPacket.cpp \
    imgui/imgui.cpp imgui/imgui_draw.cpp imgui/imgui_tables.cpp imgui/imgui_widgets.cpp \
    imgui/backends/imgui_impl_glfw.cpp imgui/backends/imgui_impl_opengl3.cpp \
    -Iimgui -Iimgui/backends -lglfw -lGL -pthread
sudo ./main
rm main