#!/bin/bash

g++ -o main ./main.cpp CustomPacket.cpp Peer.cpp -pthread
sudo ./main
rm main