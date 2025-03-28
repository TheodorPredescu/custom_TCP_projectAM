#!/bin/bash

g++ -o main ./main.cpp CustomPacket.cpp Peer.cpp
./main
rm main