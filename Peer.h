#ifndef PEER_H
#define PEER_H

#include "CustomPacket.h"
#include <mutex>
#include <queue>
#include <condition_variable>
#include <netinet/in.h>
#include <string>

class Peer {
public:
    void startPeer(int port, const char *remote_ip = nullptr);

    void sendMessage(const std::string &msg);

    void sendFile();
    void listenForPackets();
    void processPackets();

private:
    int sock;

    uint16_t packet_id = UINT16_MAX;

    std::mutex packet_mutex;
    std::queue<CustomPacket> packet_queue;
    std::condition_variable packet_cv;

    sockaddr_in peer_addr;
    uint16_t id_packet = 0;

    void sendPacket(const CustomPacket &packet);
    void receivePacket(CustomPacket &packet);
    void connectToPeer(const char *remote_ip);
    void composePacketMessage();
    void composePacketFile();
    void sendPacketFile();
};

#endif // PEER_H