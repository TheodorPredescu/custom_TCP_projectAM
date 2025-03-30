#ifndef PEER_H
#define PEER_H

#include "CustomPacket.h"
#include <mutex>
#include <vector>
#include <condition_variable>
#include <netinet/in.h>
#include <string>

// Declare cout_mutex as extern
extern std::mutex cout_mutex;

class Peer {
public:
    void startPeer(int port, const char *remote_ip = nullptr);

    void sendMessage(const std::string &msg);

    void sendFile();
    void listenForPackets();
    void processPackets();

private:
    int sock;

    uint16_t packet_id = 0;

    std::mutex packet_mutex;
    std::vector<CustomPacket> packet_vector;
    std::condition_variable packet_cv;

    sockaddr_in peer_addr, client_addr;
    bool client_addr_initialized = false; // Track if the client's address is initialized


    bool is_connected = false;

    void sendPacket(const CustomPacket &packet);
    void receivePacket(CustomPacket &packet);
    void connectToPeer(const char *remote_ip);
    void composePacketMessage();
    void composePacketFile();
    void sendPacketFile();

    //new debugging method
    void sendPacketTo(const CustomPacket &packet, const struct sockaddr_in &dest_addr);
};

#endif // PEER_H