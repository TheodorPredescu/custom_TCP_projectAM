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
    void endConnection();

private:
    int sock;

    uint16_t packet_id = UINT16_MAX;

    std::mutex packet_mutex;
    std::mutex packet_id_mutex;
    std::vector<CustomPacket> packet_vector;
    std::condition_variable packet_cv;

    sockaddr_in peer_addr, client_addr;
    bool client_addr_initialized = false; // Track if the client's address is initialized

    int serialise_packet_size = 0, procesed_packets = 0;


    bool is_connected = false;

    void sendPacket(const CustomPacket &packet);
    void receivePacket(CustomPacket &packet);
    void connectToPeer(const char *remote_ip);
    void composePacketMessage();
    void composePacketFile();
    void sendPacketFile();

    //new debugging method
    void sendPacketTo(const CustomPacket &packet, const struct sockaddr_in &dest_addr);
    void incrementing_and_checking_packet_id(const uint16_t &idpacket);
};

#endif // PEER_H