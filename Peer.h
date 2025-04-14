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

    void sendFile(const std::string &file_path);
    void listenForPackets();
    void processPackets();
    void endConnection();

private:
    int sock;
    int serialise_packet_size = 0, procesed_packets = 0;
    bool is_connected = false;
    // bool client_addr_initialized = false; // Track if the client's address is initialized
    uint16_t packet_id = UINT16_MAX;

    //For dealing with error packets, i need to store for a while the packets
    // I will try to memorate a finite number of packets (1000)
    std::map<uint16_t, CustomPacket> packetsToBeSend;
    int size_of_packetsToBeSend = 1000;

    std::mutex packet_mutex;
    std::mutex packet_id_mutex;
    std::mutex packetsToBeSend_mutex;
    
    std::vector<CustomPacket> packet_vector;
    std::condition_variable packet_cv;

    sockaddr_in peer_addr, client_addr;

    void sendPacket(const CustomPacket &packet);
    void receivePacket(CustomPacket &packet);
    void connectToPeer(const char *remote_ip);
    void composePacketMessage();
    void composePacketFile();
    void sendPacketFile();

    //new debugging method
    void sendPacketTo(const CustomPacket &packet, const struct sockaddr_in &dest_addr);
    void incrementing_and_checking_packet_id(const uint16_t &idpacket);
    CustomPacket create_ack_packet();
    CustomPacket create_error_packet(const uint16_t &missing_packet_id) const;

    //For memoring the packets that will be send
    void add_packets_to_history(const std::map<uint16_t, CustomPacket> &packet_list);
};

#endif // PEER_H