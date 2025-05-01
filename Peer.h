#ifndef PEER_H
#define PEER_H

#include "CustomPacket.h"
#include <mutex>
#include <vector>
#include <condition_variable>
#include <netinet/in.h>
#include <string>

class Peer {
public:

    std::vector<std::string> messages_received;
    bool is_connected = false, exiting = false;

    std::mutex is_connected_mutex;
    std::mutex cout_mutex;
    std::mutex adding_msg_received;
    std::mutex exiting_mutex;

    void startPeer();
    void connectToPeer(const char *remote_ip);

    void sendMessage(const std::string &msg);

    void sendFile(const std::string &file_path);
    void listenForPackets();
    void processPackets();
    void endConnection();

    std::string get_messages_received();
    bool confirm_file_received();

    void runTerminalInterface();

private:
    int sock;
    int serialise_packet_size = 0, procesed_packets = 0;
    int port=8081;
    bool requested_end_transmition = false;
    // bool client_addr_initialized = false; // Track if the client's address is initialized
    uint16_t packet_id = UINT16_MAX;
    bool connectToPeer_message_send = false;
    std::vector<uint16_t> missing_packets;

    std::string localIPAddress;

    //For dealing with error packets, i need to store for a while the packets
    // I will try to memorate a finite number of packets (1000)
    std::map<uint16_t, CustomPacket> packetsToBeSend;
    int size_of_packetsToBeSend = 1000;

    std::string folder_name = "data";

    //For seeing messages
    bool file_received = false;

    std::mutex packet_mutex;
    std::mutex packet_id_mutex;
    std::mutex packetsToBeSend_mutex;
    std::mutex checking_file_received;
    std::mutex requested_end_transmition_mutex;
    std::mutex connectToPeer_message_send_mutex;

    // Declare cout_mutex as extern

    
    std::vector<CustomPacket> packet_vector;
    std::condition_variable packet_cv;
    std::condition_variable messages_received_cv;
    std::condition_variable checking_file_received_cv;

    sockaddr_in peer_addr, client_addr;

    void sendPacket(const CustomPacket &packet);
    void receivePacket(CustomPacket &packet);
    void composePacketMessage();
    void composePacketFile();
    void sendPacketFile();

    //new debugging method
    void sendPacketTo(const CustomPacket &packet, const struct sockaddr_in &dest_addr);
    void incrementing_and_checking_packet_id(const uint16_t &idpacket);
    CustomPacket create_ack_packet();
    CustomPacket create_error_packet(const uint16_t &missing_packet_id);
    CustomPacket create_start_packet(const int &size, const bool &isFile = false);

    //For memoring the packets that will be send
    void add_packets_to_history(const std::map<uint16_t, CustomPacket> &packet_list);

    //For adding complete messages in vector
    void adding_messages_in_received_messages(const std::string &msg);

    void ensureDataFolderExists();
    std::string getLocalIPAddress() const;
    int connectToAvailablePort();
    void print_commands_options();
};

#endif // PEER_H