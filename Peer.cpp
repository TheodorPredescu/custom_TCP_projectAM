#include "CustomPacket.h"
#include <arpa/inet.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

// I need to add the logic to send a string, receive a string and print it

class Peer {
public:
  void startPeer(int port, const char *remote_ip = nullptr);
  // TO DO
  void sendMessage(const std::string msg);
  void sendFile();

private:
  int sock;
  sockaddr_in peer_addr;
  u_int16_t id_packet = 0;
  void sendPacket(CustomPacket &packet);
  void receivePacket();
  void listenForPackets();
  void connectToPeer(const char *remote_ip);

  // for later
  void composePacketMessage();
  void sendPacketMessage();

  // for much later
  void composePacketFile();
  void sendPacketFile();
};

// gets a package and sends it to the socket sock
// working to make it decent with bigger package
void Peer::sendPacket(CustomPacket &packet) {

  uint8_t buffer[sizeof(CustomPacket)];

  // // The packet_id and checksum will be added here; cannot fit verry well in
  // the
  // // CustomPacket struct
  // if (id_packet >= UINT16_MAX - 1) {
  //   std::cerr << "Warning: Packet ID overflow. Resetting...\n";
  //   id_packet = 0;
  // }
  //
  // packet.packet_id = id_packet;
  // packet.checksum = packet.calculateChecksum(packet);

  packet.serialize(buffer);
  send(sock, buffer, sizeof(buffer), 0);
  std::cout << "Packet sended to: " << sock;
}

// TODO check everithing
void Peer::startPeer(int port, const char *remote_ip) {

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    std::cerr << "Error creating socket!\n";
    return;
  }

  peer_addr.sin_family = AF_INET;
  peer_addr.sin_port = htons(port);

  if (remote_ip) {
    if (inet_pton(AF_INET, remote_ip, &peer_addr.sin_addr) <= 0) {
      std::cerr << "Invalid address/Address not supported: " << remote_ip
                << std::endl;
      return;
    }

    connectToPeer(remote_ip);

  } else {
    peer_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) < 0) {

      std::cerr << "Error: Failer to bind socket to port" << port << std::endl;
      close(sock);
      return;
    }

    listen(sock, 3);
  }

  std::thread receiver(&Peer::listenForPackets, this);
  receiver.detach();

  CustomPacket packet;
  packet.packet_id = 1;
  strcpy(packet.payload, "Hello from peer starter!");
  packet.length = strlen(packet.payload);
  packet.checksum = packet.calculateChecksum(packet);

  sendPacket(packet);
}

// We need to receive the packet, check if it has the serialize flag on and add
// it to a vector;
// If the waiting accedes a certain duration, we send it to composedMessage();
// I need to think of a way to patch the wrong transimions (meaning late
// messages) -> most likely i keep the vector here till a "finished with
// success" message !! OOOOR I  SEND FIRST A PACKET THAT TELLS ME THE NUMBER OF
// PACKAGES THAT WILL BE SEND AND I JUST CHECK IF THAT NUMBER OF PACKAGES ARE
// MET
void Peer::receivePacket() {
  u_int8_t buffer[sizeof(CustomPacket)];
  int valread = read(sock, buffer, sizeof(CustomPacket));

  if (valread > 0) {

    CustomPacket packet = CustomPacket::deserialize(buffer);
    std::cout << "Received Packet ID: " << packet.packet_id << "\n";
    std::cout << "Payload: " << packet.payload << "\n";

  } else {
    std::cout << "Error reading packet\n";
  }
}

// TODO check everithing
void Peer::listenForPackets() {
  if (peer_addr.sin_addr.s_addr == INADDR_ANY) {
    int new_socket;
    socklen_t addrlen = sizeof(peer_addr);
    new_socket = accept(sock, (struct sockaddr *)&peer_addr, &addrlen);
    if (new_socket < 0) {
      perror("Accept failed");
      exit(EXIT_FAILURE);
    }

    sock = new_socket;
  }

  while (true) {
    receivePacket();
  }
}
