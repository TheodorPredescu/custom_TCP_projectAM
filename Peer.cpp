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

  std::mutex packet_mutex; // Mutex for thread-safe access to the packet queue
  std::queue<CustomPacket> packet_queue; // Queue to store received packets
  std::condition_variable packet_cv; // Condition variable for packet processing

  sockaddr_in peer_addr;
  u_int16_t id_packet = 0;

  void sendPacket(CustomPacket &packet);
  void receivePacket(CustomPacket &packet);
  void listenForPackets();
  void connectToPeer(const char *remote_ip);
  void processPackets();

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
  packet.serialize(buffer);
  send(sock, buffer, sizeof(buffer), 0);
  std::cout << "Packet sent to: " << sock << "\n";
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
      std::cerr << "Error: Failed to bind socket to port " << port << std::endl;
      close(sock);
      return;
    }

    listen(sock, 3);
  }

  // Start threads for receiving and processing packets
  std::thread receiver(&Peer::listenForPackets, this);
  std::thread processor(&Peer::processPackets, this);

  receiver.detach();
  processor.detach();

  // Example: Send an initial packet
  CustomPacket packet;
  packet.packet_id = 1;
  strcpy(packet.payload, "Hello from peer starter!");
  packet.length = strlen(packet.payload);
  packet.checksum = packet.calculateChecksum();

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
void Peer::receivePacket(CustomPacket &packet) {
  uint8_t buffer[sizeof(CustomPacket)];
  int valread = read(sock, buffer, sizeof(CustomPacket));

  if (valread > 0) {
    packet = CustomPacket::deserialize(buffer);
    std::cout << "Received Packet ID: " << packet.packet_id << "\n";
    std::cout << "Payload: " << packet.payload << "\n";
  } else {
    std::cerr << "Error reading packet\n";
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
    CustomPacket packet;
    receivePacket(packet);

    // Add the packet to the queue
    {
      std::lock_guard<std::mutex> lock(packet_mutex);
      packet_queue.push(packet);
    }
    packet_cv.notify_one(); // Notify the processing thread
  }
}

void Peer::processPackets() {
  while (true) {
    CustomPacket packet;

    // Wait for a packet to be available
    {
      std::unique_lock<std::mutex> lock(packet_mutex);
      packet_cv.wait(lock, [this] { return !packet_queue.empty(); });

      // Get the next packet from the queue
      packet = packet_queue.front();
      packet_queue.pop();
    }

    // Validate the packet
    if (packet.calculateChecksum() != packet.checksum) {
      std::cerr << "Packet with ID " << packet.packet_id << " is corrupted!\n";
      continue;
    }

    // Process the packet (e.g., add to a map, reconstruct a message, etc.)
    std::cout << "Processing Packet ID: " << packet.packet_id << "\n";
    std::cout << "Payload: " << packet.payload << "\n";
  }
}

int main() {
  Peer peer;
  peer.startPeer(8080); // Start the peer on port 8080

  // Simulate sending a message
  peer.sendMessage("Hello, this is a test message!");

  // Keep the main thread alive
  while (true) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  return 0;
}
