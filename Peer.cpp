#include "CustomPacket.h"
#include <arpa/inet.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <map>
#include <mutex>
#include <queue>
#include <chrono>
#include <condition_variable>

#include "Peer.h"

// I need to add first the ipaddress of the user (sockaddr_in) and initialize it in startPeer funtion;
// it will then remain in the Peer class (it is a private variable)
// gets a package and sends it to the socket sock
void Peer::sendPacket(const CustomPacket &packet) { 
  // Debug: Print packet details
  std::cout << "Sending Packet ID: " << packet.packet_id << "\n";
  std::cout << "Flags: " << static_cast<int>(packet.flags) << "\n";
  std::cout << "Length: " << packet.length << "\n";
  std::cout << "Payload: " << packet.payload << "\n";
  std::cout << "Checksum: " << packet.checksum << "\n";
  packet.printFlags();



  // Debug: Print the destination address
  char dest_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(client_addr.sin_addr), dest_ip, INET_ADDRSTRLEN);
  std::cout << "Sending packet to " << dest_ip << ":" << ntohs(client_addr.sin_port) << "\n";


  // sendPacketTo(packet, client_addr);
  // return;
  
  // Allocate buffer for IP header + payload
  uint8_t buffer[sizeof(struct iphdr) + sizeof(CustomPacket)];

  // Construct the IP header
  struct iphdr *ip_header = (struct iphdr *)buffer;
  ip_header->version = 4; // IPv4
  ip_header->ihl = 5; // Header length (5 * 4 = 20 bytes)
  ip_header->tos = 0; // Type of service
  ip_header->tot_len = htons(sizeof(buffer)); // Total length (header + payload)
  ip_header->id = htons(54321); // Identification
  ip_header->frag_off = 0; // No fragmentation
  ip_header->ttl = 64; // Time to live
  ip_header->protocol = IPPROTO_RAW; // Protocol (raw socket)
  ip_header->check = 0; // Checksum (set to 0 for now, kernel may calculate it)
  ip_header->saddr = inet_addr("127.0.0.1"); // Source IP address
  ip_header->daddr = client_addr.sin_addr.s_addr; // Destination IP address

  // Copy the payload (CustomPacket) into the buffer after the IP header
  packet.serialize(buffer + sizeof(struct iphdr));


  // // Check if peer_addr is properly initialized
  // if (peer_addr.sin_family != AF_INET || peer_addr.sin_port == 0 || peer_addr.sin_addr.s_addr == 0) {
  //   std::cerr << "Error: peer_addr is not properly initialized. Cannot send packet.\n";
  //   return;
  // }

  // uint8_t buffer[sizeof(CustomPacket)];
  // packet.serialize(buffer);
  
  ssize_t bytes_sent = sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, sizeof(client_addr));

  if (bytes_sent < 0) {
    std::cerr << "Error sending packet with ID " << packet.packet_id << "\n" << bytes_sent << std::endl;
  } else {
    std::cout << "Packet with ID " << packet.packet_id << " sent successfully.\n";
  }
}

void Peer::sendPacketTo(const CustomPacket &packet, const struct sockaddr_in &dest_addr) {
  uint8_t buffer[sizeof(struct iphdr) + sizeof(CustomPacket)];

  // Construct the IP header
  struct iphdr *ip_header = (struct iphdr *)buffer;
  ip_header->version = 4; // IPv4
  ip_header->ihl = 5; // Header length (5 * 4 = 20 bytes)
  ip_header->tos = 0; // Type of service
  ip_header->tot_len = htons(sizeof(buffer)); // Total length (header + payload)
  ip_header->id = htons(54321); // Identification
  ip_header->frag_off = 0; // No fragmentation
  ip_header->ttl = 64; // Time to live
  ip_header->protocol = IPPROTO_RAW; // Protocol (raw socket)
  ip_header->check = 0; // Checksum (set to 0 for now, kernel may calculate it)
  ip_header->saddr = inet_addr("127.0.0.1"); // Source IP address
  ip_header->daddr = dest_addr.sin_addr.s_addr; // Destination IP address

  // Copy the payload (CustomPacket) into the buffer after the IP header
  packet.serialize(buffer + sizeof(struct iphdr));

  // Send the packet to the specified address
  ssize_t bytes_sent = sendto(sock, buffer, sizeof(buffer), 0,
                              (struct sockaddr *)&dest_addr, sizeof(dest_addr));

  if (bytes_sent < 0) {
    perror("Error sending packet");
  } else {
    std::cout << "Packet with ID " << packet.packet_id << " sent successfully to "
              << inet_ntoa(dest_addr.sin_addr) << ":" << ntohs(dest_addr.sin_port) << "\n";
  }
}

// TODO it is bad!!! I was using TCP
void Peer::startPeer(int port, const char *remote_ip) {
  std::cout << "startPeer called with port: " << port
            << " and remote_ip: " << (remote_ip ? remote_ip : "nullptr") << "\n";

  sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sock < 0) {
    perror( "Error creating socket");
    return;
  }

  // ?????Not present
  peer_addr.sin_family = AF_INET;
  peer_addr.sin_port = htons(port);

  if (remote_ip) {
    if (inet_pton(AF_INET, remote_ip, &peer_addr.sin_addr) <= 0) {
      std::cerr << "Invalid address/Address not supported: " << remote_ip
                << std::endl;
      return;
    }


    std::cout<<"Client mode initialized.\n";
    packet_id = 0;
    connectToPeer(remote_ip);

  } else {
    std::cout<< "Server mode" << std::endl;
    peer_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) < 0) {
      perror("Error binding socket");
      std::cerr << "Error: Failed to bind socket to port " << port << std::endl;
      close(sock);
      return;
    }

    std::cout<< "Server mode initialized.\n";
  }

  // Start threads for receiving and processing packets
  std::thread receiver(&Peer::listenForPackets, this);
  std::thread processor(&Peer::processPackets, this);

  receiver.detach();
  processor.detach();
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

  // uint8_t buffer[sizeof(CustomPacket)];
  uint8_t buffer[sizeof(struct iphdr) + sizeof(CustomPacket)];
  socklen_t addr_len = sizeof(peer_addr);

  {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "Received Packet?\n";
  }
  ssize_t bytes_read = recvfrom(sock, buffer, sizeof(buffer), 0,
                                (struct sockaddr *)&peer_addr, &addr_len);

  {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "\nReceived Packet!!\n";
  }

  if (bytes_read <= 0) {
    std::cerr << "Error reading from socket.\n";
    return;
  }else {
    std::cout<< "I have received a packet with no error!\n";
  }

  // packet = CustomPacket::deserialize(buffer);
  // Skip the IP header and deserialize the payload
  packet = CustomPacket::deserialize(buffer + sizeof(struct iphdr));


  {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "Received Packet ID: " << packet.packet_id << "\n";
    std::cout << "Payload: " << packet.payload << "\n";
    std::cout << "Checksum: " << packet.checksum << "\n";
    packet.printFlags();
  }
}

// TODO check everithing
void Peer::listenForPackets() {
  // struct sockaddr_in client_addr; // Store the client's address
  // bool client_addr_initialized = false; // Track if the client's address is initialized

  while (true) {
    CustomPacket packet;
    receivePacket(packet);

    {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout << "---Waiting to receive a packet.\n";
    }

    if (packet.length == 0) {
      continue;
    }

    {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout << "Received a packet; isconnected: " << is_connected << std::endl;
    }

    if (!is_connected) {
      if (packet.get_urgent_flag() && packet.get_start_transmition_flag()) {
        {
          std::lock_guard<std::mutex> lock(cout_mutex);
          std::cout << "Received initial connection packet. Responding with acknowledgment.\n";
        }

        // Store the client's address
        client_addr = peer_addr;
        client_addr_initialized = true;

        // Create the acknowledgment packet
        CustomPacket ack_packet;
        ack_packet.packet_id = ++packet_id;
        ack_packet.set_urgent_flag();
        ack_packet.set_ack_flag();
        ack_packet.length = 0; // No payload for the acknowledgment packet
        ack_packet.checksum = ack_packet.calculateChecksum();

        // Send the acknowledgment packet using the stored client address
        if (client_addr_initialized) {
          // sendPacketTo(ack_packet, client_addr);
          sendPacket(ack_packet);
        } else {
          std::cerr << "Error: Client address not initialized. Cannot send acknowledgment.\n";
        }

        {
          std::lock_guard<std::mutex> lock(cout_mutex);
          std::cout << "Sent acknowledgment packet.\n";
        }

        // Mark the peer as connected
        this->is_connected = true;
        continue;

      } else {
        {
          std::lock_guard<std::mutex> lock(cout_mutex);
          std::cerr << "Unexpected packet received before connection was established. Ignoring.\n";
        }
        continue;
      }
    } else {
      // Add the packet to the queue
      {
        std::lock_guard<std::mutex> lock(packet_mutex);
        packet_vector.push_back(packet);
      }
      packet_cv.notify_one(); // Notify the processing thread
    }
  }
}

void Peer::processPackets() {
  while (true) {
    // std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    CustomPacket packet;

    // Wait for a packet to be available
    {
      std::unique_lock<std::mutex> lock(packet_mutex);
      packet_cv.wait(lock, [this] { return !packet_vector.empty(); });

      {
        std::lock_guard<std::mutex> cout_lock(cout_mutex);
        std::cout << "Processing a packet from the queue.\nSize: " << packet_vector.size() << std::endl;
      }



      // Get the next packet from the queue
      // packet = packet_vector.front();
      // packet_vector.pop();
      packet = *packet_vector.begin();
      packet_vector.erase(packet_vector.begin());
    }

    // Validate the packet
    if (packet.calculateChecksum() != packet.checksum) {
      {
        std::lock_guard<std::mutex> cout_lock(cout_mutex);
        std::cerr << "Packet with ID " << packet.packet_id
                  << " is corrupted!\n";
      }
      continue;
    }

    // Process the packet (e.g., add to a map, reconstruct a message, etc.)
    {
      std::lock_guard<std::mutex> cout_lock(cout_mutex);
      std::cout << "Processing Packet ID: " << packet.packet_id << "\n";
      std::cout << "Payload: " << packet.payload << "\n";
    }
  }
}

void Peer::sendMessage(const std::string &msg) {
  // std::cout <<"Sending message: " << msg << std::endl;
  std::map<uint16_t, CustomPacket> packet_list =
      CustomPacket::fragmentMessage(msg, packet_id);

  for (const auto &pair : packet_list) {
    const CustomPacket &packet = pair.second;
    {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout << "Sending Packet ID: " << packet.packet_id << "\n";
      std::cout << "Payload to be send: " << packet.payload << "\n";

    }
    sendPacket(packet);
  }
}

void Peer::connectToPeer(const char *remote_ip) {
  std::cout << "Client is attempting to connect to " << remote_ip << "...\n";

  // Set up the destination address
  peer_addr.sin_family = AF_INET;
  peer_addr.sin_port = htons(8080); // Example port
  if (inet_pton(AF_INET, remote_ip, &peer_addr.sin_addr) <= 0) {
    std::cerr << "Invalid address/Address not supported: " << remote_ip << "\n";
    return;
  }

  client_addr = peer_addr;

  // Create the initial packet with urgent and start_transmission flags
  // CustomPacket start_packet0;
  // start_packet0.packet_id = packet_id++;
  // start_packet0.length = 0;
  // start_packet0.checksum = start_packet0.calculateChecksum();

  // // Send the initial packet
  // sendPacket(start_packet0);

  std::cout << "Sent initial packet with urgent and start_transmission flags.\n";
  // Create the initial packet with urgent and start_transmission flags
  CustomPacket start_packet;
  start_packet.packet_id = packet_id++;
  start_packet.set_urgent_flag();
  start_packet.set_start_transmition_flag();
  std::string msg= "HELLO!";
  memcpy(start_packet.payload, msg.data(), msg.size());
  // start_packet.payload = "HELLO!";
  start_packet.length = msg.size(); // No payload for the initial packet
  start_packet.checksum = start_packet.calculateChecksum();

  // Send the initial packet
  sendPacket(start_packet);

  std::cout << "Sent initial packet with urgent and start_transmission flags.\n";

  // Wait for a response packet with urgent and ack flags
  CustomPacket response_packet;
  while (true) {
    receivePacket(response_packet);

    if (response_packet.get_urgent_flag() && response_packet.get_ack_flag()) {
      std::cout << "Received acknowledgment packet from the server.\n";
      break;
    } else {
      std::cout << "Received a packet, but it does not have the expected flags. Waiting...\n";
    }
  }

  std::cout << "Connection established with remote peer at " << remote_ip << ".\n";
  this->is_connected = true;
}