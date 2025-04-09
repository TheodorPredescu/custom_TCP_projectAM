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
  {

  //   std::lock_guard<std::mutex> lock(cout_mutex);
  // // Debug: Print packet details
  // std::cout << "Sending Packet ID: " << packet.packet_id << "\n";
  // std::cout << "Flags: " << static_cast<int>(packet.flags) << "\n";
  // std::cout << "Length: " << packet.length << "\n";
  // std::cout << "Payload: " << packet.payload << "\n";
  // std::cout << "Checksum: " << packet.checksum << "\n";
  // packet.printFlags();


  // Debug: Print the destination address
  char dest_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(client_addr.sin_addr), dest_ip, INET_ADDRSTRLEN);
  std::cout << "Sending packet to " << dest_ip << ":" << ntohs(client_addr.sin_port) << "\n";
  }


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
  ip_header->id = htons(packet.packet_id); // Identification
  ip_header->frag_off = 0; // No fragmentation
  ip_header->ttl = 64; // Time to live
  ip_header->protocol = IPPROTO_RAW; // Protocol (raw socket)
  ip_header->check = 0; // Checksum (set to 0 for now, kernel may calculate it)
  ip_header->saddr = inet_addr("127.0.0.1"); // Source IP address
  ip_header->daddr = client_addr.sin_addr.s_addr; // Destination IP address

  // Copy the payload (CustomPacket) into the buffer after the IP header
  packet.serialize(buffer + sizeof(struct iphdr));
  
  ssize_t bytes_sent = sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, sizeof(client_addr));

  {
    std::lock_guard<std::mutex> lock(cout_mutex);

    if (bytes_sent < 0) {
      std::cerr << "Error sending packet with ID " << packet.packet_id << "\n" << bytes_sent << std::endl;
    } else {
      std::cout << "Packet with ID " << packet.packet_id << " sent successfully.\n";
    }
  }
}

// -----------------------------------------------------------------------------------------------------

void Peer::sendPacketTo(const CustomPacket &packet, const struct sockaddr_in &dest_addr) {
  uint8_t buffer[sizeof(struct iphdr) + sizeof(CustomPacket)];

  // Construct the IP header
  struct iphdr *ip_header = (struct iphdr *)buffer;
  ip_header->version = 4; // IPv4
  ip_header->ihl = 5; // Header length (5 * 4 = 20 bytes)
  ip_header->tos = 0; // Type of service
  ip_header->tot_len = htons(sizeof(buffer)); // Total length (header + payload)
  ip_header->id = htons(packet.packet_id); // Identification
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
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "Packet with ID " << packet.packet_id << " sent successfully to "
              << inet_ntoa(dest_addr.sin_addr) << ":" << ntohs(dest_addr.sin_port) << "\n";
  }
}

//-------------------------------------------------------------------------------------------------------
void Peer::startPeer(int port, const char *remote_ip) {
    {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout << "startPeer called with port: " << port
            << " and remote_ip: " << (remote_ip ? remote_ip : "nullptr") << "\n";
    }

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

    {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout<<"Client mode initialized.\n";
    }
    connectToPeer(remote_ip);

  } else {
    {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout<< "Server mode" << std::endl;
    }
    peer_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) < 0) {
      perror("Error binding socket");
      std::cerr << "Error: Failed to bind socket to port " << port << std::endl;
      close(sock);
      return;
    }

    {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout<< "Server mode initialized.\n";
    }
  }

  // Start threads for receiving and processing packets
  std::thread receiver(&Peer::listenForPackets, this);
  std::thread processor(&Peer::processPackets, this);

  receiver.detach();
  processor.detach();
}

//-------------------------------------------------------------------------------------------------------
// We need to receive the packet, check if it has the serialize flag on and add
// it to a vector;
// If the waiting accedes a certain duration, we send it to composedMessage();
// I need to think of a way to patch the wrong transimions (meaning late
// messages) -> most likely i keep the vector here till a "finished with
// success" message !! OOOOR I  SEND FIRST A PACKET THAT TELLS ME THE NUMBER OF
// PACKAGES THAT WILL BE SEND AND I JUST CHECK IF THAT NUMBER OF PACKAGES ARE
// MET
void Peer::receivePacket(CustomPacket &packet) {

  uint8_t buffer[sizeof(struct iphdr) + sizeof(CustomPacket)];
  socklen_t addr_len = sizeof(peer_addr);

  ssize_t bytes_read = recvfrom(sock, buffer, sizeof(buffer), 0,
                                (struct sockaddr *)&peer_addr, &addr_len);

  if (bytes_read <= 0) {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "Error reading from socket.\n";
    return;
  }else {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout<< "I have received a packet!\n";
  }

  packet = CustomPacket::deserialize(buffer + sizeof(struct iphdr));

  {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "Received Packet ID: " << packet.packet_id << "\n";
    std::cout << "Payload: " << packet.payload << "\n";
    std::cout << "Checksum: " << packet.checksum << "\n";
    packet.printFlags();
  }
}

//-------------------------------------------------------------------------------------------------------
void Peer::listenForPackets() {

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

    // Sequence for responding to a connection request
    if (!is_connected) {
      if (packet.get_urgent_flag() && packet.get_start_transmition_flag()) {
        {
          std::lock_guard<std::mutex> lock(cout_mutex);
          std::cout << "Received initial connection packet. Responding with acknowledgment.\n";
        }

        // Store the client's address
        client_addr = peer_addr;
        // client_addr_initialized = true;

        incrementing_and_checking_packet_id(packet.packet_id);
        sendPacket(create_ack_packet());

        // // Send the acknowledgment packet using the stored client address
        // if (client_addr_initialized) {
        //   // sendPacket(ack_packet);
        //   sendPacket(create_ack_packet());
        // } else {
        //   std::cerr << "Error: Client address not initialized. Cannot send acknowledgment.\n";
        // }

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

        {
          std::lock_guard<std::mutex> lock(cout_mutex);
          std::cout << "Is connected branch\n";
        }


      //if it is already connected, but it still tries to connect to it (from some reason)
      if (packet.get_urgent_flag() && packet.get_start_transmition_flag()) {
        std::lock_guard<std::mutex> lock (cout_mutex);
        std::cout<<"Receaved again a start transmition!\n\tIgnorring...\n";
        continue;
      }
      
      // If end transmition sequense started the initiation
      if (packet.get_urgent_flag() && packet.get_end_transmition_flag()) {
        {
          std::lock_guard<std::mutex> lock (cout_mutex);
          std::cout<< "Receaved end transmition packet. Responding...\n";
        }
        
        incrementing_and_checking_packet_id(packet.packet_id);

        // CustomPacket ack_packet;
        // ack_packet.packet_id = packet_id;
        // ack_packet.set_ack_flag();
        // ack_packet.set_urgent_flag();
        // std::string msg= "ack";
        // memcpy(ack_packet.payload, msg.data(), msg.size());
        // ack_packet.length = msg.size();
        // ack_packet.checksum = ack_packet.calculateChecksum();

        // sendPacket(ack_packet);

        sendPacket(create_ack_packet());
        {
          std::lock_guard<std::mutex> lock (cout_mutex);
          std::cout<< "Sended packet with ack of end transmition...:\n";
        }
        this->is_connected = false;

        // Close the socket
        close(sock);
        {
          std::lock_guard<std::mutex> lock(cout_mutex);
          std::cout << "Socket closed.\n";
        }

        return;

      }

      {
      // Add the packet to the queue
        std::lock_guard<std::mutex> lock(packet_mutex);
        packet_vector.push_back(packet);
        {
          std::lock_guard<std::mutex> lock(cout_mutex);
          std::cout<<"Added the packet with id: " << packet.packet_id << " in the packet_vector.\n";
        }
        packet_cv.notify_one(); // Notify the processing thread
      }
    }
  }
}

//-------------------------------------------------------------------------------------------------------
void Peer::processPackets() {
  std::map<uint16_t, std::string> msg_log;
  std::map<uint16_t, std::string> long_message;
  std::string msg = "";
  u_int16_t start = UINT16_MAX, end = UINT16_MAX;
  std::vector<uint16_t> missing_packets;

  while (true) {
    CustomPacket packet;

    // Wait for a packet to be available
    {
      std::unique_lock<std::mutex> lock(packet_mutex);
      packet_cv.wait(lock, [this] { return !packet_vector.empty(); });

      {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "Processing a packet from the queue.\nSize: " << packet_vector.size() << std::endl;
      }



      // Get the next packet from the queue
      packet = *packet_vector.begin();
      packet_vector.erase(packet_vector.begin());
    }

    // Validate the packet
    if (packet.calculateChecksum() != packet.checksum) {
      {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cerr << "\n\n!!! Packet with ID " << packet.packet_id
                  << " is corrupted !!!!\n\n\n";
      }
      continue;
    }

    // Process the packet (e.g., add to a map, reconstruct a message, etc.)
    {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout << "Processing Packet ID: " << packet.packet_id << "\n";
      std::cout << "Payload: " << packet.payload << "\n";
    }

    if (!packet.get_serialize_flag()) {
      msg_log.emplace(packet.packet_id, std::string(packet.payload, packet.length));
    }else {

      {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout<< "Got to the serialize section.\n";
      }

      // We will itinitate the serialise packet size if we didnt already
      if (packet.get_start_transmition_flag() && serialise_packet_size == 0) {
        serialise_packet_size = std::stoi(std::string(packet.payload, packet.length));
        start = packet.packet_id;
        {
          std::lock_guard<std::mutex> lock(cout_mutex);
          std::cout<< "\tFoud the start transmition packet. Number of packets in this train is: " << serialise_packet_size << std::endl;
        }

        incrementing_and_checking_packet_id(start);

        continue;
      }else if (packet.get_start_transmition_flag()){
        {
          std::lock_guard<std::mutex> lock(cout_mutex);
          std::cout<< "\n\nWe found a second start packet with start transmition !!! \n\n";
        }

        continue;

      }

      {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout<< "We are adding the packet "<< packet.packet_id <<" in the big message!\n";
      }

      //TODO: For longer messages; I need to recheck for 2 long messages back to back
      //The first packet (the one with the start) has in payload the number of packets from that 
      if (long_message.find(packet.packet_id) == long_message.end()) {
        long_message.emplace(packet.packet_id, std::string(packet.payload, packet.length));
        procesed_packets++; 
      }else {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout<< "\n\n\tWe have a duplicate\n\n\n";
      }

      //TODO: size_long_msg is reseting for some reason
        {
          std::lock_guard<std::mutex> lock(cout_mutex);
          std::cout<< "\n\nsize_long_msg: " << serialise_packet_size << " ; packets processed: " <<procesed_packets << std::endl;
        }

      if (serialise_packet_size != 0 && serialise_packet_size == procesed_packets) {
        for (int i = 1; i <serialise_packet_size + 1; ++i) {
          uint16_t current_packet_id = start + i;

          auto it = long_message.find(current_packet_id);
          if (it != long_message.end()) {
            msg += it->second;
          }else {
            {
              std::lock_guard<std::mutex> lock(cout_mutex);
              std::cout<< "Missing packet: " << current_packet_id << std::endl;
            }
            missing_packets.push_back(current_packet_id);
          }
        }

        if (!missing_packets.empty()) {
          {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout<< "There are missing packets!\n";
          }
          throw missing_packets;
        }

        long_message.clear();
        start = UINT16_MAX;
        serialise_packet_size = 0;
        procesed_packets = 0;

        {
          std::lock_guard<std::mutex> lock(cout_mutex);
          std::cout << "\tBIG MESSAGE:\n\t" << msg << "\n";
        }

        msg.clear();
      }
    }

    incrementing_and_checking_packet_id(packet.packet_id);
  }
}

//-------------------------------------------------------------------------------------------------------
void Peer::sendMessage(const std::string &msg) {
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

//-------------------------------------------------------------------------------------------------------
void Peer::connectToPeer(const char *remote_ip) {
  {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "Client is attempting to connect to " << remote_ip << "...\n";
  }

  // Set up the destination address
  peer_addr.sin_family = AF_INET;
  peer_addr.sin_port = htons(8080); // Example port
  if (inet_pton(AF_INET, remote_ip, &peer_addr.sin_addr) <= 0) {
    std::cerr << "Invalid address/Address not supported: " << remote_ip << "\n";
    return;
  }

  client_addr = peer_addr;
  {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "Sent initial packet with urgent and start_transmission flags.\n";
  }
  packet_id = 0;

  // Create the initial packet with urgent and start_transmission flags
  CustomPacket start_packet;
  start_packet.packet_id = packet_id;
  start_packet.set_urgent_flag();
  start_packet.set_start_transmition_flag();

  std::string msg= "HELLO!";
  memcpy(start_packet.payload, msg.data(), msg.size());
  start_packet.length = msg.size();
  start_packet.checksum = start_packet.calculateChecksum();

  // Send the initial packet
  sendPacket(start_packet);

  {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "Sent initial packet with urgent and start_transmission flags.\n";
  }

  // Wait for a response packet with urgent and ack flags
  CustomPacket response_packet;
  while (true) {
    receivePacket(response_packet);

    if (response_packet.get_urgent_flag() && response_packet.get_ack_flag()) {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout << "Received acknowledgment packet from the server.\n";
      incrementing_and_checking_packet_id(response_packet.packet_id);
      break;
    } else {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout << "?Received a packet, but it does not have the expected flags. Waiting...\n";
    }
  }

  {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "Connection established with remote peer at " << remote_ip << ".\n";
  }
  this->is_connected = true;
}

//-------------------------------------------------------------------------------------------------------
void Peer::incrementing_and_checking_packet_id(const uint16_t &packet_id_received) {

  std::lock_guard<std::mutex> lock(packet_id_mutex);

  if (packet_id < packet_id_received || packet_id == UINT16_MAX) {
    packet_id = packet_id_received;
    CustomPacket::incrementPacketId(packet_id);
  } else {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout<< "\tReceived a packet with ID lower then the current one! Keeping current id\n";
  }
}

//-------------------------------------------------------------------------------------------------------
// I need to send another message: when i receive a request to end the socket, i need to send an 
// ack packet and w8 to see if that packet gets to the user. If i dont, the iniciator can wait for
// my ack and never get it.
void Peer::endConnection() {
  {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "Attempting to end the connection...\n";
  }

  // Create the end connection packet
  CustomPacket end_packet;
  {
    std::lock_guard<std::mutex> lock(packet_id_mutex);
    end_packet.packet_id = packet_id;
    end_packet.set_urgent_flag();
    end_packet.set_end_transmition_flag();
    std::string msg= "end";
    memcpy(end_packet.payload, msg.data(), msg.size());

    end_packet.length = msg.size();
    end_packet.checksum = end_packet.calculateChecksum();
  }

  // Send the end connection packet
  sendPacket(end_packet);

  {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "Sent end connection packet with ID: " << end_packet.packet_id << "\n";
    end_packet.printFlags();
  }

  // Wait for acknowledgment
  CustomPacket response_packet;
  while (true) {
    receivePacket(response_packet);

    if (response_packet.get_urgent_flag() && response_packet.get_ack_flag()) {
      {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "\n\nReceived acknowledgment for end connection packet.\n";
      }
      break;
    } else {
      {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "\n\nReceived a packet in waiting for ack, but it does not have the expected flags. Waiting...\n";
      }
    }
  }

  // Mark the connection as disconnected
  {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "Connection successfully ended.\n";
  }
  this->is_connected = false;

  // Close the socket
  close(sock);
  {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "socket closed.\n";
  }

}
//-------------------------------------------------------------------------------------------------------
CustomPacket Peer::create_ack_packet () {

  // Create the acknowledgment packet
  CustomPacket ack_packet;
  {
    std::lock_guard<std::mutex> lock(packet_id_mutex);
    ack_packet.packet_id = packet_id;
  }
  ack_packet.set_urgent_flag();
  ack_packet.set_ack_flag();
  std::string msg= "ack";
  memcpy(ack_packet.payload, msg.data(), msg.size());
  ack_packet.length = msg.size();
  ack_packet.checksum = ack_packet.calculateChecksum();

  return ack_packet;

}