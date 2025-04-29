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

#include <fstream>
#include <sstream>
#include <sys/stat.h>  // For mkdir
#include <sys/types.h> // For mkdir
#include <filesystem>  // For checking if the folder exists (C++17)
#include <ifaddrs.h>
#include <netdb.h>

//For input select reader
#include "Peer.h"
#include "CustomPacket.h"

// I need to add first the ipaddress of the user (sockaddr_in) and initialize it in startPeer funtion;
// it will then remain in the Peer class (it is a private variable)
// gets a package and sends it to the socket sock
void Peer::sendPacket(const CustomPacket &packet) { 
  {

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
  ip_header->saddr = inet_addr(localIPAddress.c_str()); // Source IP address
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

//-------------------------------------------------------------------------------------------------------
void Peer::startPeer() {

  this->localIPAddress = getLocalIPAddress();
  if (localIPAddress == "") {
      {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "Cannot get IPAddress!!";
      }
      return;
  }else {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "IP Address: " << localIPAddress << std::endl;
  }

  {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "startPeer called with port: " << this->port << "\n";
  }

  sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sock < 0) {
    perror( "Error creating socket");
    return;
  }

  peer_addr.sin_family = AF_INET;
  peer_addr.sin_port = htons(this->port);

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

  // Start threads for receiving and processing packets
  // std::thread receiver(&Peer::listenForPackets, this);
  // std::thread processor(&Peer::processPackets, this);

  // receiver.detach();
  // processor.detach();
  // receiver.join();
  // processor.join();
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
    // std::lock_guard<std::mutex> lock(cout_mutex);
    // std::cout<< "I have received a packet!\n";
  }

  packet = CustomPacket::deserialize(buffer + sizeof(struct iphdr));

  // {
  //   std::lock_guard<std::mutex> lock(cout_mutex);
  //   std::cout << "Received Packet ID: " << packet.packet_id << "\n";
  //   std::cout << "Payload: " << packet.payload << "\n";
  //   std::cout << "Checksum: " << packet.checksum << "\n";
  //   packet.printFlags();
  // }
}

//-------------------------------------------------------------------------------------------------------
void Peer::listenForPackets() {

  while (true) {

    //End thread on receiving the signal
    {
      std::lock_guard<std::mutex> lock(exiting_mutex);
    if (exiting) break;
    }


    CustomPacket packet;
    receivePacket(packet);

    if (packet.length == 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }
    {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout<<"Received a packet\n";

    }
     // Validate the packet
    if (packet.calculateChecksum() != packet.checksum) {
      {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cerr << "\n\n!!! Packet with ID " << packet.packet_id
                  << " is corrupted !!!!\n\n\n";
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }else {
      // std::lock_guard<std::mutex> lock(cout_mutex);
      // std::cout<<"Content: " << std::string(packet.payload, packet.length);
      // packet.printFlags();
    }

    bool var_is_connected;
    {
      std::lock_guard<std::mutex> lock(is_connected_mutex);
      var_is_connected = this->is_connected;
    }

    {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout << "Received a packet; isconnected: " << var_is_connected <<"\npacket size: " << 
      packet.length<< std::endl;
      packet.printFlags();
    }

    // Sequence for responding to a connection request
    if (!var_is_connected) {
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

        {
          std::lock_guard<std::mutex> lock(cout_mutex);
          std::cout << "Sent acknowledgment packet.\n";
        }

        // Mark the peer as connected
        {
          std::lock_guard<std::mutex> lock(is_connected_mutex);
          this->is_connected = true;
        }
        continue;

        //Checking if we received ack for us trying to connect to someone
      } else if (packet.get_urgent_flag() && packet.get_ack_flag()){

        bool var = false;
        {
          std::lock_guard<std::mutex> lock(connectToPeer_message_send_mutex);
          var = this->connectToPeer_message_send;
        }

        if (var) {
          {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "Connection established with remote peer.\n";
          }
          
          {
            std::lock_guard<std::mutex> lock(is_connected_mutex);
            this->is_connected = true;
          }
          incrementing_and_checking_packet_id(packet.packet_id);

          {
            std::lock_guard<std::mutex> lock(connectToPeer_message_send_mutex);
            this->connectToPeer_message_send = false;
          }
        }else {
          std::lock_guard<std::mutex> lock(cout_mutex);
          std::cout << "Unexpected packet received before connection was established. Ignoring.\n\n";
        }
        continue;
      }else {
        {
          std::lock_guard<std::mutex> lock(cout_mutex);
          std::cout << "Unexpected packet received before connection was established. Ignoring.\n\n";
        }
      }
    } else {

        {
          std::lock_guard<std::mutex> lock(cout_mutex);
          std::cout << "\nIs connected branch\n";
          std::cout<< "Processing packet: " << packet.packet_id<< std::endl;
          packet.printFlags();
          std::cout<<std::endl;
        }
      std::this_thread::sleep_for(std::chrono::milliseconds(100));



      //if it is already connected, but it still tries to connect to it (from some reason)
      // TODO: we need to send 1 more packet in this sequence to be sore that we bouth end it.
      if (packet.get_urgent_flag() && packet.get_start_transmition_flag()) {
        std::lock_guard<std::mutex> lock (cout_mutex);
        std::cout<<"Received again a start transmition!\n\tIgnorring...\n";
        continue;
      }
      
      // If end transmition sequense started the initiation
      if (packet.get_urgent_flag() && packet.get_end_transmition_flag()) {
        {
          std::lock_guard<std::mutex> lock (cout_mutex);
          std::cout<< "Received end transmition packet. Responding...\n";
        }
        
        incrementing_and_checking_packet_id(packet.packet_id);
        sendPacket(create_ack_packet());
        {
          std::lock_guard<std::mutex> lock (cout_mutex);
          std::cout<< "Sended packet with ack of end transmition...:\n";
        }

        {
          std::lock_guard<std::mutex> lock (is_connected_mutex);
          this->is_connected = false;
        }

        {
          std::lock_guard<std::mutex> lock(exiting_mutex);
          this->exiting = true;
        }


        // Close the socket
        close(sock);

        //Creating mock packet so that we dont block the processPackets
        CustomPacket mock_packet;
        {
          std::lock_guard<std::mutex> lock(packet_mutex);
          packet_vector.push_back(mock_packet);
          packet_cv.notify_one();
        }

        {
          std::lock_guard<std::mutex> lock(cout_mutex);
          std::cout << "Socket closed.Sended mock packet to close the processPackets.\n";
        }

        return;
      }

      //Responding to a missing packet from the serialise message
      // TODO: Check if it works with text message and file!!!
      if (packet.get_error_flag() && packet.get_serialize_flag()) {
        if (packet.packet_id <= packet_id) {
          {
            std::lock_guard<std::mutex> lock (cout_mutex);
            std::cout << "Received a packet that has info about packets that did not make it\n\t";
          }

          {
            std::lock_guard<std::mutex> lock(packetsToBeSend_mutex);
            auto it = packetsToBeSend.find(packet.packet_id);

            if (it != packetsToBeSend.end()){
              sendPacket(it->second);
            }else {
              std::lock_guard<std::mutex> lock(cout_mutex);
              std::cout<<"The packet that did not make it is not in the history anymore\n";
            }
          }
        }else {
          std::lock_guard<std::mutex> lock (cout_mutex);
          std::cout << "Received an error packet with id to big!! IGNORING!\n";
        }

        continue;
      }

      if (packet.get_urgent_flag() && packet.get_ack_flag()) {
        bool var_req_end = false;
        {
          std::lock_guard<std::mutex> lock(requested_end_transmition_mutex);
          var_req_end = this->requested_end_transmition;
        }

        {
          std::lock_guard<std::mutex> lock(cout_mutex);
          std::cout<<"Ack packet received\n";
        }

        if (var_req_end) {
          {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "Connection successfully ended.\n";
          }

          // Close the socket
          close(sock);
          {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "socket closed.\n";
          }
          {
            std::lock_guard<std::mutex> lock(exiting_mutex);
            this->exiting = true;
          }

          //Creating mock packet so that we dont block the processPackets
          CustomPacket mock_packet;
          {
            std::lock_guard<std::mutex> lock(packet_mutex);
            packet_vector.push_back(mock_packet);
            packet_cv.notify_one();
          }
          {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "sended mocking packet";
          }

          std::this_thread::sleep_for(std::chrono::milliseconds(100));

          return;
        }

        continue;
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

  std::string file_name, file_extension;
  size_t file_size = 0;
  std::ostringstream file_content;
  
  while (true) {

    CustomPacket packet;

    // Wait for a packet to be available
    {
      std::unique_lock<std::mutex> lock(packet_mutex);
      packet_cv.wait(lock, [this] { return !packet_vector.empty(); });

      //End thread on receiving the signal
      {
        std::lock_guard<std::mutex> lock(exiting_mutex);
        if (exiting){
          {
            std::lock_guard<std::mutex> lock(adding_msg_received);
            messages_received.push_back("Aw12@0986^12luAwCluhWQ123~~``!");
            messages_received_cv.notify_one();
          }
          break;
        }
      }

      {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "Processing a packet from the queue.\nSize: " << packet_vector.size() << std::endl;
      }

      // Get the next packet from the queue
      packet = *packet_vector.begin();
      packet_vector.erase(packet_vector.begin());
    }

    // I will do this in listen for packets
    // // Validate the packet
    // if (packet.calculateChecksum() != packet.checksum) {
    //   {
    //     std::lock_guard<std::mutex> lock(cout_mutex);
    //     std::cerr << "\n\n!!! Packet with ID " << packet.packet_id
    //               << " is corrupted !!!!\n\n\n";
    //   }
    //   continue;
    // }

    // Process the packet (e.g., add to a map, reconstruct a message, etc.)
    {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout << "Processing Packet ID: " << packet.packet_id << "\n";
      // std::cout << "Payload: " << packet.payload << "\n";
    }

    if (!packet.get_serialize_flag()) {
      //-------------nonserialize-----------------

    {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout << "Single packet.\n";
    }

      std::string msg = std::string(packet.payload, packet.length);
      msg_log.emplace(packet.packet_id, msg);

      //For showing in interface
      adding_messages_in_received_messages(msg);
      

      // If i receive a packet that its not in the interval precizated
      if (start != UINT16_MAX && end != UINT16_MAX && 
         !(start < packet.packet_id && packet.packet_id <= start + serialise_packet_size)) {

        {
          std::lock_guard<std::mutex> lock(cout_mutex);
          std::cout << "Not all packets are received!\tSending the missing packets";
        }

        // TODO: I need to add logic for dealing with this !! If the error message is lost, 
        // the message will remain incomplete; it will not send it twice
        if (!missing_packets.empty()) {
          for (const auto &it : missing_packets) {
            // sendPacket(create_error_packet(it));
            {
              std::lock_guard<std::mutex> lock(cout_mutex);
              std::cout << "Sending request for resend for: " << static_cast<int>(it);
            }
          }
          missing_packets.clear();

          continue;
        }
      }
    }else {

      // ------------serialise section--------------------------
      {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout<< "Got to the serialize section.\n";
      }

      //-----------------Text message-------------------
      if (packet.getMsgType() == 0) {

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

        //The first packet (the one with the start) has in payload the number of packets from that 
        if (long_message.find(packet.packet_id) == long_message.end() && serialise_packet_size != 0) {
          long_message.emplace(packet.packet_id, std::string(packet.payload, packet.length));
          procesed_packets++; 
        }else {
          std::lock_guard<std::mutex> lock(cout_mutex);
          std::cout<< "\n\n\tWe have a duplicate\n\n\n";
        }

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

          if (packet.getMsgType() == 1){
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "\tBIG MESSAGE:\n\t" << msg << "\n";
          }else {

          }

          //For showing it in interface
          adding_messages_in_received_messages(msg);

          // Nush sigur; nu pare deloc eficient sa folosesc acelasi tip de packet pentru date binare:/


          msg.clear();
        }

      } else {
        // -----------FILE TYPE-------------------

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
        // Process metadata packet; First packet after the size packet is the one with metadata
        if (file_name.empty()) {
            std::string metadata(packet.payload, packet.length);
            size_t pos1 = metadata.find('|');
            size_t pos2 = metadata.find('|', pos1 + 1);

            file_name = metadata.substr(0, pos1);
            file_extension = metadata.substr(pos1 + 1, pos2 - pos1 - 1);
            file_size = std::stoul(metadata.substr(pos2 + 1));

            {
              std::lock_guard<std::mutex> lock(cout_mutex);
              std::cout << "Received metadata: File Name: " << file_name
                        << ", File Extension: " << file_extension
                        << ", File Size: " << file_size << " bytes\n";
            }

            long_message[packet.packet_id] = metadata;
            procesed_packets++;

            continue;
        }

        // We add all the content message dirrecly in the long_message var
        long_message[packet.packet_id] = std::string(packet.payload, packet.length);
        procesed_packets++;

        {
          std::lock_guard<std::mutex> lock(cout_mutex);
          std::cout<<"Added content in the file\n";
          std::cout<<"\tprocessed packets : " << procesed_packets 
              << "\n\tserialize_packet_size: " << serialise_packet_size<<std::endl;
        }

        // If the size is met, we create the file and add the content in it.
        if (procesed_packets == serialise_packet_size) {
        {
          std::lock_guard<std::mutex> lock(cout_mutex);
          std::cout<<"all files received\n";
        }

          bool metadata_check = true;
          for (const auto &pair : long_message) {
            if (metadata_check) {
              {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cout<<"Ignorring metadata\n";
              }
              metadata_check = false;
              continue;
            }
            file_content << pair.second;
          }

          // Write the file to disk
          ensureDataFolderExists();

          std::string relative_path = folder_name + "/" + file_name;
          std::ofstream output_file(relative_path, std::ios::binary);
          if (output_file.is_open()) {
              output_file << file_content.str();
              output_file.close();

              {
                  std::lock_guard<std::mutex> lock(cout_mutex);
                  std::cout << "File reassembled and saved as: " << file_name << "\n";
              }
          } else {
              {
                  std::lock_guard<std::mutex> lock(cout_mutex);
                  std::cerr << "Error: Could not create file: " << file_name << "\n";
              }
          }

          // Clear the buffers
          long_message.clear();
          file_content.str("");
          file_content.clear();
          file_name.clear();
          file_extension.clear();
          file_size = 0;
          serialise_packet_size = 0;
          procesed_packets = 0;

          // // Reprint the commands
          // {
          //     std::lock_guard<std::mutex> lock(cout_mutex);
          //     std::cout << "\nCommands:\n";
          //     std::cout << "1. Send message\n";
          //     std::cout << "2. Send file\n";
          //     std::cout << "3. Exit\n";
          //     std::cout << "Enter your choice: \n";
          // }

          print_commands_options();
        }

      }

    }

    incrementing_and_checking_packet_id(packet.packet_id);
  }
}

//-------------------------------------------------------------------------------------------------------
void Peer::sendMessage(const std::string &msg) {
  std::map<uint16_t, CustomPacket> packet_list =
      CustomPacket::fragmentMessage(msg, packet_id);

  // I will add it to the new buffer to deal with the error packet if need be
  add_packets_to_history(packet_list);
  
  bool check = false;

  for (const auto &pair : packet_list) {
    const CustomPacket &packet = pair.second;
    {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout << "Sending Packet ID: " << packet.packet_id << "\n";
      std::cout << "Payload to be send: " << packet.payload << "\n";

    }

    // if (!check) {
    //   std::lock_guard<std::mutex> lock(cout_mutex);
    //   std::cout << "Skiping once\n";
    //   check = true;
    // }else {
    // }
    sendPacket(packet);
  }
}

//-------------------------------------------------------------------------------------------------------
void Peer::sendFile(const std::string &file_path) {
  std::map<uint16_t, CustomPacket> packet_list = CustomPacket::fragmentMessage(file_path, packet_id, true);

  // I will add it to the new buffer to deal with the error packet if need be
  add_packets_to_history(packet_list);
  
  bool check = false;

  for (const auto &pair : packet_list) {
    const CustomPacket &packet = pair.second;
    {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout << "\n\nSending Packet ID: " << packet.packet_id << "\n";
      std::cout << "Payload to be send: " << packet.payload << "\n";
      packet.printFlags();
      std::cout<<std::endl;

    }

    // if (!check) {
    //   std::lock_guard<std::mutex> lock(cout_mutex);
    //   std::cout << "Skiping once\n";
    //   check = true;
    // }else {
    // }
    sendPacket(packet);
  }
}


//STARTING AND ENDING CONNECTION
//-------------------------------------------------------------------------------------------------------
void Peer::connectToPeer(const char *remote_ip) {
  {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "Client is attempting to connect to " << remote_ip << "...\n";
  }

  // Set up the destination address
  peer_addr.sin_family = AF_INET;
  peer_addr.sin_port = htons(this->port); // port
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
    std::lock_guard<std::mutex> lock(connectToPeer_message_send_mutex);
    this->connectToPeer_message_send = true;
  }

  {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "Sent initial packet with urgent and start_transmission flags.\n";
  }

  // Wait for a response packet with urgent and ack flags
  CustomPacket response_packet;
  // while (true) {
  //   receivePacket(response_packet);

  //   if (response_packet.get_urgent_flag() && response_packet.get_ack_flag()) {
  //     std::lock_guard<std::mutex> lock(cout_mutex);
  //     std::cout << "Received acknowledgment packet from the server.\n";
  //     incrementing_and_checking_packet_id(response_packet.packet_id);
  //     break;
  //   } else {
  //     std::lock_guard<std::mutex> lock(cout_mutex);
  //     std::cout << "?Received a packet, but it does not have the expected flags. Waiting...\n";
  //   }
  // }

  // {
  //   std::lock_guard<std::mutex> lock(cout_mutex);
  //   std::cout << "Connection established with remote peer at " << remote_ip << ".\n";
  // }
  
  // {
  //   std::lock_guard<std::mutex> lock(is_connected_mutex);
  //   this->is_connected = true;
  // }
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

  {
    std::lock_guard<std::mutex> lock(requested_end_transmition_mutex);
    this->requested_end_transmition = true;
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Send the end connection packet
  sendPacket(end_packet);

  // {
  //   std::lock_guard<std::mutex> lock(exiting_mutex);
  //   this->exiting = true;
  // }

  {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "Sent end connection packet with ID: " << end_packet.packet_id << "\n";
    end_packet.printFlags();
  }

  // Wait for acknowledgment
  // CustomPacket response_packet;
  // while (true) {
  //   receivePacket(response_packet);

  //   if (response_packet.get_urgent_flag() && response_packet.get_ack_flag()) {
  //     {
  //       std::lock_guard<std::mutex> lock(cout_mutex);
  //       std::cout << "\nReceived acknowledgment for end connection packet.\n";
  //     }
  //     break;
  //   } else {
  //     {
  //       std::lock_guard<std::mutex> lock(cout_mutex);
  //       std::cout << "\n\nReceived a packet in waiting for ack, but it does not have the expected flags. Waiting...\n";
  //     }
  //   }
  // }

  // Mark the connection as disconnected
  // {
  //   std::lock_guard<std::mutex> lock(cout_mutex);
  //   std::cout << "Connection successfully ended.\n";
  // }
  
  // {
  //   std::lock_guard<std::mutex> lock(is_connected_mutex);
  //   this->is_connected = false;
  // }

  // // Close the socket
  // close(sock);
  // {
  //   std::lock_guard<std::mutex> lock(cout_mutex);
  //   std::cout << "socket closed.\n";
  // }

  // // For checking functionality and contents (debug)
  // {
  //   std::lock_guard<std::mutex> lock(packetsToBeSend_mutex);

  //   for (const auto &[key, val] : packetsToBeSend) {
  //     std::lock_guard<std::mutex> lock(cout_mutex);
  //     std::cout << key << "; " << std::string(val.payload, val.length) << "\n";
  //   }
  // }

}
//-------------------------------------------------------------------------------------------------------
CustomPacket Peer::create_ack_packet() {

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
//-------------------------------------------------------------------------------------------------------
CustomPacket Peer::create_start_packet(const int &size, const bool &isFile) {
  CustomPacket packet;
  packet.set_start_transmition_flag();
  packet.set_serialize_flag();
  isFile == 1 ? packet.setMsgType(1) : packet.setMsgType(0);

  std::string string_size = std::to_string(size);
  memcpy(packet.payload, string_size.data(), string_size.length());
  packet.payload[string_size.length()] = '\n';
  packet.length = string_size.length() + 1;
  packet.packet_id = this->packet_id;
  packet.checksum = packet.calculateChecksum();
  CustomPacket::incrementPacketId(packet.packet_id);

  return packet;
}

//-------------------------------------------------------------------------------------------------------
CustomPacket Peer::create_error_packet(const uint16_t &missing_packet_id) const {

  // Create the acknowledgment packet
  CustomPacket error_packet;
  
  error_packet.packet_id = missing_packet_id;
  error_packet.set_error_flag();
  error_packet.set_serialize_flag();
  std::string msg= "error";
  memcpy(error_packet.payload, msg.data(), msg.size());
  error_packet.length = msg.size();
  error_packet.checksum = error_packet.calculateChecksum();

  return error_packet;
}

//-------------------------------------------------------------------------------------------------------
void Peer::add_packets_to_history(const std::map<uint16_t, CustomPacket> &packet_list){
  for (const auto &pair : packet_list) {
    {
      std::lock_guard<std::mutex> lock(packetsToBeSend_mutex);

      while (packetsToBeSend.size() > size_of_packetsToBeSend) {
        auto oldest = packetsToBeSend.begin();
        packetsToBeSend.erase(oldest);
      }

      packetsToBeSend[pair.first] = pair.second;
    }

  }
}

//-------------------------------------------------------------------------------------------------------
void Peer::incrementing_and_checking_packet_id(const uint16_t &packet_id_received) {

  std::lock_guard<std::mutex> lock(packet_id_mutex);

  if (packet_id < packet_id_received || packet_id == UINT16_MAX) {
    packet_id = packet_id_received;
    CustomPacket::incrementPacketId(packet_id);
  } else {
    // std::lock_guard<std::mutex> lock(cout_mutex);
    // std::cout<< "\tReceived a packet with ID lower then the current one! Keeping current id\n";
  }
}

//-------------------------------------------------------------------------------------------------------
void Peer::adding_messages_in_received_messages(const std::string &msg) {

  {
    std::lock_guard<std::mutex> lock(adding_msg_received);
    messages_received.push_back(msg);

    {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout<<"Message added: " << msg <<  std::endl;
    }
  }


  messages_received_cv.notify_one();

}
//-------------------------------------------------------------------------------------------------------

std::string Peer::get_messages_received() {

  std::string msg;
  {
    std::unique_lock<std::mutex> lock(adding_msg_received);
    messages_received_cv.wait(lock, [this] {return !messages_received.empty();});

    msg = *messages_received.begin();
    messages_received.erase(messages_received.begin());
  }
  return msg;

}

void Peer::print_commands_options() {

  std::lock_guard<std::mutex> lock(cout_mutex);
  std::cout << "\nCommands:\n";
  std::cout << "1. Send message\n";
  std::cout << "2. Send file\n";
  std::cout << "3. Exit\n";
  std::cout << "Enter your choice:\n";
}
//-------------------------------------------------------------------------------------------------------

// bool Peer::confirm_file_received() {

//   {
//     std::unique_lock<std::mutex> lock(checking_file_received);
//     checking_file_received_cv.wait(lock, [this] {return checking_file_received;});

//     {
//       std::lock_guard<std::mutex> lock(cout_mutex);
//       std::cout <<"You have received a file. It has been saved in the data folder.\n";
//     }
//   }
//   return true;

// }

//-------------------------------------------------------------------------------------------------------
void Peer::runTerminalInterface() {

  // this->localIPAddress = getLocalIPAddress();
  // if (localIPAddress == "") {
  //     {
  //       std::lock_guard<std::mutex> lock(cout_mutex);
  //       std::cout << "Cannot get IPAddress!!";
  //     }
  //     return;
  // }else {
  //   std::lock_guard<std::mutex> lock(cout_mutex);
  //   std::cout << "IP Address: " << localIPAddress << std::endl;
  // }

  startPeer();

  // Start a thread to listen for incoming packets
  std::thread listener_thread([this]() {
      listenForPackets();
  });

  // Start a thread to print received messages
  std::thread message_printer_thread([this]() {

      // bool var_is_connected;
      // {
      //   std::lock_guard<std::mutex> lock(is_connected_mutex);
      //   var_is_connected = this->is_connected;
      // }
      while (true) {
          
        {
          std::lock_guard<std::mutex> lock(exiting_mutex);
          if (exiting) break;
        }
          std::string received_message = get_messages_received();

          {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "\n[Received Message]: " << received_message << "\n";
          }

          print_commands_options();

        // {
        //   std::lock_guard<std::mutex> lock(is_connected_mutex);
        //   var_is_connected = this->is_connected;
        // }
      }
  });

  {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "Welcome to the Peer CLI!\n";
    std::cout << "Choose mode:\n";
    std::cout << "1. Client\n";
  }

  // int mode;
  // std::cin >> mode;

  // bool var_is_connected;
  // {
  //   std::lock_guard<std::mutex>lock(is_connected_mutex);
  //   var_is_connected = is_connected;
  // }
  // if (mode == 1 && !var_is_connected) {

  //   std::string remote_ip;
  //   {
  //       std::lock_guard<std::mutex> lock(cout_mutex);
  //       std::cout << "Enter the server IP: ";
  //   }
  //   std::cin >> remote_ip;
  //   connectToPeer(remote_ip.c_str());
  //   {
  //       std::lock_guard<std::mutex> lock(cout_mutex);
  //       std::cout << "Connected to server at " << remote_ip << ":" << port << "\n";
  //   }
  // } else if (!var_is_connected){
  //     {
  //         std::lock_guard<std::mutex> lock(cout_mutex);
  //         std::cerr << "Invalid mode selected. Exiting...\n";
  //     }
  //     return;
  // }else if (var_is_connected){

  // }

  // bool var_is_connected = false;

  // while (!var_is_connected) {
  //   {
  //     std::lock_guard<std::mutex> lock(is_connected_mutex);
  //     var_is_connected = this->is_connected;
  //   }
  //   std::this_thread::sleep_for(std::chrono::milliseconds(100));
  // }

  bool var_is_connected;

  // Main loop for user commands
  while (true) {
      
    //********************************** */
    //blocking sequence
    {
      std::lock_guard<std::mutex> lock(exiting_mutex);
      if (exiting) break;
    }

    {
      std::lock_guard<std::mutex>lock(is_connected_mutex);
      var_is_connected = this->is_connected;
    }

    if (!var_is_connected) {

      {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "Welcome to the Peer CLI!\n";
        std::cout << "Choose mode:\n";
        std::cout << "1. Client\n";
      }

      int mode;
      std::cin >> mode;
      
      if (mode == 1) {
        std::string remote_ip;
        {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "Enter the server IP: ";
        }
        std::cin >> remote_ip;
        connectToPeer(remote_ip.c_str());
        {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "Connected to server at " << remote_ip << ":" << port << "\n";
        }
      } else {
        {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cerr << "Invalid mode selected. Exiting...\n";
        }
        return;
      }
    } else {

      print_commands_options();

      int choice;
      std::cin >>choice;

      // Validate input
      if (std::cin.fail()) {
          std::cin.clear(); // Clear the error flag
          std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Discard invalid input
          {
              std::lock_guard<std::mutex> lock(cout_mutex);
              std::cerr << "Invalid choice. Please try again.\n";
          }
          continue;
      }

      if (choice == 1) {
          // Send a message
          std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Clear the newline character
          std::string message;
          {
              std::lock_guard<std::mutex> lock(cout_mutex);
              std::cout << "Enter your message: ";
          }
          std::getline(std::cin, message);
          sendMessage(message);
      } else if (choice == 2) {
          // Send a file
          std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Clear the newline character
          std::string file_path;
          {
              std::lock_guard<std::mutex> lock(cout_mutex);
              std::cout << "Enter the file path: ";
          }
          std::getline(std::cin, file_path);
          sendFile(file_path);
      } else if (choice == 3) {
          {
              std::lock_guard<std::mutex> lock(cout_mutex);
              std::cout << "Exiting...\n";
          }
          endConnection();
          break;
      } else {
          {
              std::lock_guard<std::mutex> lock(cout_mutex);
              std::cerr << "Invalid choice. Please try again.\n";
          }
      }
    }

      
    //   // Non-blocking input
    //   while (true) {
    //       {
    //           std::lock_guard<std::mutex> lock(exiting_mutex);
    //           if (exiting) break; // Exit the loop if the `exiting` flag is set
    //       }

    //       if (std::cin.peek() != EOF) { // Check if input is available
    //           std::cin >> choice;
    //           break;
    //       }

    //       // Sleep briefly to avoid busy-waiting
    //       std::this_thread::sleep_for(std::chrono::milliseconds(100));
    //   }

    // {
    //     std::lock_guard<std::mutex> lock(exiting_mutex);
    //     if (exiting) break; // Exit the loop if the `exiting` flag is set
    // }
      // // Validate input
      // if (std::cin.fail()) {
      //     std::cin.clear(); // Clear the error flag
      //     std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Discard invalid input
      //     {
      //         std::lock_guard<std::mutex> lock(cout_mutex);
      //         std::cerr << "Invalid choice. Please try again.\n";
      //     }
      //     continue;
      // }

      // if (choice == 1) {
      //     // Send a message
      //     std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Clear the newline character
      //     std::string message;
      //     {
      //         std::lock_guard<std::mutex> lock(cout_mutex);
      //         std::cout << "Enter your message: ";
      //     }
      //     std::getline(std::cin, message);
      //     sendMessage(message);
      // } else if (choice == 2) {
      //     // Send a file
      //     std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Clear the newline character
      //     std::string file_path;
      //     {
      //         std::lock_guard<std::mutex> lock(cout_mutex);
      //         std::cout << "Enter the file path: ";
      //     }
      //     std::getline(std::cin, file_path);
      //     sendFile(file_path);
      // } else if (choice == 3) {
      //     {
      //         std::lock_guard<std::mutex> lock(cout_mutex);
      //         std::cout << "Exiting...\n";
      //     }
      //     endConnection();
      //     break;
      // } else {
      //     {
      //         std::lock_guard<std::mutex> lock(cout_mutex);
      //         std::cerr << "Invalid choice. Please try again.\n";
      //     }
      // }

    // {
    //   std::lock_guard<std::mutex> lock(is_connected_mutex);
    //   var_is_connected = this->is_connected;
    // }

  }

  // Wait for the listener thread to finish
  if (listener_thread.joinable()) {
      listener_thread.join();
  }

  // Wait for the message printer thread to finish
  if (message_printer_thread.joinable()) {
      message_printer_thread.detach(); // Detach the thread to allow it to exit independently
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  exit(0);
}

//-------------------------------------------------------------------------------------------------------
void Peer::ensureDataFolderExists() {

    // Check if the folder exists
    if (!std::filesystem::exists(folder_name)) {
        // Create the folder
        if (mkdir(folder_name.c_str(), 0777) == 0) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "Folder 'data' created successfully.\n";
        } else {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "Error: Could not create folder 'data'.\n";
        }
    }else {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout<<"Folder exists.\n";
    }
}

//-------------------------------------------------------------------------------------------------------
// I need to use this function in setting up the ip address, currently I use constants;
// I need to not use the port as a hard codded value
std::string Peer::getLocalIPAddress() const {
    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return "";
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;

        if (ifa->ifa_addr->sa_family == AF_INET) { // Check for IPv4
            if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                            host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST) == 0) {
                if (std::string(ifa->ifa_name) != "lo") { // Skip loopback interface
                    freeifaddrs(ifaddr);
                    return std::string(host);
                }
            }
        }
    }

    freeifaddrs(ifaddr);
    return "";
}