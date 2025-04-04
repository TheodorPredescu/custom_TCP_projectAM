#include <cstdint> // For uint8_t, uint16_t
#include <cstring> // For memcpy
#include <iostream>
#include <map>
#include <vector>
#include <thread>
#include <chrono>
#include <mutex>
#include <condition_variable>

#include "CustomPacket.h"
#include "MissingPacketsException.h"
#include "Peer.h"

std::mutex cout_mutex;

// flags:
// bit7  bit6    bit5      bit4       bit3       bit2        bit1   bit0 
// enc ---  msg_type  start_trans  end_trans   series     ACK       URGENT
//
//
// msg_type: 0 text, 1 file
//  Define Packet Structure

void print_and_verify_bits0_5(CustomPacket packet) {
  std::cout << "Initial MsgType: " << packet.getMsgType() << std::endl;
  packet.setMsgType(1); // File
  std::cout << "Updated MsgType: " << packet.getMsgType() << std::endl;

  std::cout << "Initial ACK flag: " << packet.get_ack_flag() << std::endl;
  packet.set_ack_flag();
  std::cout << "Updated ACK flag: " << packet.get_ack_flag() << std::endl;

  std::cout << "Initial End Transmission flag: " << packet.get_end_transmition_flag() << std::endl;
  packet.set_end_transmition_flag();
  std::cout << "Updated End Transmission flag: " << packet.get_end_transmition_flag() << std::endl;

  std::cout << "Initial Start Transmission flag: " << packet.get_start_transmition_flag() << std::endl;
  packet.set_start_transmition_flag();
  std::cout << "Updated Start Transmission flag: " << packet.get_start_transmition_flag() << std::endl;

  std::cout << "Initial Urgent flag: " << packet.get_urgent_flag() << std::endl;
  packet.set_urgent_flag();
  std::cout << "Updated Urgent flag: " << packet.get_urgent_flag() << std::endl;
}

void test_packet_serialization() {
  // Create a test packet
  CustomPacket packet;
  packet.packet_id = 1;
  packet.setMsgType(0); // Text message
  packet.set_ack_flag();
  packet.set_start_transmition_flag();
  strcpy(packet.payload, "Hello, custom protocol!"); // Set payload
  packet.length = strlen(packet.payload);           // Set length
  packet.checksum = packet.calculateChecksum();     // Calculate checksum

  // Print the original packet details
  std::cout << "Original Packet Details:\n";
  std::cout << "Packet ID: " << packet.packet_id << "\n";
  std::cout << "Message Type: " << (int)packet.getMsgType() << "\n";
  std::cout << "Payload: " << packet.payload << "\n";
  std::cout << "Length: " << packet.length << "\n";
  std::cout << "Checksum: " << packet.checksum << "\n";
  packet.printFlags();

  // Serialize the packet
  uint8_t buffer[sizeof(CustomPacket)];
  packet.serialize(buffer);

  // Deserialize the packet
  CustomPacket received = CustomPacket::deserialize(buffer);

  // Print the deserialized packet details
  std::cout << "\nDeserialized Packet Details:\n";
  std::cout << "Packet ID: " << received.packet_id << "\n";
  std::cout << "Message Type: " << (int)received.getMsgType() << "\n";
  std::cout << "Payload: " << received.payload << "\n";
  std::cout << "Length: " << received.length << "\n";
  std::cout << "Checksum: " << received.checksum << "\n";
  received.printFlags();

  // Verify the deserialized packet
  if (received.packet_id == packet.packet_id &&
      received.getMsgType() == packet.getMsgType() &&
      strcmp(received.payload, packet.payload) == 0 &&
      received.length == packet.length &&
      received.checksum == packet.checksum) {
    std::cout << "\nTest passed: Packet serialization and deserialization are correct.\n";
  } else {
    std::cout << "\nTest failed: Packet serialization and deserialization are incorrect.\n";
  }
}

void test_fragment_and_compose_message() {
  // Create a long message to be fragmented
  std::string long_message = "Site-ul are în pagina (pagina textit) două butoare disponibile extit șiextit, al doilea "
                             "fiind pentru crearea de utilizator nou al aplicației (orice utilizator va trebui să-și facă cont pentru a putea cumpăra bilete), "
                             "iar primul pentru a te conecta la un cont deja existent. "
                             "Pentru conectarea la un cont este nevoie doar de textitși de textit{parola} contului. Conectarea la un cont ne va oferi "
                             "posibilitatea de a vizualiza istoricul biletelor cumpărate (dacă există), cursele ce vor avea loc și lista locurilor libere din avion. "
                             "Prin apăsarea pe un loc liber, acel bilet va fi adaugat în coșul utilizatorului. Această acțiune poate fi repetată pentru posibilitatea "
                             "cumpărării a multiple bilete simultan. "
                             "Dacă în coș se află cel puțin un bilet, vor apărea două butoane: textit{} și textit{}, ce vor oferi posibilitatea de a șterge din coșul "
                             "curent biletul selectat, dar și de a finaliza cumpărarea, adăugând biletele în istoric și golind coșul.";
  uint16_t packet_id = 0;

  // Fragment the message
  std::map<uint16_t, CustomPacket> fragmented_packets = CustomPacket::fragmentMessage(long_message, packet_id);

  // Print fragmented packets
  std::cout << "Fragmented Packets:\n";
  for (const auto &pair : fragmented_packets) {
    const CustomPacket &packet = pair.second;
    std::cout << "Packet ID: " << packet.packet_id << ", Payload: " << packet.payload << ", Checksum: " << packet.checksum << ", length: "<< packet.length<<"\n\n";
  }

  // fragmented_packets.erase(2);
  if (fragmented_packets.find(2) != fragmented_packets.end()){
    fragmented_packets[2].checksum = 1243;
  }
  std::cout << "Fragmented Packets:\n";
  for (const auto &pair : fragmented_packets) {
    const CustomPacket &packet = pair.second;
    std::cout << "Packet ID: " << packet.packet_id << ", Payload: " << packet.payload << ", Checksum: " << packet.checksum << ", length: "<< packet.length<<"\n\n";
  }


  try {
  // Compose the message from fragmented packets
  std::string composed_message = CustomPacket::composedMessage(fragmented_packets);

  // Print the composed message
  std::cout << "\n\nComposed Message: " << composed_message << "\n";
  std::cout << "Composed Message size: " << composed_message.length() << "\n";


  } catch (const MissingPacketsException& e) {
    std::cerr <<"Error: " << e.what() <<std::endl;
    const std::vector<uint16_t>& missing_packets = e.getMissingPackets();

    for (const uint16_t missing_packet_id : missing_packets) {
      std::cout<<missing_packet_id << std::endl;
    }

  }catch (const std::exception& e) {
    std::cerr<<"Error: " << e.what()<<std::endl;
  }

  // // Verify the composed messag se
  // if (composed_message == long_message) {
  //   std::cout << "Test passed: Message fragmentation and composition are correct.\n";
  // } else {
  //   std::cout << "Test failed: Message fragmentation and composition are incorrect.\n\n";
  //   std::cout << "Composed Message:\n";
  //   for (size_t i = 0; i < composed_message.size(); ++i) {
  //     std::cout << composed_message[i] << " (" << static_cast<int>(composed_message[i]) << ") ";
  //   }
  //   std::cout << "\n\nOriginal Message:\n";
  //   for (size_t i = 0; i < long_message.size(); ++i) {
  //     std::cout << long_message[i] << " (" << static_cast<int>(long_message[i]) << ") ";
  //   }
  //   std::cout << "\n";
  //   std::cout << "Composed Message size: " << composed_message.size() << "\n";
  //   std::cout << "Original Message size: " << long_message.size() << "\n";
  // }
}

void test_peer_class() {
  // Mutex and condition variable for thread synchronization
  std::mutex sync_mutex;
  std::condition_variable server_ready_cv;
  bool server_ready = false;

  // Mutex for thread-safe output
  std::mutex cout_mutex;

  // Peer 1: Server
  std::thread server_thread([&]() {
    Peer server_peer;
    {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout << "Starting server peer on port 8080...\n";
    }

    // Start the server
    server_peer.startPeer(8080);

    // Notify the client that the server is ready
    {
      std::lock_guard<std::mutex> lock(sync_mutex);
      server_ready = true;
    }
    server_ready_cv.notify_one();

    // Keep the server running
    std::this_thread::sleep_for(std::chrono::seconds(10)); // Simulate server activity
  });

  // Peer 2: Client
  std::thread client_thread([&]() {
    {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout << "Client thread started.\n";
    }

    // Wait for the server to be ready
    {
      std::unique_lock<std::mutex> lock(sync_mutex);
      server_ready_cv.wait(lock, [&]() { return server_ready; });
    }

    Peer client_peer;
    {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout << "Starting client peer...\n";
    }

    // Start the client and send a message
    client_peer.startPeer(8080, "127.0.0.1");
    client_peer.sendMessage("Hello from client!");
    std::this_thread::sleep_for(std::chrono::seconds(3));
    client_peer.sendMessage("Hello again!");
  });

  // Wait for both threads to finish
  server_thread.join();
  client_thread.join();

  {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "Peer test completed.\n";
  }
}

int main() {
  // Test flag manipulation
  CustomPacket packet;
  packet.packet_id = 1;
  // print_and_verify_bits0_5(packet);

  // Test packet serialization and deserialization
  // test_packet_serialization();

  // Test message fragmentation and composition
  // std::cout<<std::endl<<std::endl;
  // test_fragment_and_compose_message();


  test_peer_class();

  return 0;
}
