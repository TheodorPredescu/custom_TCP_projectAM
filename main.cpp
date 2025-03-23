#include "CustomPacket.h"
#include <cstdint> // For uint8_t, uint16_t
#include <cstring> // For memcpy
#include <iostream>
#include <map>

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
  strcpy(packet.payload, "Hello, custom protocol!");
  packet.length = strlen(packet.payload);
  packet.checksum = packet.calculateChecksum(packet);

  // Serialize packet
  uint8_t buffer[sizeof(CustomPacket)];
  packet.serialize(buffer);

  // Deserialize packet
  CustomPacket received = CustomPacket::deserialize(buffer);

  // Print received packet details
  std::cout << "Received Packet ID: " << received.packet_id << "\n";
  std::cout << "Message Type: " << (int)received.getMsgType() << "\n";
  std::cout << "Payload: " << received.payload << "\n";
  std::cout << "Checksum: " << received.checksum << "\n";

  // Verify the deserialized packet
  if (received.packet_id == packet.packet_id &&
      received.getMsgType() == packet.getMsgType() &&
      strcmp(received.payload, packet.payload) == 0 &&
      received.checksum == packet.checksum) {
    std::cout << "Test passed: Packet serialization and deserialization are correct.\n";
  } else {
    std::cout << "Test failed: Packet serialization and deserialization are incorrect.\n";
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

  // Compose the message from fragmented packets
  std::string composed_message = CustomPacket::composedMessage(fragmented_packets);

  // Print the composed message
  std::cout << "\n\nComposed Message: " << composed_message << "\n";
  std::cout << "Composed Message size: " << composed_message.length() << "\n";

  // Verify the composed message
  if (composed_message == long_message) {
    std::cout << "Test passed: Message fragmentation and composition are correct.\n";
  } else {
    std::cout << "Test failed: Message fragmentation and composition are incorrect.\n\n";
    std::cout << "Composed Message:\n";
    for (size_t i = 0; i < composed_message.size(); ++i) {
      std::cout << composed_message[i] << " (" << static_cast<int>(composed_message[i]) << ") ";
    }
    std::cout << "\n\nOriginal Message:\n";
    for (size_t i = 0; i < long_message.size(); ++i) {
      std::cout << long_message[i] << " (" << static_cast<int>(long_message[i]) << ") ";
    }
    std::cout << "\n";
    std::cout << "Composed Message size: " << composed_message.size() << "\n";
    std::cout << "Original Message size: " << long_message.size() << "\n";
  }
}

int main() {
  // Test flag manipulation
  CustomPacket packet;
  packet.packet_id = 1;
  print_and_verify_bits0_5(packet);

  // Test packet serialization and deserialization
  test_packet_serialization();

  // Test message fragmentation and composition
  std::cout<<std::endl<<std::endl;
  test_fragment_and_compose_message();

  return 0;
}
