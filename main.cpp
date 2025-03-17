#include "CustomPacket.h"
#include <cstdint> // For uint8_t, uint16_t
#include <cstring> // For memcpy
#include <iostream>

// flags:
// bit7  bit6    bit5      bit4       bit3       bit2        bit1 bit0 enc
// ---  msg_type  start_trans  end_trans   serialize     ACK       URGENT
//
//
// msg_type: 0 text, 1 file
//  Define Packet Structure

// Example usage
int main() {
  // Create a test packet
  CustomPacket packet;
  packet.packet_id = 1;
  // packet.flags = 0; // Text message

  std::cout << packet.getMsgType() << std::endl;
  packet.setMsgType(1); // File
  std::cout << packet.getMsgType() << std::endl;

  std::cout << packet.get_ack_flag() << std::endl;
  packet.set_ack_flag();
  std::cout << packet.get_ack_flag() << std::endl;

  std::cout << packet.get_end_transmition_flag() << std::endl;
  packet.set_end_transmition_flag();
  std::cout << packet.get_end_transmition_flag() << std::endl;

  std::cout << packet.get_start_transmition_flag() << std::endl;
  packet.set_start_transmition_flag();
  std::cout << packet.get_start_transmition_flag() << std::endl;

  std::cout << packet.get_urgent_flag() << std::endl;
  packet.set_urgent_flag();
  std::cout << packet.get_urgent_flag() << std::endl;

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

  return 0;
}
