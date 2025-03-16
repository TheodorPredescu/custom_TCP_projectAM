#include <cstdint> // For uint8_t, uint16_t
#include <cstring> // For memcpy
#include <iostream>

// flags:
// bit7  bit6    bit5      bit4       bit3       bit2        bit1        bit0
// enc   ---  msg_type  start_trans  end_trans   serialize     ACK       URGENT
//
//
// msg_type: 0 text, 1 file
//  Define Packet Structure
struct CustomPacket {
  uint16_t packet_id; // 2 bytes
  uint8_t flags = 0;
  uint16_t length;   // 2 bytes
  char payload[256]; // Fixed-size payload (can be dynamic)
  uint16_t checksum; // 2 bytes

  uint16_t calculateChecksum(const CustomPacket &packet) {
    uint32_t sum = 0;
    const uint8_t *data = reinterpret_cast<const uint8_t *>(&packet);

    for (size_t i = 0; i < sizeof(packet) - sizeof(packet.checksum); ++i) {
      sum += data[i];
    }

    return static_cast<uint16_t>(sum & 0xFFFF);
  }

  // Serialize packet to raw bytes
  void serialize(uint8_t *buffer) {
    memcpy(buffer, this, sizeof(CustomPacket));
  }

  // Deserialize raw bytes to packet
  static CustomPacket deserialize(const uint8_t *buffer) {
    CustomPacket packet;
    memcpy(&packet, buffer, sizeof(CustomPacket));
    return packet;
  }

  // Extract message type from flagsT
  uint8_t getMsgType() const {
    return (flags >> 2) & 0x01; // Extract msg_type from the flags byte
  }

  // Set message type in flags
  void setMsgType(uint8_t msgType) {

    if (msgType == 0) {
      flags &= ~0x04; // Clear bit 2 (00000100) to set msgType to 0 (text)
    } else if (msgType == 1) {
      flags |= 0x04; // Set bit 2 (00000100) to set msgType to 1 (file)
    } else {
      std::cout << "Invalid msgType value!! Only 0 and 1 accepted.\n";
    }
  }

  //
  void setClose_transmision() {}
};

// Example usage
int main() {
  // Create a test packet
  CustomPacket packet;
  packet.packet_id = 1;
  packet.flags = 0; // Text message
  std::cout << (int)packet.flags << std::endl;
  packet.setMsgType(1); // File
  std::cout << (int)packet.flags << std::endl;

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
