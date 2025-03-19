
// CustomPacket.cpp
#include "CustomPacket.h"

uint16_t CustomPacket::calculateChecksum(const CustomPacket &packet) {
  uint32_t sum = 0;
  const uint8_t *data = reinterpret_cast<const uint8_t *>(&packet);
  for (size_t i = 0; i < sizeof(packet) - sizeof(packet.checksum); ++i) {
    sum += data[i];
  }
  return static_cast<uint16_t>(sum & 0xFFFF);
}

void CustomPacket::serialize(uint8_t *buffer) const {
  memcpy(buffer, this, sizeof(CustomPacket));
}

CustomPacket CustomPacket::deserialize(const uint8_t *buffer) {
  CustomPacket packet;
  memcpy(&packet, buffer, sizeof(CustomPacket));
  return packet;
}

// SETS CONTEXT TYPE: MESSAGE OR FILE
// 0 for msg and 1 for file
bool CustomPacket::getMsgType() const { return (bool)((flags >> 5) & 0x01); }

void CustomPacket::setMsgType(int msgType) {
  // clears it if msgType = 0 -> text
  if (msgType == 0) {
    flags &= ~0x20;

    // or it sets it to 1 the 5th bit(starting from 0) if the package is part of
    // a file
  } else if (msgType == 1) {
    flags |= 0x20;
  } else {
    std::cout << "Invalid msgType value!! Only 0 and 1 accepted.\n";
  }
}

// start transmition flag -> the 4th bit
void CustomPacket::set_start_transmition_flag() { flags |= 0x10; }
bool CustomPacket::get_start_transmition_flag() const {
  return (flags & 0x10) != 0;
}

// end transmition flag the 3rd bit
void CustomPacket::set_end_transmition_flag() { flags |= 0x08; }
bool CustomPacket::get_end_transmition_flag() const {
  return (flags & 0x08) != 0;
}

// serialize bit flag; the 2nd bit
void CustomPacket::set_serialize_flag() { flags |= 0x04; }
bool CustomPacket::get_serialize_flag() const { return (flags & 0x04) != 0; }

// acknowledgement flag; the 1st bit
void CustomPacket::set_ack_flag() { flags |= 0x02; }
bool CustomPacket::get_ack_flag() const { return (flags & 0x02) != 0; }

// urgent flag -> check and set; the 0th bit
void CustomPacket::set_urgent_flag() { flags |= 0x01; }
bool CustomPacket::get_urgent_flag() const { return (flags & 0x01) != 0; }

// Fragment a message into multiple packets if necessary
std::vector<CustomPacket> CustomPacket::fragmentMessage(const std::string &message, const uint16_t id_last_package) {
    std::vector<CustomPacket> packets;
    size_t maxPayloadSize = 256;
    size_t totalLength = message.size();
    size_t offset = 0;
    bool first_package = true;

    while (offset < totalLength) {
        CustomPacket packet;

        if (first_package) {
          first_package = false;
          
        }
        size_t length = std::min(maxPayloadSize, totalLength - offset);
        memcpy(packet.payload, message.data() + offset, length);
        packet.set_serialize_flag(); // Mark as fragmented
        offset += length;

        if (offset >= totalLength) {
            packet.set_end_transmition_flag(); // Last packet
        }
        packets.push_back(packet);
    }
    return packets;
}
