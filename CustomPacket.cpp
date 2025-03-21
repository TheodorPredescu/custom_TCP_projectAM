
// CustomPacket.cpp
#include "CustomPacket.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <string>
#include <sys/types.h>

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
    std::cerr << "Invalid msgType value!! Only 0 and 1 accepted.\n";
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

// Fragment a message into multiple packets
// It does add packed id because it was needed (switched to map)
// It does add checksumm so that all is done here
std::map<u_int16_t, CustomPacket>
CustomPacket::fragmentMessage(const std::string &message,
                              u_int16_t &packet_id) {

  std::map<u_int16_t, CustomPacket> packets;
  size_t maxPayloadSize = 256;
  size_t totalLength = message.size();
  size_t offset = 0;
  bool first_package = true;

  // Calculating the number of packets that will be needed to be send for this
  // message
  int number_of_packages_to_be_sended =
      (totalLength + maxPayloadSize - 1) / maxPayloadSize;

  // Creating the first packet that contains the size of the big message; It
  // will have 2 flags on : serialize and start transmition flag
  if (number_of_packages_to_be_sended > 1) {
    CustomPacket start_packet;

    start_packet.set_start_transmition_flag();
    start_packet.set_serialize_flag();

    std::string length_ser = std::to_string(number_of_packages_to_be_sended);
    memcpy(start_packet.payload, length_ser.data(), length_ser.length());

    // increment the packed_id so that it does not repeat
    packet_id += 1;
    if (packet_id >= UINT16_MAX) {
      std::cerr << "Warning: Packet ID overflow. Resetting...\n";
      packet_id = 0;
    }
    start_packet.packet_id = packet_id;
    start_packet.checksum = start_packet.calculateChecksum(start_packet);

    packets[packet_id] = start_packet;
  }

  while (offset < totalLength) {

    CustomPacket packet;
    // packet.packet_id = id_last_package++;
    //
    // // checking if the value of id_last_package excedes the max value
    // if (id_last_package >= UINT16_MAX) {
    //   std::cerr << "Warning: Packet ID overflow. Resetting...\n";
    //   id_last_package = 1;
    // }

    // copying in memory in the current packet.payload the message string
    size_t length = std::min(maxPayloadSize, totalLength - offset);
    memcpy(packet.payload, message.data() + offset, length);

    // Setting length
    packet.length = length;

    offset += length;

    if (number_of_packages_to_be_sended > 1) {
      packet.set_serialize_flag();
    }

    if (offset >= totalLength) {
      packet.set_end_transmition_flag(); // Last packet
    }

    packet_id += 1;
    if (packet_id >= UINT16_MAX) {
      std::cerr << "Warning: Packet ID overflow. Resetting...\n";
      packet_id = 0;
    }

    packet.packet_id = packet_id;
    packet.checksum = packet.calculateChecksum(packet);
    packets[packet_id] = packet;
  }

  return packets;
}

// Checks if there is a start and end to this map and if the number of elements
// given in the first packet is the same with the number of elements received;
std::string CustomPacket::composedMessage(
    const std::map<uint16_t, CustomPacket> &receivedPackets) {
  int expectedPacketCount = -1; // Unknown initially
  int receivedPacketCount = 0;
  uint16_t startPacketId = 0;
  bool hasEndPacket = false;

  for (const auto &pair : receivedPackets) {
    const CustomPacket &packet = pair.second; // Access the packet from the map

    // If we find a start packet, extract the expected number of packets
    if (packet.get_start_transmition_flag()) {
      std::string countStr(packet.payload, packet.length);
      try {
        expectedPacketCount = std::stoi(countStr);
      } catch (...) {
        std::cerr << "Error: Invalid start packet format.\n";
        return "";
      }
      startPacketId = packet.packet_id; // Store its ID
      continue;                         // Do not add start packet to the map
    }

    receivedPacketCount++;

    if (packet.get_end_transmition_flag()) {
      hasEndPacket = true;
    }
  }

  // Ensure we received all expected packets
  if (expectedPacketCount == -1 || receivedPacketCount < expectedPacketCount ||
      !hasEndPacket) {
    std::cerr << "Error: Missing packets or end flag not received.\n";
    return "";
  }

  // Now, reconstruct the message
  std::string message;
  for (const auto &pair : receivedPackets) {
    const CustomPacket &packet = pair.second;
    message.append(packet.payload, packet.length);
  }

  return message;
}
