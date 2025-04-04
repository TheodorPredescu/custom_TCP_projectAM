// CustomPacket.cpp
#include "CustomPacket.h"
#include "MissingPacketsException.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <sys/types.h>
#include <bitset>

// Added function for increment because i was repeating myself
void CustomPacket::incrementPacketId(uint16_t &packet_id) {
  packet_id += 1;
  if (packet_id >= UINT16_MAX - 1) {
    std::cerr << "Warning: Packet ID overflow. Resetting...\n";
    packet_id = 0;
  }
}

uint16_t CustomPacket::calculateChecksum() const{
  uint32_t sum = 0;
  const uint8_t *data = reinterpret_cast<const uint8_t *>(this);
  for (size_t i = 0; i < sizeof(*this) - sizeof(this->checksum); ++i) {
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

// error flag (the one that will contain missing packets)
void CustomPacket::set_error_flag() {flags |= 0x01 << 5;}
bool CustomPacket::get_error_flag() const {return (flags & (0x01 << 5)) != 0;}

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

//---------------------------------------------------------------------------
// Fragment a message into multiple packets
// It does add packet id because it was needed (switched to map)
// It does add checksumm so that all is done here
std::map<u_int16_t, CustomPacket>
CustomPacket::fragmentMessage(const std::string &message,
                              u_int16_t &packet_id) {

  std::map<u_int16_t, CustomPacket> packets;
  size_t maxPayloadSize = 256;
  size_t totalLength = message.size() + 1;
  size_t offset = 0;

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
    start_packet.payload[length_ser.length()] = '\0'; // Add null terminator
    start_packet.length = length_ser.length() + 1; // Include null terminator in length

    CustomPacket::incrementPacketId(packet_id);
    start_packet.packet_id = packet_id;

    start_packet.checksum = start_packet.calculateChecksum();

    packets[packet_id] = start_packet;
  }

  while (offset < totalLength) {

    CustomPacket packet;

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
      // packet.payload[length] = '\0';
      // packet.length += 1;
    }

    // packet_id += 1;
    // if (packet_id >= UINT16_MAX) {
    //   std::cerr << "Warning: Packet ID overflow. Resetting...\n";
    //   packet_id = 0;
    // }

    CustomPacket::incrementPacketId(packet_id);
    packet.packet_id = packet_id;
    packet.checksum = packet.calculateChecksum();
    packets[packet_id] = packet;
  }

  return packets;
}

//---------------------------------------------------------------------------------
// Checks if there is a start and end to this map and if the number of elements
// given in the first packet is the same with the number of elements received;
std::string CustomPacket::composedMessage(
    std::map<uint16_t, CustomPacket> &receivedPackets) {

  int expectedPacketCount = -1; // Unknown initially
  int receivedPacketCount = 0;
  uint16_t startPacketId = 0;
  bool hasEndPacket = false;

  // For the request back of the packages that did not make it
  std::vector<uint16_t> not_received_packages;

  for (auto it = receivedPackets.begin(); it != receivedPackets.end();) {
    const CustomPacket &packet = it->second;


    //we recalculate checksum and check if it has the same value
    if (packet.calculateChecksum() != packet.checksum) {
      std::cerr << "\nPacket with id: " << it->first << " has been compromised!\n\n";
      it = receivedPackets.erase(it);
      continue;

    }

    // If we find a start packet, extract the expected number of packets
    if (packet.get_start_transmition_flag()) {
      std::string countStr(packet.payload, packet.length - 1);
      std::cout<<"\n\nCountStr: "<<countStr<<", Of size: "<<countStr.length()<<std::endl;
      try {
        expectedPacketCount = std::stoi(countStr);
      } catch (...) {
        std::cerr << "Error: Invalid start packet format.\n";
        throw std::runtime_error("Invalid start packet format");
      }
      startPacketId = packet.packet_id; // Store its ID
      ++it;
      continue;                         // Do not add start packet to the map
    }

    receivedPacketCount++;

    if (packet.get_end_transmition_flag()) {
      hasEndPacket = true;
    }

    ++it;
  }

  std::cout << "Expected Packet Count: " << expectedPacketCount
            << ", Received Packet Count: " << receivedPacketCount
            << ", Has End Packet: " << std::boolalpha << hasEndPacket
            << ", hasEndPacket: " << hasEndPacket << std::endl;

  // Ensure we received all expected packets; care that if we have a short message
  // we will not have a start, end and serialise flag, and only the packetid
  if (expectedPacketCount == -1 || receivedPacketCount != expectedPacketCount ||
      !hasEndPacket) {
    std::cerr << "Error: Missing packets or end flag not received.\n";
    // throw MissingPacketsException(not_received_packages, expectedPacketCount == -1);
  }

  if (expectedPacketCount == -1) {
    std::cerr << "Error: No starting packet\n\t"
          "It is needed a starting packet to know the dimention of the message!!!\n"
          "\tSending request for a new starting packet.\n\n";
    throw MissingPacketsException(not_received_packages, true);
  }

  // Now, reconstruct the message
  std::string message;
  uint16_t i = startPacketId;

  for (const auto &pair : receivedPackets) {
    const CustomPacket &packet = pair.second;

    if (packet.packet_id != startPacketId){
      if (packet.get_end_transmition_flag()) {
        message.append(packet.payload, packet.length - 1);
      }else {
        message.append(packet.payload, packet.length);
      }
    }

    // TODO: Recheck for infinite loop; Carefull for later
    while (i != pair.first) {
      not_received_packages.push_back(i);
      CustomPacket::incrementPacketId(i);
      if (i == startPacketId) break;
    }

    CustomPacket::incrementPacketId(i);
  }

  //We try to use try catch first, waiting for results and trying new things
  if (!not_received_packages.empty()) {
    throw MissingPacketsException(not_received_packages, false);
  }

  return message;
}

void CustomPacket::printFlags() const {
  std::cout << "Flags (binary): " << std::bitset<8>(static_cast<unsigned int>(flags)) << "\n";
  std::cout << "  Encryption (enc): " << ((flags & (1 << 7)) != 0) << "\n";
  std::cout << "  Error: " << get_error_flag() << "\n";
  std::cout << "  Message Type (msg_type): " << getMsgType() << "\n";
  std::cout << "  Start Transmission (start_trans): " << get_start_transmition_flag() << "\n";
  std::cout << "  End Transmission (end_trans): " << get_end_transmition_flag() << "\n";
  std::cout << "  Serialize (series): " << get_serialize_flag() << "\n";
  std::cout << "  Acknowledgment (ACK): " << get_ack_flag() << "\n";
  std::cout << "  Urgent: " << get_urgent_flag() << "\n";
}