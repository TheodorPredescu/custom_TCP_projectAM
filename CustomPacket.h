// CustomPacket.h
#ifndef CUSTOM_PACKET_H
#define CUSTOM_PACKET_H

#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <sys/types.h>
#include <vector>

// flags:
// bit7| bit6 |   bit5  |    bit4    |   bit3   | bit2  |bit1 |  bit0
// enc |error |msg_type |start_trans |end_trans |series |ACK  |URGENT

// msg_type: 0 text, 1 file
// to fully ask for end of transmition we send URGENT bit and end_trans bit
// to end a serialised message (string or file) we need to have the
// end_trans bit on and the series bit on END TRANS IS NOT ONLY FOR THE
// FULLY END OF TRANSMITION !!!! TO REMIND MYSELF

struct CustomPacket {
  uint16_t packet_id;
  uint8_t flags = 0;
  uint16_t length;
  char payload[256];
  uint16_t checksum;

  static std::map<u_int16_t, CustomPacket>
  fragmentMessage(const std::string &message, u_int16_t &packet_id, const bool &is_file = false);
  static std::string
  composedMessage(std::map<uint16_t, CustomPacket> &map_packets);
  static void incrementPacketId(uint16_t &packet_id);

  uint16_t calculateChecksum() const;
  void serialize(uint8_t *buffer) const;
  static CustomPacket deserialize(const uint8_t *buffer);
  bool getMsgType() const;
  void setMsgType(int msgType);
  void set_start_transmition_flag();
  bool get_start_transmition_flag() const;
  void set_end_transmition_flag();
  bool get_end_transmition_flag() const;
  void set_serialize_flag();
  bool get_serialize_flag() const;
  void set_ack_flag();
  bool get_ack_flag() const;
  void set_urgent_flag();
  bool get_urgent_flag() const;
  void set_error_flag();
  bool get_error_flag() const;

  //debug
  void printFlags() const;

;
};

#endif
