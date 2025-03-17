// CustomPacket.h
#ifndef CUSTOM_PACKET_H
#define CUSTOM_PACKET_H

#include <cstdint>
#include <cstring>
#include <iostream>

struct CustomPacket {
  uint16_t packet_id;
  uint8_t flags = 0;
  uint16_t length;
  char payload[256];
  uint16_t checksum;

  uint16_t calculateChecksum(const CustomPacket &packet);
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
};

#endif // CUSTOM_PACKET_H
