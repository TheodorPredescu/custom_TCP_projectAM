#ifndef MISSINGPACKETSEXCEPTION_H
#define MISSINGPACKETSEXCEPTION_H

#include <exception>
#include <vector>
#include <cstdint>

class MissingPacketsException : public std::exception {
public:
  MissingPacketsException(const std::vector<uint16_t>& missingPackets, bool isFirstPacketMissing)
      : missingPackets_(missingPackets), isFirstPacketMissing_(isFirstPacketMissing) {}

  const char* what() const noexcept override {
    return "Missing packets detected.";
  }

  const std::vector<uint16_t>& getMissingPackets() const {
    return missingPackets_;
  }

  bool isFirstPacketMissing() const {
    return isFirstPacketMissing_;
  }

private:
  std::vector<uint16_t> missingPackets_;
  bool isFirstPacketMissing_;
};

#endif // MISSINGPACKETSEXCEPTION_H