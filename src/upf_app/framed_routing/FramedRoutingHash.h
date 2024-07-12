//
// Created by root on 6/25/24.
//

#pragma once

// todo(kw) maybe call it subnet or similar
struct FramedRoutingKey {
  uint32_t networkAdress{};
  uint32_t subnet{};

  bool operator==(const FramedRoutingKey& other) const {
    return (networkAdress == other.networkAdress && subnet == other.subnet);
  }
};

template<>
struct std::hash<FramedRoutingKey> {
  std::size_t operator()(const FramedRoutingKey& k) const {
    std::size_t hash = 17;
    hash *= std::hash<uint32_t>()(k.networkAdress);
    return hash ^ std::hash<uint32_t>()(k.subnet);
  }
};