#pragma once

#include <string>

class Rlogin {
public:
  static bool session(std::string host, int port, std::string luser, std::string ruser, std::string termtype, bool ipv6);
};
