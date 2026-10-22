#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

#include "httplib.h"

int main(int argc, char **argv) {
  if (argc != 3) {
    std::cerr << "usage: fixture PORT ROOT\n";
    return 2;
  }

  httplib::Server server;
  server.Get("/delay", [](const httplib::Request &request,
                           httplib::Response &response) {
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    auto tag = request.has_param("tag") ? request.get_param_value("tag") : "";
    response.set_header("X-Attacker-Tag", tag);
    response.set_content("ATTACKER-" + tag, "text/plain");
  });
  server.Get("/victim", [](const httplib::Request &, httplib::Response &response) {
    response.set_content("VICTIM-OWN", "text/plain");
  });
  if (!server.set_mount_point("/", argv[2])) {
    std::cerr << "failed to mount root\n";
    return 1;
  }
  std::cout << "cpp_httplib_fixture_listening=" << argv[1] << std::endl;
  return server.listen("127.0.0.1", std::atoi(argv[1])) ? 0 : 1;
}
