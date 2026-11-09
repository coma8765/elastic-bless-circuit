#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <chrono>
#include <curl/curl.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <regex>
#include <set>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <yaml-cpp/yaml.h>
using J = nlohmann::json;
namespace fs = std::filesystem;
static volatile sig_atomic_t stopping = 0;
static void stop(int) { stopping = 1; }
static std::string read(const std::string &p) {
  std::ifstream f(p);
  if (!f)
    throw std::runtime_error("cannot read " + p);
  return {std::istreambuf_iterator<char>(f), {}};
}
static std::string secret(const YAML::Node &n) {
  auto s = read(n.as<std::string>());
  while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
    s.pop_back();
  return s;
}
static J jsonyaml(const YAML::Node &n) {
  if (!n || n.IsNull())
    return nullptr;
  if (n.IsMap()) {
    J j = J::object();
    for (auto it : n)
      j[it.first.as<std::string>()] = jsonyaml(it.second);
    return j;
  }
  if (n.IsSequence()) {
    J j = J::array();
    for (auto it : n)
      j.push_back(jsonyaml(it));
    return j;
  }
  auto s = n.Scalar();
  if (n.Tag() == "!" || n.Tag() == "tag:yaml.org,2002:str")
    return s;
  if (s == "true")
    return true;
  if (s == "false")
    return false;
  if (std::regex_match(s, std::regex("-?(0|[1-9][0-9]*)")))
    return std::stoll(s);
  return s;
}
static pid_t launch(const std::vector<std::string> &args, bool quiet = false) {
  pid_t p = fork();
  if (p < 0)
    throw std::runtime_error("fork failed");
  if (!p) {
    if (quiet) {
      const auto sink = open("/dev/null", O_WRONLY);
      if (sink < 0 || dup2(sink, STDOUT_FILENO) < 0 ||
          dup2(sink, STDERR_FILENO) < 0)
        _exit(127);
      close(sink);
    }
    std::vector<char *> av;
    for (auto &s : args)
      av.push_back(const_cast<char *>(s.c_str()));
    av.push_back(nullptr);
    execvp(av[0], av.data());
    _exit(127);
  }
  return p;
}
static int run(const std::vector<std::string> &args, bool quiet = false) {
  auto p = launch(args, quiet);
  int s = 0;
  pid_t waited;
  do {
    waited = waitpid(p, &s, 0);
  } while (waited < 0 && errno == EINTR);
  if (waited < 0)
    throw std::runtime_error("waitpid failed");
  return WIFEXITED(s) ? WEXITSTATUS(s) : 128;
}
static void terminate(pid_t p) {
  if (p <= 0)
    return;
  kill(p, SIGTERM);
  for (int i = 0; i < 50; i++) {
    auto waited = waitpid(p, nullptr, WNOHANG);
    if (waited == p || (waited < 0 && errno == ECHILD))
      return;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  kill(p, SIGKILL);
  waitpid(p, nullptr, 0);
}
static void atomic(const fs::path &p, const std::string &value) {
  auto tmp = p.string() + ".tmp";
  {
    std::ofstream f(tmp);
    f << value;
    f.flush();
    if (!f)
      throw std::runtime_error("write failed");
  }
  int fd = open(tmp.c_str(), O_RDONLY);
  if (fd < 0 || fsync(fd) < 0) {
    if (fd >= 0)
      close(fd);
    throw std::runtime_error("fsync failed");
  }
  close(fd);
  fs::rename(tmp, p);
  int dir = open(p.parent_path().c_str(), O_RDONLY | O_DIRECTORY);
  if (dir >= 0) {
    fsync(dir);
    close(dir);
  }
}
static size_t receive(char *p, size_t a, size_t b, void *ctx) {
  auto &s = *static_cast<std::string *>(ctx);
  if (s.size() + a * b > 16 * 1024 * 1024)
    return 0;
  s.append(p, a * b);
  return a * b;
}
static J request(CURL *c, const std::string &url,
                 const std::string &post = "") {
  std::string body;
  curl_easy_setopt(c, CURLOPT_URL, url.c_str());
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, receive);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, &body);
  curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 5L);
  curl_easy_setopt(c, CURLOPT_TIMEOUT, 15L);
  curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L);
  curl_easy_setopt(c, CURLOPT_POST, post.empty() ? 0L : 1L);
  if (!post.empty())
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, post.c_str());
  auto rc = curl_easy_perform(c);
  long code = 0;
  curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
  if (rc != CURLE_OK || code != 200)
    throw std::runtime_error("panel request failed (HTTP " +
                             std::to_string(code) + ")");
  auto j = J::parse(body);
  if (!j.value("success", false))
    throw std::runtime_error("panel rejected request");
  return j;
}
static J panel(const YAML::Node &c) {
  auto p = c["panel"];
  auto url = p["url"].as<std::string>();
  if (url.rfind("https://", 0) != 0 && !p["allow_http"].as<bool>(false))
    throw std::runtime_error("panel requires HTTPS");
  static std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> h(
      nullptr, curl_easy_cleanup);
  static std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headers(
      nullptr, curl_slist_free_all);
  static std::string session_url, session_user, session_pass;
  auto user = secret(p["username_file"]), pass = secret(p["password_file"]);
  if (session_url != url || session_user != user || session_pass != pass) {
    h.reset();
    headers.reset();
  }
  J reply;
  try {
    if (!h) {
      h.reset(curl_easy_init());
      if (!h)
        throw std::runtime_error("curl init failed");
      CURL *raw = h.get();
      curl_easy_setopt(raw, CURLOPT_COOKIEFILE, "");
      auto token =
          request(raw, url + "/csrf-token").at("obj").get<std::string>();
      headers.reset(
          curl_slist_append(nullptr, ("X-CSRF-Token: " + token).c_str()));
      curl_easy_setopt(raw, CURLOPT_HTTPHEADER, headers.get());
      char *u = curl_easy_escape(raw, user.c_str(), 0);
      char *pw = curl_easy_escape(raw, pass.c_str(), 0);
      if (!u || !pw) {
        curl_free(u);
        curl_free(pw);
        throw std::runtime_error("credential encoding failed");
      }
      std::string form = "username=" + std::string(u) + "&password=" + pw;
      curl_free(u);
      curl_free(pw);
      request(raw, url + "/login", form);
      session_url = url;
      session_user = user;
      session_pass = pass;
    }
    reply = request(h.get(), url + "/panel/api/inbounds/get/" +
                                 p["inbound_id"].as<std::string>());
  } catch (...) {
    h.reset();
    headers.reset();
    throw;
  }
  auto in = reply.at("obj");
  if (in.at("protocol") != "vless")
    throw std::runtime_error("panel inbound must be VLESS");
  J result = J::array();
  if (in.value("total", int64_t(0)) > 0)
    throw std::runtime_error("inbound quotas require central accounting");
  auto inbound_expiry = in.value("expiryTime", int64_t(0));
  if (!in.at("enable").get<bool>() ||
      (inbound_expiry > 0 &&
       inbound_expiry <=
           std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
               .count()))
    return result;
  auto settings = in.at("settings");
  if (settings.is_string())
    settings = J::parse(settings.get<std::string>());
  if (settings.value("decryption", std::string("none")) != "none")
    throw std::runtime_error("panel VLESS encryption is unsupported");
  auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                 std::chrono::system_clock::now().time_since_epoch())
                 .count();
  for (auto client : settings.at("clients")) {
    if (!client.value("enable", true))
      continue;
    auto expiry = client.value("expiryTime", int64_t(0));
    if (expiry > 0 && expiry <= now)
      continue;
    // Negative expiry means panel first-use activation: unsupported without
    // traffic feedback.
    if (expiry < 0)
      throw std::runtime_error(
          "first-use expiry requires central traffic accounting");
    if (client.value("limitIp", 0) > 0 || client.value("limitHwid", 0) > 0)
      throw std::runtime_error("device limits require central accounting");
    if (client.value("totalGB", int64_t(0)) > 0)
      throw std::runtime_error(
          "traffic quotas require central traffic accounting");
    result.push_back({{"id", client.at("id")},
                      {"email", client.at("email")},
                      {"expiryTime", expiry},
                      {"flow", in.value("disableFlow", false)
                                   ? std::string()
                                   : client.value("flow", std::string())}});
  }
  return result;
}
static void uuid(const std::string &s) {
  if (!std::regex_match(
          s, std::regex("[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")))
    throw std::runtime_error("invalid UUID");
}
static bool mesh_ipv4(const std::string &address) {
  in_addr addr{};
  return inet_pton(AF_INET, address.c_str(), &addr) == 1 &&
         (ntohl(addr.s_addr) & 0xffc00000U) == 0x64400000U;
}
static int port(const YAML::Node &n) {
  const auto value = n.as<int>();
  if (value < 1 || value > 65535)
    throw std::runtime_error("port must be in 1..65535");
  return value;
}
static int mesh_udp_port(const YAML::Node &c) {
  const auto mesh = c["mesh"];
  return mesh && mesh["udp_port"] ? port(mesh["udp_port"]) : 41641;
}
static bool dns_hostname(const std::string &name) {
  if (name.empty() || name.size() > 253 || name.find('*') != std::string::npos)
    return false;
  static const std::regex label(
      "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?");
  size_t begin = 0;
  while (begin < name.size()) {
    auto end = name.find('.', begin);
    if (end == std::string::npos)
      end = name.size();
    if (!std::regex_match(name.substr(begin, end - begin), label))
      return false;
    begin = end + 1;
  }
  return name.back() != '.';
}
static bool ip_literal(const std::string &name) {
  in_addr ipv4{};
  in6_addr ipv6{};
  return inet_pton(AF_INET, name.c_str(), &ipv4) == 1 ||
         inet_pton(AF_INET6, name.c_str(), &ipv6) == 1;
}
static void reality_stream(const YAML::Node &c, J &stream) {
  if (stream.value("security", "none") != "reality")
    return;
  const auto network = stream.value("network", "tcp");
  if (network != "tcp" && network != "raw")
    throw std::runtime_error("REALITY ingress currently requires TCP/RAW");
  auto settings = c["listener"]["stream"]["realitySettings"];
  if (!settings || !settings.IsMap() || !settings["private_key_file"])
    throw std::runtime_error(
        "REALITY requires realitySettings.private_key_file");
  auto &reality = stream["realitySettings"];
  if (reality.contains("privateKey"))
    throw std::runtime_error(
        "use private_key_file instead of an inline REALITY private key");
  const auto key = secret(settings["private_key_file"]);
  if (!std::regex_match(key, std::regex("[A-Za-z0-9_-]{43}")))
    throw std::runtime_error(
        "REALITY private key must be a raw URL-base64 X25519 key");
  const auto target = reality.value("target", std::string());
  const auto separator = target.rfind(':');
  if (separator == std::string::npos || separator == 0 ||
      separator + 1 == target.size())
    throw std::runtime_error(
        "REALITY target must be hostname:port or [IPv6]:port");
  const auto host = target.substr(0, separator),
             service = target.substr(separator + 1);
  in6_addr ipv6{};
  if (!dns_hostname(host) &&
      !(host.front() == '[' && host.back() == ']' &&
        inet_pton(AF_INET6, host.substr(1, host.size() - 2).c_str(), &ipv6) ==
            1))
    throw std::runtime_error("REALITY target hostname is invalid");
  if (!std::regex_match(service, std::regex("[0-9]{1,5}")) ||
      std::stoi(service) < 1 || std::stoi(service) > 65535)
    throw std::runtime_error("REALITY target port must be in 1..65535");
  if (!reality.contains("serverNames") || !reality["serverNames"].is_array() ||
      reality["serverNames"].empty())
    throw std::runtime_error("REALITY requires at least one serverName");
  for (const auto &name : reality["serverNames"])
    if (!name.is_string() || !dns_hostname(name.get<std::string>()) ||
        ip_literal(name.get<std::string>()))
      throw std::runtime_error(
          "REALITY serverNames must be exact nonempty DNS names");
  if (!reality.contains("shortIds") || !reality["shortIds"].is_array() ||
      reality["shortIds"].empty())
    throw std::runtime_error("REALITY requires at least one shortId");
  std::set<std::string> short_ids;
  for (const auto &value : reality["shortIds"]) {
    if (!value.is_string())
      throw std::runtime_error("REALITY shortIds must be quoted hex strings");
    auto id = value.get<std::string>();
    if (id.size() > 16 || id.size() % 2 != 0 ||
        !std::regex_match(id, std::regex("[0-9a-fA-F]*")))
      throw std::runtime_error(
          "REALITY shortIds must contain 0..16 even-length hex characters");
    std::transform(id.begin(), id.end(), id.begin(), [](unsigned char ch) {
      return static_cast<char>(std::tolower(ch));
    });
    id.resize(16, '0');
    if (!short_ids.insert(id).second)
      throw std::runtime_error("duplicate REALITY shortId");
  }
  reality.erase("private_key_file");
  reality["privateKey"] = key;
}
static J render(const YAML::Node &c, const J &users) {
  std::string role = c["role"].as<std::string>();
  if (role != "in" && role != "out")
    throw std::runtime_error("role must be in or out");
  if (!users.is_array())
    throw std::runtime_error("users must be an array");
  J root = {{"log", {{"loglevel", "warning"}}},
            {"inbounds", J::array()},
            {"outbounds", J::array()}};
  J stream = c["listener"]["stream"]
                 ? jsonyaml(c["listener"]["stream"])
                 : J{{"network", "tcp"}, {"security", "none"}};
  if (role == "in" && stream.value("security", "none") != "tls" &&
      stream.value("security", "none") != "reality" &&
      !c["allow_insecure_lab"].as<bool>(false))
    throw std::runtime_error("public listener requires TLS or REALITY");
  reality_stream(c, stream);
  auto address = c["listener"]["address"].as<std::string>();
  if (address == "mesh")
    address = read("/run/mesh-ip");
  while (!address.empty() && address.back() == '\n')
    address.pop_back();
  if (role == "out" && !c["allow_insecure_lab"].as<bool>(false) &&
      !mesh_ipv4(address))
    throw std::runtime_error(
        "out listener must bind mesh IPv4 in 100.64.0.0/10");
  J clients = J::array(), rules = J::array();
  std::set<std::string> ids, emails, exits;
  if (role == "out") {
    auto id = secret(c["transit_uuid_file"]);
    uuid(id);
    clients.push_back({{"id", id}});
    root["outbounds"].push_back({{"tag", "internet"},
                                 {"protocol", "freedom"},
                                 {"settings", J::object()}});
    if (c["allow_private_destinations"].as<bool>(false))
      root["outbounds"][0]["settings"]["finalRules"] = J::array(
          {{{"action", "allow"}, {"ip", J::array({"geoip:private"})}}});
    if (!c["allow_private_destinations"].as<bool>(false))
      rules.push_back({{"type", "field"},
                       {"ip", J::array({"geoip:private"})},
                       {"outboundTag", "block"}});
  } else {
    // Default deny: there is deliberately no direct internet outbound on
    // ingress.
    root["outbounds"].push_back({{"tag", "block"}, {"protocol", "blackhole"}});
    if (!c["exits"] || !c["exits"].IsSequence() || c["exits"].size() == 0)
      throw std::runtime_error("ingress requires at least one exit");
    size_t transit_index = 0;
    for (auto e : c["exits"]) {
      auto name = e["name"].as<std::string>();
      if (name.empty() || name == "block")
        throw std::runtime_error("exit name is empty or reserved");
      if (!exits.insert(name).second)
        throw std::runtime_error("duplicate exit");
      if (!c["allow_insecure_lab"].as<bool>(false) &&
          !mesh_ipv4(e["address"].as<std::string>()))
        throw std::runtime_error("transit exit must use a mesh IPv4 address");
      auto id = secret(e["uuid_file"]);
      uuid(id);
      auto transit_address = e["address"].as<std::string>();
      in_addr transit_ip{};
      const bool mesh_transit = mesh_ipv4(transit_address) && c["mesh"] &&
                                c["mesh"]["enabled"].as<bool>(true);
      if (inet_pton(AF_INET, transit_address.c_str(), &transit_ip) == 1) {
        // Xray rejects plaintext VLESS to CGNAT literals, even when WireGuard
        // already encrypts the transport. Resolve a private synthetic name
        // exclusively through this pinned hosts entry; no external DNS lookup.
        const auto domain =
            "transit-" + std::to_string(transit_index) + ".mesh.invalid";
        root["dns"]["hosts"][domain] = transit_address;
        transit_address = domain;
      }
      ++transit_index;
      root["outbounds"].push_back(
          {{"tag", name},
           {"protocol", "vless"},
           {"settings",
            {{"vnext",
              J::array({{{"address", transit_address},
                         {"port", port(e["port"])},
                         {"users", J::array({{{"id", id},
                                              {"encryption", "none"}}})}}})}}},
           {"streamSettings",
            {{"network", "tcp"},
             {"security", "none"},
             {"sockopt", {{"domainStrategy", "UseIPv4"}}}}}});
      if (mesh_transit)
        root["outbounds"].back()["streamSettings"]["sockopt"]["interface"] =
            "tailscale0";
    }
    for (auto u : users) {
      auto expiry = u.value("expiryTime", int64_t(0));
      if (expiry > 0 &&
          expiry <= std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count())
        continue;
      auto id = u.at("id").get<std::string>(),
           email = u.at("email").get<std::string>();
      uuid(id);
      std::transform(id.begin(), id.end(), id.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
      });
      if (email.empty() || !ids.insert(id).second ||
          !emails.insert(email).second)
        throw std::runtime_error("duplicate or empty user identity");
      auto route = c["routes"][email];
      if (!route)
        throw std::runtime_error("user has no explicit route: " + email);
      auto exit = route.as<std::string>();
      if (!exits.count(exit))
        throw std::runtime_error("unknown exit");
      const auto flow = u.value("flow", std::string());
      if (!flow.empty() && flow != "xtls-rprx-vision")
        throw std::runtime_error("unsupported VLESS flow");
      if (!flow.empty() && ((stream.value("security", "none") != "tls" &&
                             stream.value("security", "none") != "reality") ||
                            (stream.value("network", "tcp") != "tcp" &&
                             stream.value("network", "tcp") != "raw")))
        throw std::runtime_error(
            "Vision flow requires TCP with TLS or REALITY");
      clients.push_back({{"id", id}, {"email", email}, {"flow", flow}});
      rules.push_back({{"type", "field"},
                       {"user", J::array({email})},
                       {"outboundTag", exit}});
    }
  }
  if (role == "out")
    root["outbounds"].push_back({{"tag", "block"}, {"protocol", "blackhole"}});
  root["inbounds"].push_back(
      {{"tag", "vless"},
       {"listen", address},
       {"port", port(c["listener"]["port"])},
       {"protocol", "vless"},
       {"settings", {{"clients", clients}, {"decryption", "none"}}},
       {"streamSettings", stream}});
  root["routing"] = {{"domainStrategy", "IPIfNonMatch"}, {"rules", rules}};
  return root;
}
static void mesh(const YAML::Node &c) {
  auto m = c["mesh"];
  if (!m || !m["enabled"].as<bool>(true))
    return;
  auto server = m["server"].as<std::string>();
  if (server.rfind("https://", 0) != 0 &&
      !c["allow_insecure_lab"].as<bool>(false))
    throw std::runtime_error("Headscale requires HTTPS");
  if (run({"tailscale", "up", "--login-server=" + server,
           "--auth-key=file:" + m["auth_key_file"].as<std::string>(),
           "--hostname=" + m["hostname"].as<std::string>(),
           "--accept-dns=false", "--accept-routes=false", "--timeout=60s"}))
    throw std::runtime_error("mesh enrollment failed");
  // Redirection without a shell; file contains only the selected mesh IPv4.
  auto p = fork();
  if (p == 0) {
    if (!freopen("/run/mesh-ip", "w", stdout))
      _exit(127);
    execlp("tailscale", "tailscale", "ip", "-4", nullptr);
    _exit(127);
  }
  if (p < 0)
    throw std::runtime_error("fork failed");
  int s = 0;
  waitpid(p, &s, 0);
  if (s)
    throw std::runtime_error("mesh IP unavailable");
}
int main(int argc, char **argv) {
  try {
    if (argc < 3)
      throw std::runtime_error("usage: node-agent render|run|control|mesh-port "
                               "config.yaml [users.json]");
    umask(0077);
    curl_global_init(CURL_GLOBAL_DEFAULT);
    auto c = YAML::LoadFile(argv[2]);
    if (std::string(argv[1]) == "mesh-port") {
      std::cout << mesh_udp_port(c) << '\n';
      return 0;
    }
    if (std::string(argv[1]) == "render") {
      J users = argc > 3 ? J::parse(read(argv[3])) : jsonyaml(c["users"]);
      if (users.is_null())
        users = J::array();
      std::cout << render(c, users).dump(2) << '\n';
      return 0;
    }
    if (std::string(argv[1]) == "control") {
      signal(SIGTERM, stop);
      signal(SIGINT, stop);
      mesh(c);
      fs::create_directories("/run/node");
      auto settings = c["panel_settings"];
      if (!fs::exists("/etc/x-ui/.provisioned")) {
        // An imported database already owns its credentials and settings.
        // Provision only a fresh volume, never reset an existing installation.
        if (!fs::exists("/etc/x-ui/x-ui.db") &&
            run({"/app/x-ui", "setting", "-username",
                 secret(settings["username_file"]), "-password",
                 secret(settings["password_file"]), "-port",
                 settings["port"].as<std::string>(), "-webBasePath",
                 settings["base_path"].as<std::string>("/")},
                true))
          throw std::runtime_error("panel initialization failed");
        atomic("/etc/x-ui/.provisioned", "provisioned\n");
      }
      pid_t child = launch({"/app/x-ui"});
      while (!stopping) {
        if (waitpid(child, nullptr, WNOHANG) == child)
          return 1;
        atomic("/run/node/ready", "ready\n");
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
      }
      fs::remove("/run/node/ready");
      terminate(child);
      return 0;
    }
    if (std::string(argv[1]) != "run")
      throw std::runtime_error("unknown command");
    signal(SIGTERM, stop);
    signal(SIGINT, stop);
    mesh(c);
    fs::create_directories("/run/node");
    fs::create_directories("/var/lib/node");
    pid_t child = -1;
    std::string active;
    int interval = c["sync_seconds"].as<int>(15);
    if (interval < 1 || interval > 3600)
      throw std::runtime_error("invalid sync interval");
    const auto max_stale = c["max_stale_seconds"].as<int>(86400);
    if (max_stale < 0 || max_stale > 604800)
      throw std::runtime_error("max_stale_seconds must be in 0..604800");
    while (!stopping) {
      try {
        J users;
        bool fresh = false;
        if (c["panel"]) {
          try {
            users = panel(c);
            render(c, users);
            fresh = true;
          } catch (const std::exception &e) {
            std::cerr << "panel sync unavailable: " << e.what() << '\n';
            if (!fs::exists("/var/lib/node/users.json") && active.empty())
              throw;
            // An unreadable cache must not bypass the stale-data ceiling by
            // keeping an already running instance alive indefinitely.
            users = J::array();
            try {
              auto cached = J::parse(read("/var/lib/node/users.json"));
              auto age =
                  std::chrono::duration_cast<std::chrono::seconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count() -
                  cached.at("saved").get<int64_t>();
              if (age >= 0 && age < max_stale) {
                auto candidate_users = cached.at("users");
                render(c, candidate_users);
                users = std::move(candidate_users);
              }
            } catch (const std::exception &cache_error) {
              if (active.empty())
                throw;
              std::cerr << "cache unusable; denying cached users: "
                        << cache_error.what() << '\n';
            }
          }
        } else
          users = jsonyaml(c["users"]);
        if (users.is_null())
          users = J::array();
        auto candidate = render(c, users).dump(2);
        if (candidate != active) {
          atomic("/run/node/candidate.json", candidate);
          if (run({"xray", "run", "-test", "-config",
                   "/run/node/candidate.json"}))
            throw std::runtime_error("Xray rejected candidate");
          fs::remove("/run/node/ready");
          terminate(child);
          child = -1;
          fs::rename("/run/node/candidate.json", "/run/node/config.json");
          child = launch({"xray", "run", "-config", "/run/node/config.json"});
          active = candidate;
          std::cerr << "configuration applied\n";
        }
        if (fresh) {
          auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
          atomic("/var/lib/node/users.json",
                 J{{"saved", now}, {"users", users}}.dump());
        }
      } catch (const std::exception &e) {
        if (!active.empty() && child <= 0)
          throw;
        std::cerr << "sync failed; retaining active configuration: " << e.what()
                  << '\n';
      }
      for (int i = 0; i < interval * 10 && !stopping; i++) {
        if (child > 0 && waitpid(child, nullptr, WNOHANG) == child) {
          std::cerr << "Xray exited unexpectedly\n";
          fs::remove("/run/node/ready");
          return 1;
        }
        if (child > 0)
          atomic("/run/node/ready", "ready\n");
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }
    fs::remove("/run/node/ready");
    terminate(child);
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "fatal: " << e.what() << '\n';
    return 1;
  }
}
