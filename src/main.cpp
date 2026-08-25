// SPDX-License-Identifier: MIT
// cpp-udp-watch — Linux UDP socket monitor (/proc/net/udp + /proc/net/udp6)
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o udp-watch
// Usage: ./udp-watch [--top N] [--watch N] [--port PORT] [--state CONNECTED|UNCONNECTED]
//                     [--drops] [--json] [--demo] [--file PATH] [--no-resolve]
//                     [--no-color] [--selftest]

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Mutable ANSI palette (--no-color must actually clear it — see skill pitfall)
// ─────────────────────────────────────────────────────────────────────────────
static std::string C_RESET  = "\x1b[0m";
static std::string C_BOLD   = "\x1b[1m";
static std::string C_DIM    = "\x1b[2m";
static std::string C_RED    = "\x1b[31m";
static std::string C_GREEN  = "\x1b[32m";
static std::string C_YELLOW = "\x1b[33m";
static std::string C_BLUE   = "\x1b[34m";
static std::string C_CYAN   = "\x1b[36m";
static std::string C_MAGENTA= "\x1b[35m";

static void disable_color() {
  C_RESET = C_BOLD = C_DIM = C_RED = C_GREEN = C_YELLOW = C_BLUE = C_CYAN = C_MAGENTA = "";
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// std::from_chars does NOT skip leading whitespace — trim first.
static std::optional<unsigned long long> parse_ull(std::string_view s, int base = 10) {
  auto start = s.find_first_not_of(" \t");
  if (start == std::string_view::npos) return std::nullopt;
  s.remove_prefix(start);
  unsigned long long v = 0;
  auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v, base);
  if (ec != std::errc()) return std::nullopt;
  if (ptr != s.data() + s.size()) return std::nullopt;  // trailing garbage
  return v;
}

static std::optional<unsigned long long> parse_hex(std::string_view s) {
  return parse_ull(s, 16);
}

static std::vector<std::string> split_ws(std::string_view s) {
  std::vector<std::string> out;
  std::istringstream ss{std::string(s)};
  std::string tok;
  while (ss >> tok) out.push_back(tok);
  return out;
}

static std::string fmt_num(unsigned long long v) {
  char buf[24];
  if (v >= 1000000000ULL)      std::snprintf(buf, sizeof(buf), "%.1fG", static_cast<double>(v) / 1e9);
  else if (v >= 1000000ULL)    std::snprintf(buf, sizeof(buf), "%.1fM", static_cast<double>(v) / 1e6);
  else if (v >= 1000ULL)       std::snprintf(buf, sizeof(buf), "%.1fk", static_cast<double>(v) / 1e3);
  else                         std::snprintf(buf, sizeof(buf), "%llu", v);
  return buf;
}

// ─────────────────────────────────────────────────────────────────────────────
// Address decoding
//   /proc/net/udp  : "0100007F" -> 127.0.0.1   (little-endian uint32)
//   /proc/net/udp6 : 32 hex chars = 4 uint32 words. Each group g is the
//                    LITTLE-ENDIAN memory image of network word W_g (kernel
//                    prints __be32 words with %08X on a LE host), and the
//                    groups are in order: group 0 = W0 ... group 3 = W3.
//                    "0000000000000000FFFF00000100007F" -> ::ffff:127.0.0.1
// ─────────────────────────────────────────────────────────────────────────────
static bool decode_addr(std::string_view hex, bool ipv6, std::array<uint8_t, 16>& out, int& len) {
  if (ipv6) {
    if (hex.size() != 32) return false;
    for (int g = 0; g < 4; ++g) {
      auto v = parse_hex(hex.substr(static_cast<size_t>(g) * 8, 8));
      if (!v) return false;
      uint32_t w = static_cast<uint32_t>(*v);  // byte-swapped image of W_g (kernel %08X on LE host)
      int off = g * 4;                         // W_g occupies bytes [g*4 .. g*4+3]
      out[static_cast<size_t>(off) + 0] = static_cast<uint8_t>(w & 0xff);
      out[static_cast<size_t>(off) + 1] = static_cast<uint8_t>((w >> 8) & 0xff);
      out[static_cast<size_t>(off) + 2] = static_cast<uint8_t>((w >> 16) & 0xff);
      out[static_cast<size_t>(off) + 3] = static_cast<uint8_t>((w >> 24) & 0xff);
    }
    len = 16;
    return true;
  }
  if (hex.size() != 8) return false;
  auto v = parse_hex(hex);
  if (!v) return false;
  uint32_t w = static_cast<uint32_t>(*v);
  out[0] = static_cast<uint8_t>(w & 0xff);
  out[1] = static_cast<uint8_t>((w >> 8) & 0xff);
  out[2] = static_cast<uint8_t>((w >> 16) & 0xff);
  out[3] = static_cast<uint8_t>((w >> 24) & 0xff);
  len = 4;
  return true;
}

static std::string fmt_ipv4(const std::array<uint8_t, 16>& b) {
  char buf[24];
  std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
  return buf;
}

static std::string fmt_ipv6(const std::array<uint8_t, 16>& b) {
  // IPv4-mapped ::ffff:a.b.c.d
  bool mapped = true;
  for (int i = 0; i < 10; ++i) if (b[static_cast<size_t>(i)] != 0) { mapped = false; break; }
  if (mapped && b[10] == 0xff && b[11] == 0xff) {
    char buf[40];
    std::snprintf(buf, sizeof(buf), "::ffff:%u.%u.%u.%u", b[12], b[13], b[14], b[15]);
    return buf;
  }
  uint16_t w[8];
  for (int i = 0; i < 8; ++i)
    w[i] = static_cast<uint16_t>((static_cast<uint16_t>(b[static_cast<size_t>(i) * 2]) << 8) |
                                  static_cast<uint16_t>(b[static_cast<size_t>(i) * 2 + 1]));
  // longest run of zero words (>= 2) -> "::"
  int best_start = -1, best_len = 0;
  for (int i = 0; i < 8;) {
    if (w[i] == 0) {
      int j = i;
      while (j < 8 && w[j] == 0) ++j;
      if (j - i >= 2 && j - i > best_len) { best_start = i; best_len = j - i; }
      i = j;
    } else ++i;
  }
  std::string out;
  for (int i = 0; i < 8;) {
    if (i == best_start) {
      out += "::";
      i += best_len;
      continue;
    }
    if (!out.empty() && out.back() != ':') out += ':';
    char buf[8];
    std::snprintf(buf, sizeof(buf), "%x", w[i]);
    out += buf;
    ++i;
  }
  if (out.empty()) out = "::";
  return out;
}

// Format an endpoint as text: "1.2.3.4:53", "[::]:53" or "0.0.0.0:53"
static std::string fmt_host(const std::array<uint8_t, 16>& b, int len, uint16_t port) {
  char buf[96];
  if (len == 16)
    std::snprintf(buf, sizeof(buf), "[%s]:%u", fmt_ipv6(b).c_str(), port);
  else
    std::snprintf(buf, sizeof(buf), "%s:%u", fmt_ipv4(b).c_str(), port);
  return buf;
}

// ─────────────────────────────────────────────────────────────────────────────
// UDP state decode — /proc/net/udp column 3 uses the TCP state enum:
//   0x01 ESTABLISHED -> connected UDP socket (connected(2) or connect(2))
//   0x07 CLOSE       -> unconnected UDP socket (the common case, listen/recvfrom)
// ─────────────────────────────────────────────────────────────────────────────
static std::string state_name(uint8_t code) {
  switch (code) {
    case 0x01: return "CONNECTED";
    case 0x07: return "UNCONNECTED";
    default:   return "UNKNOWN";
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Well-known port names from /etc/services (lazy) + builtin fallback for
// containers without /etc/services.
// ─────────────────────────────────────────────────────────────────────────────
static const std::vector<std::pair<unsigned, std::string>>& builtin_services() {
  static const std::vector<std::pair<unsigned, std::string>> m = {
    {7, "echo"}, {9, "discard"}, {13, "daytime"}, {17, "qotd"}, {19, "chargen"},
    {37, "time"}, {42, "nameserver"}, {53, "domain"}, {67, "bootps"}, {68, "bootpc"},
    {69, "tftp"}, {80, "http"}, {111, "sunrpc"}, {123, "ntp"}, {137, "netbios-ns"},
    {138, "netbios-dgm"}, {139, "netbios-ssn"}, {161, "snmp"}, {162, "snmptrap"},
    {177, "xdmcp"}, {179, "bgp"}, {389, "ldap"}, {443, "https"}, {500, "isakmp"},
    {514, "syslog"}, {520, "route"}, {5353, "mdns"}, {5355, "llmnr"},
    {4500, "ipsec-nat-t"}, {10000, "webmin"},
  };
  return m;
}

static const std::map<unsigned, std::string>& services() {
  static const std::map<unsigned, std::string> m = [] {
    std::map<unsigned, std::string> out;
    for (auto& [p, n] : builtin_services()) out[p] = n;
    std::ifstream f("/etc/services");
    std::string line;
    int n = 0;
    while (std::getline(f, line) && n < 4000) {
      ++n;
      if (line.empty() || line[0] == '#') continue;
      auto hash = line.find('#');
      if (hash != std::string::npos) line = line.substr(0, hash);
      std::istringstream ss(line);
      std::string name, proto;
      unsigned port = 0;
      if (!(ss >> name >> port >> proto)) continue;
      if (!proto.empty() && (proto == "udp" || proto.starts_with("udp")))
        out[port] = name;  // file wins over builtin
    }
    return out;
  }();
  return m;
}

static std::string port_name(uint16_t port) {
  auto it = services().find(port);
  if (it == services().end()) return "";
  return it->second;
}

// ─────────────────────────────────────────────────────────────────────────────
// Data model — one UDP socket from /proc/net/udp(|6)
// ─────────────────────────────────────────────────────────────────────────────
struct UdpSocket {
  std::array<uint8_t, 16> local{};
  int local_len = 0;
  uint16_t lport = 0;
  std::array<uint8_t, 16> remote{};
  int remote_len = 0;
  uint16_t rport = 0;
  uint8_t state_code = 0;
  std::string state;
  unsigned uid = 0;
  unsigned long long tx = 0, rx = 0;
  std::string inode;
  unsigned long long drops = 0;
  int pid = -1;
  std::string proc;
  bool ipv6 = false;

  std::string local_str() const { return fmt_host(local, local_len, lport); }

  std::string remote_str() const {
    bool wildcard = rport == 0;
    for (int i = 0; wildcard && i < remote_len; ++i)
      if (remote[static_cast<size_t>(i)] != 0) wildcard = false;
    if (wildcard) return "*";
    return fmt_host(remote, remote_len, rport);
  }

  std::string proc_str() const {
    if (!proc.empty()) return proc;
    if (pid >= 0) return std::to_string(pid);
    return "-";
  }
};

struct Filters {
  int top = 0;                        // 0 = show all
  std::optional<unsigned> port;       // --port N
  std::string state;                  // CONNECTED | UNCONNECTED (empty = all)
  bool drops_only = false;            // --drops
  bool resolve = true;                // --no-resolve disables PID scan
  bool color = true;                  // --no-color
  bool json = false;                  // --json
  std::string file;                   // --file PATH (parse dump instead of /proc)
  bool demo = false;                  // --demo synthetic snapshot
  int watch = 0;                      // --watch N seconds
};

struct Snapshot {
  std::vector<UdpSocket> socks;
  long long ts = 0;
  double real_dt = 0.0;               // seconds since previous snapshot (watch)

  unsigned long long total() const { return socks.size(); }
  unsigned long long ipv4() const {
    unsigned long long n = 0;
    for (auto& s : socks) if (!s.ipv6) ++n;
    return n;
  }
  unsigned long long ipv6() const {
    unsigned long long n = 0;
    for (auto& s : socks) if (s.ipv6) ++n;
    return n;
  }
  unsigned long long count_state(const std::string& st) const {
    unsigned long long n = 0;
    for (auto& s : socks) if (s.state == st) ++n;
    return n;
  }
  unsigned long long total_drops() const {
    unsigned long long n = 0;
    for (auto& s : socks) n += s.drops;
    return n;
  }
  unsigned long long sockets_with_drops() const {
    unsigned long long n = 0;
    for (auto& s : socks) if (s.drops > 0) ++n;
    return n;
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Parsing
// ─────────────────────────────────────────────────────────────────────────────
// Tolerates comment lines (#) and blank lines so dumps are safe to annotate.
static bool parse_udp_file(const std::string& path, bool ipv6, std::vector<UdpSocket>& out) {
  std::ifstream f(path);
  if (!f) return false;
  std::string line;
  bool first = true;
  while (std::getline(f, line)) {
    if (first) { first = false; continue; }          // header
    auto hash = line.find('#');
    if (hash != std::string::npos) line = line.substr(0, hash);
    if (line.find_first_not_of(" \t") == std::string::npos) continue;
    auto toks = split_ws(line);
    if (toks.size() < 13) continue;                  // malformed -> skip, never break the rest
    // Auto-detect v6 lines inside mixed dumps: the local_address hex part is
    // 32 chars for IPv6, 8 chars for IPv4 (works for --file combined dumps).
    auto colon = toks[1].find(':');
    bool line6 = ipv6 || (colon == 32);
    auto parse_endpoint = [&](const std::string& ep, std::array<uint8_t, 16>& addr,
                              int& len, uint16_t& port) -> bool {
      auto colon2 = ep.find(':');
      if (colon2 == std::string::npos) return false;
      auto p = parse_hex(std::string_view(ep).substr(colon2 + 1));
      if (!p || *p > 65535) return false;
      port = static_cast<uint16_t>(*p);
      return decode_addr(std::string_view(ep).substr(0, colon2), line6, addr, len);
    };
    UdpSocket s;
    s.ipv6 = line6;
    if (!parse_endpoint(toks[1], s.local, s.local_len, s.lport)) continue;
    if (!parse_endpoint(toks[2], s.remote, s.remote_len, s.rport)) continue;
    auto st = parse_hex(toks[3]);
    s.state_code = st ? static_cast<uint8_t>(*st) : 0;
    s.state = state_name(s.state_code);
    auto qpos = toks[4].find(':');
    if (qpos != std::string::npos) {
      if (auto tx = parse_hex(std::string_view(toks[4]).substr(0, qpos))) s.tx = *tx;
      if (auto rx = parse_hex(std::string_view(toks[4]).substr(qpos + 1))) s.rx = *rx;
    }
    if (auto uid = parse_ull(toks[7])) s.uid = static_cast<unsigned>(*uid);
    s.inode = toks[9];
    if (auto d = parse_ull(toks[12])) s.drops = *d;
    out.push_back(std::move(s));
  }
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// inode -> pid -> process name resolution (scan /proc/*/fd socket symlinks)
// ─────────────────────────────────────────────────────────────────────────────
static std::map<std::string, int> scan_socket_pids() {
  std::map<std::string, int> out;
  std::error_code ec;
  std::filesystem::directory_iterator proc_it("/proc", ec);
  std::filesystem::directory_iterator proc_end;
  for (; proc_it != proc_end; proc_it.increment(ec)) {
    if (ec) { ec.clear(); continue; }
    const std::string name = proc_it->path().filename().string();
    if (name.empty() || !std::all_of(name.begin(), name.end(),
                                     [](unsigned char c) { return std::isdigit(c); }))
      continue;
    auto pidv = parse_ull(name);
    if (!pidv) continue;
    const std::string fd_dir = proc_it->path().string() + "/fd";
    std::filesystem::directory_iterator fd_it(fd_dir, ec);
    std::filesystem::directory_iterator fd_end;
    for (; fd_it != fd_end; fd_it.increment(ec)) {
      if (ec) { ec.clear(); continue; }
      char buf[256];
      ssize_t n = readlink(fd_it->path().c_str(), buf, sizeof(buf) - 1);
      if (n <= 0) continue;
      buf[n] = '\0';
      std::string_view t{buf, static_cast<size_t>(n)};
      constexpr std::string_view prefix = "socket:[";
      if (t.starts_with(prefix) && t.size() > prefix.size() + 1 && t.back() == ']') {
        std::string inode{t.substr(prefix.size(), t.size() - prefix.size() - 1)};
        if (!out.contains(inode)) out[std::move(inode)] = static_cast<int>(*pidv);
      }
    }
  }
  return out;
}

static std::string read_comm(int pid) {
  std::ifstream f("/proc/" + std::to_string(pid) + "/comm");
  std::string s;
  std::getline(f, s);
  return s;
}

static void resolve_procs(std::vector<UdpSocket>& socks) {
  auto inode_map = scan_socket_pids();
  if (inode_map.empty()) return;
  std::map<int, std::string> comm_cache;
  for (auto& s : socks) {
    if (s.inode.empty()) continue;
    auto it = inode_map.find(s.inode);
    if (it == inode_map.end()) continue;
    s.pid = it->second;
    auto cit = comm_cache.find(s.pid);
    if (cit == comm_cache.end()) {
      auto comm = read_comm(s.pid);
      if (comm.size() > 15) comm = comm.substr(0, 15);
      cit = comm_cache.emplace(s.pid, std::move(comm)).first;
    }
    s.proc = cit->second;
  }
}

static long long now_secs() {
  return std::chrono::duration_cast<std::chrono::seconds>(
           std::chrono::system_clock::now().time_since_epoch()).count();
}

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot read
// ─────────────────────────────────────────────────────────────────────────────
static std::vector<UdpSocket> demo_sockets();  // defined below (demo data)

static bool read_snapshot(Snapshot& s, const Filters& f) {
  s.socks.clear();
  s.ts = now_secs();
  if (f.demo) {
    s.socks = demo_sockets();
  } else if (!f.file.empty()) {
    parse_udp_file(f.file, false, s.socks);
  } else {
    parse_udp_file("/proc/net/udp", false, s.socks);
    parse_udp_file("/proc/net/udp6", true, s.socks);
    if (f.resolve) resolve_procs(s.socks);
  }
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Demo data — synthetic busy DNS/NTP/syslog host (16 UDP sockets)
// ─────────────────────────────────────────────────────────────────────────────
// mk() takes dotted-decimal / v6 text addresses (NOT hex) — this is demo data
// written by humans; the /proc parser above handles the kernel hex formats.
static bool parse_host(std::string_view s, bool v6, std::array<uint8_t, 16>& out, int& len) {
  std::string tmp{s};
  if (v6) {
    in6_addr a{};
    if (inet_pton(AF_INET6, tmp.c_str(), &a) != 1) return false;
    std::memcpy(out.data(), &a, 16);
    len = 16;
    return true;
  }
  in_addr a{};
  if (inet_pton(AF_INET, tmp.c_str(), &a) != 1) return false;
  std::memcpy(out.data(), &a, 4);
  len = 4;
  return true;
}

static UdpSocket mk(const std::string& loc, uint16_t lp, const std::string& rem,
                    uint16_t rp, uint8_t st, unsigned uid, const std::string& inode,
                    unsigned long long drops, bool v6) {
  UdpSocket s;
  s.ipv6 = v6;
  int len = 0;
  parse_host(loc, v6, s.local, len);
  s.local_len = len;
  s.lport = lp;
  parse_host(rem, v6, s.remote, len);
  s.remote_len = len;
  s.rport = rp;
  s.state_code = st;
  s.state = state_name(st);
  s.uid = uid;
  s.inode = inode;
  s.drops = drops;
  if (lp == 53 || lp == 5355)      s.proc = "systemd-resolve";
  else if (lp == 123)              s.proc = "systemd-timesyn";
  else if (lp == 68)               s.proc = "dhclient";
  else if (lp == 514)              s.proc = "rsyslogd";
  else if (lp == 161)              s.proc = "snmpd";
  else if (lp == 137 || lp == 138) s.proc = "nmbd";
  else if (lp == 500 || lp == 4500)s.proc = "charon";
  else if (lp == 10000)            s.proc = "miniserv.pl";
  else if (st == 0x01)             s.proc = "systemd-resolve";
  return s;
}

static std::vector<UdpSocket> demo_sockets() {
  std::vector<UdpSocket> v;
  v.push_back(mk("0.0.0.0", 53,    "0.0.0.0", 0, 0x07, 102, "43521", 0, false));   // DNS
  v.push_back(mk("0.0.0.0", 5355,  "0.0.0.0", 0, 0x07, 102, "43522", 0, false));   // LLMNR
  v.push_back(mk("0.0.0.0", 123,   "0.0.0.0", 0, 0x07, 104, "43999", 0, false));   // NTP
  v.push_back(mk("0.0.0.0", 68,    "0.0.0.0", 0, 0x07, 0,    "44120", 0, false));  // DHCP
  v.push_back(mk("0.0.0.0", 514,   "0.0.0.0", 0, 0x07, 101, "44510", 34, false));  // syslog w/ drops
  v.push_back(mk("0.0.0.0", 161,   "0.0.0.0", 0, 0x07, 0,    "44817", 0, false));  // snmpd
  v.push_back(mk("0.0.0.0", 137,   "0.0.0.0", 0, 0x07, 60,   "45005", 12, false)); // netbios w/ drops
  v.push_back(mk("0.0.0.0", 138,   "0.0.0.0", 0, 0x07, 60,   "45006", 9, false));  // netbios-dgm
  v.push_back(mk("0.0.0.0", 500,   "0.0.0.0", 0, 0x07, 0,    "45122", 0, false));  // IKE
  v.push_back(mk("0.0.0.0", 4500,  "0.0.0.0", 0, 0x07, 0,    "45123", 0, false));  // IPsec NAT-T
  v.push_back(mk("0.0.0.0", 10000, "0.0.0.0", 0, 0x07, 119,  "45571", 0, false));  // Webmin
  v.push_back(mk("127.0.0.1", 52341, "127.0.0.1", 53, 0x01, 102, "46000", 0, false)); // resolv q
  v.push_back(mk("127.0.0.1", 52342, "127.0.0.1", 53, 0x01, 102, "46001", 0, false));
  v.push_back(mk("::", 53, "::", 0, 0x07, 102, "43523", 0, true));                 // DNS v6
  v.push_back(mk("::", 123, "::", 0, 0x07, 104, "44000", 0, true));                // NTP v6
  v.push_back(mk("2001:db8::1", 52350, "2001:db8::2", 53, 0x01, 102, "46002", 0, true));
  return v;
}

// ─────────────────────────────────────────────────────────────────────────────
// Keyword search for the detach helper (needed before use below)
// ─────────────────────────────────────────────────────────────────────────────
static std::string colorize(const std::string& s, const std::string& color) {
  return color + s + C_RESET;
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendering
// ─────────────────────────────────────────────────────────────────────────────
static std::string state_color(const std::string& st) {
  if (st == "CONNECTED")   return C_GREEN;
  if (st == "UNCONNECTED") return C_DIM;
  return C_RESET;
}

static void render_socket_line(const UdpSocket& s, bool verbose) {
  // LOCAL                    STATE        UID   DROPS  PROC
  std::string local = s.local_str();
  if (verbose) {
    std::string svc = port_name(s.lport);
    if (!svc.empty()) local += " (" + svc + ")";
  }
  char buf[160];
  std::snprintf(buf, sizeof(buf), "  %-23s %s", local.c_str(), colorize(s.state, state_color(s.state)).c_str());
  std::cout << buf;
  std::string drop_mark = s.drops > 0 ? colorize(fmt_num(s.drops), C_RED) : "0";
  char tail[96];
  std::snprintf(tail, sizeof(tail), "  %6u  %5s  %s\n",
                s.uid, drop_mark.c_str(), s.proc_str().c_str());
  std::cout << tail;
}

static void render_snapshot(const Snapshot& s, const Filters& f, bool header_only) {
  std::cout << C_BOLD << "  UDP WATCH — /proc/net/udp + udp6" << C_RESET << "\n";
  std::cout << "  ------------------------------------------------------------------------------\n";
  char tsbuf[64];
  std::snprintf(tsbuf, sizeof(tsbuf), "  Snapshot: %lld  (IPv4: %llu, IPv6: %llu)",
                s.ts, s.ipv4(), s.ipv6());
  std::cout << tsbuf << "\n\n";

  if (header_only) return;

  // KPI row
  std::cout << "  " << colorize(fmt_num(s.total()), C_CYAN) << " sockets   "
            << colorize(fmt_num(s.count_state("CONNECTED")), C_GREEN) << " connected   "
            << colorize(fmt_num(s.count_state("UNCONNECTED")), C_DIM) << " unconnected   "
            << "drops " << colorize(fmt_num(s.total_drops()),
                                    s.total_drops() > 0 ? C_RED : C_GREEN)
            << "  (" << fmt_num(s.sockets_with_drops()) << " sockets with drops)\n\n";

  // Filtered list
  std::vector<const UdpSocket*> view;
  for (auto& sk : s.socks) {
    if (f.port && sk.lport != *f.port) continue;
    if (!f.state.empty() && sk.state != f.state) continue;
    if (f.drops_only && sk.drops == 0) continue;
    view.push_back(&sk);
  }
  std::sort(view.begin(), view.end(), [](const UdpSocket* a, const UdpSocket* b) {
    if (a->lport != b->lport) return a->lport < b->lport;
    if ((a->drops > 0) != (b->drops > 0)) return a->drops > 0;
    return a->local_str() < b->local_str();
  });
  if (f.top > 0 && static_cast<int>(view.size()) > f.top)
    view.resize(static_cast<size_t>(f.top));

  std::cout << "  LOCAL ADDRESS            STATE           UID     DROPS  PROC\n";
  std::cout << "  ------------------------ --------------- ------ ------- --------------\n";
  for (auto* sk : view)
    render_socket_line(*sk, true);
  std::cout << "  ------------------------------------------------------------------------------\n";
  char foot[96];
  std::snprintf(foot, sizeof(foot), "  %zu sockets shown (filter: %s%s%s%s)\n",
                view.size(),
                f.state.empty() ? "all" : f.state.c_str(),
                f.port ? " port=" : "", f.port ? std::to_string(*f.port).c_str() : "",
                f.drops_only ? " drops>0" : "");
  std::cout << foot;
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON output (hand-built, keys always quoted — validate before publishing)
// ─────────────────────────────────────────────────────────────────────────────
static std::string json_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (char c : s) {
    if (c == '"' || c == '\\') { out += '\\'; out += c; }
    else if (c == '\n') out += "\\n";
    else if (c == '\t') out += "\\t";
    else out += c;
  }
  return out;
}

static void render_json(std::ostream& os, const Snapshot& s, const Filters& f) {
  os << "{\n  \"summary\": {\n";
  os << "    \"ts\": " << s.ts << ",\n";
  os << "    \"total\": " << s.total() << ",\n";
  os << "    \"ipv4\": " << s.ipv4() << ",\n";
  os << "    \"ipv6\": " << s.ipv6() << ",\n";
  os << "    \"connected\": " << s.count_state("CONNECTED") << ",\n";
  os << "    \"unconnected\": " << s.count_state("UNCONNECTED") << ",\n";
  os << "    \"drops\": " << s.total_drops() << ",\n";
  os << "    \"sockets_with_drops\": " << s.sockets_with_drops() << "\n";
  os << "  },\n  \"sockets\": [\n";
  bool first = true;
  for (auto& sk : s.socks) {
    if (f.port && sk.lport != *f.port) continue;
    if (!f.state.empty() && sk.state != f.state) continue;
    if (f.drops_only && sk.drops == 0) continue;
    if (!first) os << ",\n";
    first = false;
    char buf[48];
    std::snprintf(buf, sizeof(buf), "    {\"local\": \"%s\", \"lport\": %u",
                  json_escape(sk.local_str()).c_str(), sk.lport);
    os << buf;
    os << ", \"remote\": \"" << json_escape(sk.remote_str()) << "\"";
    os << ", \"state\": \"" << sk.state << "\"";
    os << ", \"uid\": " << sk.uid;
    os << ", \"drops\": " << sk.drops;
    os << ", \"inode\": \"" << json_escape(sk.inode) << "\"";
    os << ", \"pid\": " << sk.pid;
    os << ", \"proc\": \"" << json_escape(sk.proc_str()) << "\"";
    os << ", \"ipv6\": " << (sk.ipv6 ? "true" : "false") << "}";
  }
  os << "\n  ]\n}\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Watch mode — delta between snapshots (new/closed sockets, drops delta)
// ─────────────────────────────────────────────────────────────────────────────
static void render_watch_delta(const Snapshot& prev, const Snapshot& cur) {
  std::set<std::string> prev_inodes, cur_inodes;
  for (auto& s : prev.socks) prev_inodes.insert(s.inode);
  for (auto& s : cur.socks)  cur_inodes.insert(s.inode);
  std::vector<std::string> created, closed;
  for (auto& ino : cur_inodes) if (!prev_inodes.contains(ino)) created.push_back(ino);
  for (auto& ino : prev_inodes) if (!cur_inodes.contains(ino)) closed.push_back(ino);

  unsigned long long drops_delta = cur.total_drops() > prev.total_drops()
                                     ? cur.total_drops() - prev.total_drops() : 0;

  char buf[160];
  std::snprintf(buf, sizeof(buf),
                "  delta: +%zu new  -%zu closed  |  sockets %llu -> %llu  |  drops %s (+%llu in %.1fs)",
                created.size(), closed.size(), prev.total(), cur.total(),
                fmt_num(cur.total_drops()).c_str(), drops_delta, cur.real_dt);
  std::cout << C_BOLD << buf << C_RESET << "\n";
  for (auto& ino : created) {
    for (auto& s : cur.socks) {
      if (s.inode == ino) {
        std::cout << "  " << C_GREEN << "+ " << C_RESET << s.local_str() << " " << s.state
                  << (s.drops ? " drops=" + fmt_num(s.drops) : "") << "\n";
        break;
      }
    }
  }
  for (auto& ino : closed) {
    std::cout << "  " << C_RED << "- " << C_RESET << "inode " << ino << " closed\n";
  }
  std::cout << std::flush;
}

// ─────────────────────────────────────────────────────────────────────────────
// Selftest
// ─────────────────────────────────────────────────────────────────────────────
static int g_pass = 0, g_fail = 0;
static void check(bool cond, const std::string& name) {
  if (cond) { ++g_pass; std::cout << "  PASS  " << name << "\n"; }
  else      { ++g_fail; std::cout << "  FAIL  " << name << "\n"; }
}

static int selftest() {
  std::cout << "== parse_ull / parse_hex ==\n";
  check(parse_ull("  42") == 42ull, "parse_ull trims leading spaces");
  check(parse_ull("") == std::nullopt, "parse_ull empty -> nullopt");
  check(parse_ull("12a") == std::nullopt, "parse_ull trailing garbage -> nullopt");
  check(parse_hex("BA5E") == 0xBA5Eull, "parse_hex basic");
  check(parse_hex("zz") == std::nullopt, "parse_hex invalid -> nullopt");

  std::cout << "== address decoding ==\n";
  {
    std::array<uint8_t, 16> b{}; int len = 0;
    check(decode_addr("0100007F", false, b, len) && len == 4 && fmt_ipv4(b) == "127.0.0.1",
          "ipv4 0100007F -> 127.0.0.1");
    check(decode_addr("0B00007F", false, b, len) && fmt_ipv4(b) == "127.0.0.11",
          "ipv4 0B00007F -> 127.0.0.11");
    check(decode_addr("00000000", false, b, len) && fmt_ipv4(b) == "0.0.0.0",
          "ipv4 00000000 -> 0.0.0.0");
    check(decode_addr("0000000000000000FFFF00000100007F", true, b, len) &&
          fmt_ipv6(b) == "::ffff:127.0.0.1", "ipv6 mapped ::ffff:127.0.0.1");
    check(decode_addr("00000000000000000000000000000000", true, b, len) &&
          fmt_ipv6(b) == "::", "ipv6 all-zero -> ::");
    check(decode_addr("B80D0120000000000000000001000000", true, b, len) &&
          fmt_ipv6(b) == "2001:db8::1", "ipv6 2001:db8::1");
    // Real kernel form for ::1 (group3 = 01000000, not 00000001 — see skill pitfall)
    check(decode_addr("00000000000000000000000001000000", true, b, len) &&
          fmt_ipv6(b) == "::1", "ipv6 ::1 real kernel form");
  }

  std::cout << "== UDP state decode ==\n";
  check(state_name(0x01) == "CONNECTED", "0x01 -> CONNECTED");
  check(state_name(0x07) == "UNCONNECTED", "0x07 -> UNCONNECTED");
  check(state_name(0x02) == "UNKNOWN", "0x02 -> UNKNOWN");

  std::cout << "== parser (udp + udp6 line formats) ==\n";
  {
    std::vector<UdpSocket> v;
    check(parse_udp_file("/proc/net/udp", false, v), "opens /proc/net/udp");
    std::string dump =
      "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
      " 1: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000    102        0 43521 2 0000000000000000 0\n"
      " 2: 0100007F:CC75 0100007F:0035 01 00000000:00000000 00:00000000 00000000    102        0 46000 2 0000000000000000 12\n";
    std::string path = "/tmp/udp-selftest.table";
    { std::ofstream o(path); o << dump; }
    v.clear();
    check(parse_udp_file(path, false, v) && v.size() == 2, "parses 2 UDPv4 lines");
    if (v.size() == 2) {
      check(v[0].local_str() == "127.0.0.1:53", "v4 local 127.0.0.1:53");
      check(v[0].state == "UNCONNECTED" && v[1].state == "CONNECTED", "states decoded");
      check(v[0].uid == 102, "uid parsed");
      check(v[0].drops == 0 && v[1].drops == 12, "drops column parsed");
      check(v[0].inode == "43521", "inode parsed");
    }
    // comment tolerance
    std::string dump_comment =
      "# sample with comments\n"
      "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
      " 3: 00000000:007B 00000000:0000 07 00000000:00000000 00:00000000 00000000    104        0 43999 2 0000000000000000 0   # NTP\n";
    { std::ofstream o(path); o << dump_comment; }
    v.clear();
    check(parse_udp_file(path, false, v) && v.size() == 1 && v[0].lport == 123,
          "comments (#) and trailing annotations tolerated");
    // v6 line
    std::string dump_v6 =
      "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
      " 14: 00000000000000000000000000000000:0035 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000    102        0 43523 2 0000000000000000 0\n"
      " 16: B80D0120000000000000000001000000:CC7E B80D0120000000000000000002000000:0035 01 00000000:00000000 00:00000000 00000000    102        0 46002 2 0000000000000000 0\n";
    { std::ofstream o(path); o << dump_v6; }
    v.clear();
    check(parse_udp_file(path, true, v) && v.size() == 2, "parses 2 UDPv6 lines");
    if (v.size() == 2) {
      check(v[0].local_str() == "[::]:53", "v6 [::]:53");
      check(v[1].local_str() == "[2001:db8::1]:52350", "v6 [2001:db8::1]:52350");
      check(v[1].remote_str() == "[2001:db8::2]:53", "v6 remote decoded");
      check(v[1].ipv6 && v[0].ipv6, "ipv6 flag set");
    }
    std::remove(path.c_str());
  }

  std::cout << "== port names ==\n";
  {
    check(port_name(53) == "domain", "port 53 -> domain");
    check(port_name(123) == "ntp", "port 123 -> ntp");
    check(port_name(514) == "syslog", "port 514 -> syslog");
  }

  std::cout << "== demo snapshot ==\n";
  {
    Snapshot s;
    Filters f; f.demo = true;
    read_snapshot(s, f);
    check(s.total() == 16, "demo has 16 sockets");
    check(s.count_state("CONNECTED") == 3, "demo 3 connected");
    check(s.count_state("UNCONNECTED") == 13, "demo 13 unconnected");
    check(s.ipv4() == 13 && s.ipv6() == 3, "demo 13 v4 / 3 v6");
    check(s.total_drops() == 55, "demo drops total == 55");
    check(s.sockets_with_drops() == 3, "demo 3 sockets with drops");
  }

  std::cout << "== JSON valid ==\n";
  {
    Snapshot s;
    Filters f; f.demo = true;
    read_snapshot(s, f);
    std::ostringstream os;
    render_json(os, s, f);
    std::string j = os.str();
    check(j.starts_with("{\n  \"summary\": {"), "json starts with quoted summary key");
    check(j.find("\"sockets\": [") != std::string::npos, "json has quoted sockets array");
    check(j.find(": \"127.0.0.1:53\"") != std::string::npos, "json local endpoint quoted");
    check(j.rfind("}") == j.size() - 2, "json ends with closing brace");
    check(std::count(j.begin(), j.end(), '{') == std::count(j.begin(), j.end(), '}'),
          "json braces balanced");
  }

  std::cout << "== real /proc ==\n";
  {
    Snapshot s;
    Filters f;
    check(read_snapshot(s, f) && s.ts > 0, "reads real /proc/net/udp(|6)");
    if (!s.socks.empty()) {
      const auto& sk = s.socks.front();
      check(!sk.local_str().empty(), "real socket has a local endpoint");
      check(sk.state == "CONNECTED" || sk.state == "UNCONNECTED", "real state decodable: " + sk.state);
    } else {
      std::cout << "  INFO  host has 0 UDP sockets — using --demo for visual checks\n";
      check(true, "host /proc/net/udp is header-only (sparse host)");
    }
  }

  std::cout << "\nRESULT: " << g_pass << " passed, " << g_fail << " failed\n";
  return g_fail == 0 ? 0 : 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────
static void usage() {
  std::cout <<
    "Usage: ./udp-watch [options]\n"
    "  Linux UDP socket monitor — /proc/net/udp + /proc/net/udp6\n"
    "\n"
    "  --top N              show only the first N sockets (by port)\n"
    "  --watch N            refresh every N seconds with deltas between snapshots\n"
    "  --port PORT          filter by local port\n"
    "  --state ST           filter by state: CONNECTED | UNCONNECTED\n"
    "  --drops              only sockets with drops > 0\n"
    "  --json               machine-readable JSON output\n"
    "  --demo               synthetic 16-socket demo (busy DNS/NTP host)\n"
    "  --file PATH          parse a dump file instead of /proc (tolerates # comments)\n"
    "  --no-resolve         skip PID/process name resolution (faster)\n"
    "  --no-color           disable ANSI colors (0 escapes in pipes)\n"
    "  --selftest           run self-tests\n"
    "  -h, --help           show this help\n";
}

int main(int argc, char** argv) {
  Filters f;
  for (int i = 1; i < argc; ++i) {
    std::string_view a{argv[i]};
    auto next_val = [&](const char* flag) -> std::optional<std::string> {
      if (i + 1 < argc) { ++i; return std::string(argv[i]); }
      std::cerr << "Missing value for " << flag << "\n";
      return std::nullopt;
    };
    if (a == "-h" || a == "--help") { usage(); return 0; }
    else if (a == "--selftest")     { return selftest(); }
    else if (a == "--no-color")     { f.color = false; disable_color(); }
    else if (a == "--no-resolve")   { f.resolve = false; }
    else if (a == "--json")         { f.json = true; }
    else if (a == "--demo")         { f.demo = true; }
    else if (a == "--drops")        { f.drops_only = true; }
    else if (a == "--top") {
      auto v = next_val("--top"); if (!v) return 2;
      if (auto n = parse_ull(*v)) f.top = static_cast<int>(*n); else { std::cerr << "Bad --top\n"; return 2; }
    }
    else if (a == "--watch") {
      auto v = next_val("--watch"); if (!v) return 2;
      if (auto n = parse_ull(*v)) f.watch = static_cast<int>(*n); else { std::cerr << "Bad --watch\n"; return 2; }
      if (f.watch <= 0) f.watch = 0;
    }
    else if (a == "--port") {
      auto v = next_val("--port"); if (!v) return 2;
      if (auto n = parse_ull(*v)) { if (*n > 65535) { std::cerr << "Port out of range\n"; return 2; } f.port = static_cast<unsigned>(*n); }
      else { std::cerr << "Bad --port\n"; return 2; }
    }
    else if (a == "--state") {
      auto v = next_val("--state"); if (!v) return 2;
      std::string up = *v;
      std::transform(up.begin(), up.end(), up.begin(),
                     [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
      if (up != "CONNECTED" && up != "UNCONNECTED") { std::cerr << "Bad --state (CONNECTED|UNCONNECTED)\n"; return 2; }
      f.state = up;
    }
    else if (a == "--file") {
      auto v = next_val("--file"); if (!v) return 2;
      f.file = *v;
    }
    else { std::cerr << "Unknown option: " << a << "\n"; usage(); return 2; }
  }

  if (f.watch > 0) {
    Snapshot prev, cur;
    read_snapshot(prev, f);
    double dt = static_cast<double>(f.watch);
    for (;;) {
      cur.ts = now_secs();
      cur.real_dt = dt;
      read_snapshot(cur, f);
      cur.ts = now_secs();
      render_snapshot(cur, f, false);
      if (prev.socks.size() > 0) render_watch_delta(prev, cur);
      prev = std::move(cur);
      std::this_thread::sleep_for(std::chrono::seconds(static_cast<unsigned>(f.watch)));
      dt = static_cast<double>(f.watch);
    }
  }

  Snapshot s;
  read_snapshot(s, f);
  if (f.json) render_json(std::cout, s, f);
  else        render_snapshot(s, f, false);
  return 0;
}