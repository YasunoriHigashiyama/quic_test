#ifndef NEOSYSTEM_COMMON_HPP_
#define NEOSYSTEM_COMMON_HPP_

#include <list>
#include <thread>
#include <shared_mutex>
#include <memory>
#include <unordered_map>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/format.hpp>
#include <boost/array.hpp>

#define S_ __FILE__ << ":" << __LINE__ << " "

using read_lock = std::shared_lock<std::shared_mutex>;
using write_lock = std::lock_guard<std::shared_mutex>;

namespace neosystem {
namespace util {

void set_rlimit_core(void);

void append_buffer(boost::asio::streambuf&, boost::asio::streambuf&);
void append_buffer(boost::asio::streambuf&, boost::asio::streambuf&, std::size_t);

void urlencode(const std::string&, std::string&);
bool urldecode(const std::string&, std::string&, bool = true);

std::string get_sha1_hash(const std::string&);

bool generate_csrf_token(std::string&);

bool generate_span_id(std::string&);
bool generate_trace_id(std::string&);

void decode_base64(const char *, size_t, boost::asio::streambuf&);
void encode_base64(const uint8_t *, size_t, std::string&);

bool generate_nonce(std::string&);
bool generate_oauth2_state(std::string&);

void socket_shutdown(boost::asio::ip::tcp::socket&);
void socket_shutdown_send(boost::asio::ip::tcp::socket&);

bool is_char(int);
bool is_ctl(int);
bool is_tspecial(int);
bool is_digit(int);

bool judge_sample(double);

bool parse_token(const std::string&, std::string&);

}
}

#endif
