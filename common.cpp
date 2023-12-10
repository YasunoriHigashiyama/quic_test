#include <cstdlib>
#include <ctype.h>
#include <sstream>
#include <iomanip>
#include <random>
#include <utility>

#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <boost/asio.hpp>
#include <boost/uuid/detail/sha1.hpp>

#include "common.hpp"


namespace neosystem {
namespace util {

using hash_data_t = boost::array<boost::uint8_t, 20>;

static bool check_urlencodechar(unsigned char);
static hash_data_t get_sha1_hash(const void *, const std::size_t);

static bool check_urlencodechar(unsigned char c) {
	return isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~';
}

void set_rlimit_core(void) {
	struct rlimit rlim = {0, 0};

	rlim.rlim_cur = 1073741824;
	rlim.rlim_max = 1073741824;
	setrlimit(RLIMIT_CORE, &rlim);
	return;
}

void append_buffer(boost::asio::streambuf& from, boost::asio::streambuf& to) {
	append_buffer(from, to, from.size());
	return;
}

void append_buffer(boost::asio::streambuf& from, boost::asio::streambuf& to, std::size_t move_size) {
	std::ostream os(&to);
	os.write(boost::asio::buffer_cast<const char *>(from.data()), move_size);
	from.consume(move_size);
	return;
}

bool urldecode(const std::string& src, std::string& ns, bool reject_ctrl) {
	std::size_t alloc = src.size() + 1;
	unsigned char in;
	unsigned long hex;
	char hexstr[3];
	char *ptr;

	for (const char *str = src.c_str(); --alloc > 0; ) {
		in = *str;
		if (('%' == in) && (alloc > 2) && isxdigit(str[1]) && isxdigit(str[2])) {
			hexstr[0] = str[1];
			hexstr[1] = str[2];
			hexstr[2] = 0;

			hex = strtoul(hexstr, &ptr, 16);
			in = (unsigned char) hex;

			str += 2;
			alloc -= 2;
		}

		if(reject_ctrl && (in < 0x20)) {
			return false;
		}

		ns += in;
		str++;
	}
	return true;
}

void urlencode(const std::string& src, std::string& out) {
	std::stringstream s;
	s << std::hex << std::uppercase << std::setfill('0') << std::right;
	auto end = src.end();
	for (auto it = src.begin(); it != end; ++it) {
		if (check_urlencodechar(*it)) {
			s << *it;
			continue;
		}
		s << '%' << std::setw(2) << (((uint32_t) *it) & 0x000000FF);
	}
	out = s.str();
	return;
}

hash_data_t get_sha1_hash(const void *data, const std::size_t byte_count) {
	boost::uuids::detail::sha1 sha1;
	sha1.process_bytes(data, byte_count);

	unsigned int digest[5];
	sha1.get_digest(digest);

	const boost::uint8_t *p_digest = reinterpret_cast<const boost::uint8_t *>(digest);
	hash_data_t hash_data;
	for (int i = 0; i < 5; ++i) {
		hash_data[i * 4] = p_digest[i * 4 + 3];
		hash_data[i * 4 + 1] = p_digest[i * 4 + 2];
		hash_data[i * 4 + 2] = p_digest[i * 4 + 1];
		hash_data[i * 4 + 3] = p_digest[i * 4];
	}
	return hash_data;
}

std::string get_sha1_hash(const std::string& data) {
	hash_data_t h = get_sha1_hash(data.c_str(), data.size());

	std::stringstream s;
	s << std::hex;
	for (auto it = h.begin(); it != h.end(); ++it) {
		s << ((*it  & 0xf0 ) >> 4) << (*it  & 0x0f);
	}
	return s.str();
}

bool generate_csrf_token(std::string& csrf_token) {
	try {
		std::random_device seed_gen;
		std::mt19937 engine(seed_gen());

		std::stringstream s;
		s << engine() << "-" << engine() << "-" << engine();
		csrf_token = get_sha1_hash(s.str());
	} catch (...) {
		return false;
	}
	return true;
}

bool generate_span_id(std::string& span_id) {
	try {
		std::random_device seed_gen;
		std::mt19937 engine(seed_gen());

		std::stringstream s;
		s << std::hex << std::setw(16) << std::setfill('0') << engine();
		span_id = s.str();
	} catch (...) {
		return false;
	}
	return true;
}

bool generate_trace_id(std::string& trace_id) {
	try {
		std::random_device seed_gen;
		std::mt19937 engine(seed_gen());

		std::stringstream s;
		s << std::hex << std::setw(32) << std::setfill('0') << engine();
		trace_id = s.str();
	} catch (...) {
		return false;
	}
	return true;
}

void decode_base64(const char *p, size_t len, boost::asio::streambuf& out) {
	const char B64[] ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	unsigned char b64[128];
	unsigned char c[4];
	char tmp;
	int i, length = static_cast<int>(len), count;
	std::ostream stream(&out);

	for (i = 0; i < 65; ++i) b64[static_cast<int>(B64[i])] = static_cast<unsigned char>(i % 64);
	while (length > 0) {
		count = 3;
		for (i = 0; i < 4; ++i) {
			if (*p != '=') {
				c[i] = b64[static_cast<int>(*p)];
			} else {
				--count;
			}
			++p;
			--length;
		}
		for (i = 0; i < count; ++i) {
			tmp = static_cast<unsigned char>(c[i] << (i * 2 + 2) | c[i + 1] >> ((2 - i) * 2));
			stream.put(tmp);
		}
	}
	return;
}

void encode_base64(const uint8_t *src, size_t src_length, std::string& out) {
	const char B64[] ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	size_t i;
	char c[5];

	out = "";
	c[4] = '\0';
	for (i = 0; i < src_length; i += 3) {
		if ((i + 2) >= src_length) {
			if ((i + 1) >= src_length) {
				c[0] = (char) (B64[src[i] >> 2]);
				c[1] = (char) (B64[((src[i] & 0x03) << 4)]);
				c[2] = '=';
				c[3] = '=';
			} else {
				c[0] = (char) (B64[src[i] >> 2]);
				c[1] = (char) (B64[((src[i] & 0x03) << 4) | (src[i + 1] >> 4)]);
				c[2] = (char) (B64[((src[i + 1] & 0x0f) << 2)]);
				c[3] = '=';
			}
		} else {
			c[0] = (char) (B64[src[i] >> 2]);
			c[1] = (char) (B64[((src[i] & 0x03) << 4) | (src[i + 1] >> 4)]);
			c[2] = (char) (B64[((src[i + 1] & 0x0f) << 2) | (src[i + 2] >> 6)]);
			c[3] = (char) (B64[src[i + 2] & 0x3f]);
		}
		out += c;
	}
	return;
}

bool generate_nonce(std::string& nonce) {
	try {
		std::random_device seed_gen;
		std::mt19937 engine(seed_gen());

		std::stringstream s;
		s << engine() << engine();
		nonce = s.str();
	} catch (...) {
		return false;
	}
	return true;
}

bool generate_oauth2_state(std::string& state) {
	try {
		std::random_device seed_gen;
		std::mt19937 engine(seed_gen());

		std::stringstream s;
		s << engine() << engine();
		state = s.str();
	} catch (...) {
		return false;
	}
	return true;
}

void socket_shutdown(boost::asio::ip::tcp::socket& socket) {
	if (!socket.is_open()) {
		return;
	}

	boost::system::error_code ec;
	//socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
	socket.close(ec);
	return;
}

void socket_shutdown_send(boost::asio::ip::tcp::socket& socket) {
	if (!socket.is_open()) {
		return;
	}

	boost::system::error_code ec;
	socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
	return;
}

bool is_char(int c) {
	return c >= 0 && c <= 127;
}

bool is_ctl(int c) {
	return (c >= 0 && c <= 31) || (c == 127);
}

bool is_tspecial(int c) {
	switch (c) {
	case '(': case ')': case '<': case '>': case '@':
	case ',': case ';': case ':': case '\\': case '"':
	case '/': case '[': case ']': case '?': case '=':
	case '{': case '}': case ' ': case '\t':
		return true;
	}
	return false;
}

bool is_digit(int c) {
	return c >= '0' && c <= '9';
}

bool judge_sample(double rate) {
	std::mt19937 engine;
	engine.seed(std::chrono::system_clock::now().time_since_epoch().count());
	std::uniform_real_distribution<> dist(0.0, 1.0);

	double result = dist(engine);
	return result <= rate;
}

bool parse_token(const std::string& token, std::string& tenant_key) {
	for (std::size_t i = 0; i < token.size(); ++i) {
		if (token[i] == '.') {
			return true;
		}
		tenant_key = token[i];
	}
	return false;
}

}
}
