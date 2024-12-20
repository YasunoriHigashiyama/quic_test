#include <cstring>

#include "http2_util.hpp"
#include "application.hpp"
#include "common.hpp"


namespace neosystem {
namespace http2 {

uint64_t get_int(int prefix, const uint8_t *p, std::size_t length, std::size_t& consume_length) {
	consume_length = 0;
	uint64_t result = 0;

	if (prefix < 0 || prefix > 8) {
		return result;
	}
	if (length <= 0) {
		return result;
	}

	uint8_t mask = (uint8_t) (0b11111111 >> (8 - prefix));
	uint8_t f = *p & mask;
	result = f;
	if (f < mask) {
		++consume_length;
		return result;
	}
	++consume_length;
	++p;
	for (std::size_t i = 1, m = 0; i < length; ++i) {
		uint8_t b = *p;
		if (m == 0) {
			result += (b & 127);
		} else {
			result += (b & 127) * (2 << (m - 1));
		}
		++consume_length;
		++p;
		m += 7;
		if ((b & 128) != 128) break;
	}
	return result;
}

bool write_encode_int(uint8_t first, uint8_t *buf, std::size_t length, uint64_t value, int n, std::size_t& consume_length) {
	consume_length = 0;
	bool ret = write_encode_int(buf, length, value, n, consume_length);
	buf[0] = first | buf[0];
	return ret;
}

bool write_encode_int(uint8_t *buf, std::size_t length, uint64_t value, int n, std::size_t& consume_length) {
	//neosystem::wg::log::logger& logger_ = application::get_logger();
	if (length == 0) {
		return false;
	}
	uint8_t max = (uint8_t) ((2 << (n - 1)) - 1);
	if (value < max) {
		uint8_t u = (uint8_t) value;
		*buf = u;
		++consume_length;
		//neosystem::wg::log::info(logger_)() << S_ << "consume_length: " << consume_length;
		return true;
	}

	uint8_t u = (uint8_t) max;
	*buf = u;
	++buf;
	--length;
	++consume_length;

	uint64_t i = value - max;
	//neosystem::wg::log::info(logger_)() << S_ << "consume_length: " << consume_length << ", max: " << (uint32_t) max << ", i: " << i;
	for (; i >= 128; ) {
		u = (uint8_t) (i % 128 + 128) | 0b10000000;
		*buf = u;
		++buf;
		--length;
		++consume_length;
		//neosystem::wg::log::info(logger_)() << S_ << "consume_length: " << consume_length;
		if (length == 0) {
			return false;
		}
		i = i / 128;
	}
	return write_encode_int(buf, length, i, 8, consume_length);
}

}
}
