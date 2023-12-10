#include <quicly.h>
#include <picotls.h>
#include <picotls/openssl.h>
#include <quicly/defaults.h>
#include <quicly/streambuf.h>
#include <t/util.h>

#include "http3_common.hpp"
#include "quic_functions.hpp"


namespace neosystem {
namespace http3 {

int get_uint_value(const uint8_t *p, std::size_t length, uint64_t& value) {
	int int_length = get_int_length(*p);

	if (int_length == 8) {
		uint64_t v;
		if (get_uint(p, length, v) == false) {
			return 0;
		}
		value = v;
	} else if (int_length == 4) {
		uint32_t v;
		if (get_uint(p, length, v) == false) {
			return 0;
		}
		value = v;
	} else if (int_length == 2) {
		uint16_t v;
		if (get_uint(p, length, v) == false) {
			return 0;
		}
		value = v;
	} else if (int_length == 1) {
		uint8_t v;
		if (get_uint(p, length, v) == false) {
			return 0;
		}
		value = v;
	}
	return int_length;
}

bool write_uint_value(uint8_t *p, std::size_t length, uint64_t value, std::size_t& consume_length) {
	if (value <= 63) {
		uint8_t tmp = (uint8_t) value;
		consume_length = 1;
		return write_uint(p, length, tmp);
	} else if (value <= 16383) {
		uint16_t tmp = (uint16_t) value;
		consume_length = 2;
		return write_uint(p, length, tmp);
	} else if (value <= 1073741823) {
		uint32_t tmp = (uint32_t) value;
		consume_length = 4;
		return write_uint(p, length, tmp);
	}
	consume_length = 8;
	return write_uint(p, length, value);
}

}
}
