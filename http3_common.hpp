#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP3_COMMON_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP3_COMMON_HPP_

#include <cstdint>


namespace neosystem {
namespace http3 {

enum class frame_type {
	invalid,
	data,
	headers,
	cancel_push,
	settings,
	push_promise,
	goaway,
	max_push_id,
	reserved_frame,
};

template<typename T>
bool is_reserved_frame_type(T stream_type) {
	return (stream_type - 0x21) % 0x1f == 0;
}

template<typename T>
frame_type to_enum_frame_type(T type) {
	switch (type) {
	case 0x0:
		return frame_type::data;
	case 0x1:
		return frame_type::headers;
	case 0x3:
		return frame_type::cancel_push;
	case 0x4:
		return frame_type::settings;
	case 0x5:
		return frame_type::push_promise;
	case 0x7:
		return frame_type::goaway;
	case 0xd:
		return frame_type::max_push_id;
	}
	if (is_reserved_frame_type(type)) {
		return frame_type::reserved_frame;
	}
	return frame_type::invalid;
}

int get_uint_value(const uint8_t *, std::size_t, uint64_t&);
bool write_uint_value(uint8_t *, std::size_t, uint64_t, std::size_t&);

}
}

#endif
