#ifndef NEOSYSTEM_HTTP2_HTTP2_UTIL_HPP_
#define NEOSYSTEM_HTTP2_HTTP2_UTIL_HPP_

#include <ostream>
#include <cstdint>


namespace neosystem {
namespace http2 {

uint64_t get_int(int, const uint8_t *, std::size_t, std::size_t&);
bool write_encode_int(uint8_t, uint8_t *, std::size_t, uint32_t, int, std::size_t&);
bool write_encode_int(uint8_t *, std::size_t, uint32_t, int, std::size_t&);

}
}

#endif
