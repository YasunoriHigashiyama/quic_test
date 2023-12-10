#ifndef NEOSYSTEM_HTTP3_HTTP3_STATIC_HEADERS_TABLE_HPP_
#define NEOSYSTEM_HTTP3_HTTP3_STATIC_HEADERS_TABLE_HPP_

#include <cstdint>

#include "http_common.hpp"


namespace neosystem {
namespace http3 {

void init_http3_static_headers_table(void);
const neosystem::http::header *find_http3_static_headers_table(uint32_t);
std::size_t get_http3_static_headers_table_size(void);

}
}

#endif
