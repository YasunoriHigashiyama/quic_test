#ifndef NEOSYSTEM_HTTP2_HTTP2_HUFFMAN_HPP_
#define NEOSYSTEM_HTTP2_HTTP2_HUFFMAN_HPP_

#include <string>


namespace neosystem {
namespace http2 {

void init_huffman(void);
void destruct_huffman_root(void);
bool decode_huffman(std::size_t, const uint8_t *, std::string&);

}
}

#endif
