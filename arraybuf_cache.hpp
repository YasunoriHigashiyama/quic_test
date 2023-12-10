#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_ARRAYBUF_CACHE_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_ARRAYBUF_CACHE_HPP_

#include <memory>
#include <vector>
#include <array>

#include <boost/noncopyable.hpp>


namespace neosystem {
namespace http {

class arraybuf_cache : private boost::noncopyable {
public:
	using arraybuf_type = std::array<uint8_t, 65536>;
	using buf_type = std::unique_ptr<arraybuf_type>;

private:
	std::size_t max_size_;
	std::vector<buf_type> cache_;

public:
	arraybuf_cache(std::size_t max_size) : max_size_(max_size) {
		cache_.reserve(max_size);
		for (std::size_t i = 0; i < max_size / 2; ++i) {
			cache_.push_back(std::make_unique<arraybuf_type>());
		}
	}

	buf_type get(void) {
		if (cache_.empty()) {
			return std::make_unique<arraybuf_type>();
		}
		auto buf = std::move(*cache_.rbegin());
		cache_.pop_back();
		return buf;
	}

	void release(buf_type& buf) {
		if (buf == nullptr) {
			return;
		}
		if (cache_.size() >= max_size_) {
			return;
		}
		cache_.push_back(std::move(buf));
		return;
	}
};

}
}

#endif
