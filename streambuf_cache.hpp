#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_STREAMBUF_CACHE_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_STREAMBUF_CACHE_HPP_

#include <memory>
#include <vector>

#include <boost/asio.hpp>
#include <boost/noncopyable.hpp>


namespace neosystem {
namespace http {

class streambuf_cache : private boost::noncopyable {
public:
	using buf_type = std::unique_ptr<boost::asio::streambuf>;

private:
	std::size_t max_size_;
	std::vector<std::unique_ptr<boost::asio::streambuf>> cache_;

public:
	streambuf_cache(std::size_t max_size) : max_size_(max_size) {
		cache_.reserve(max_size);
		for (std::size_t i = 0; i < max_size / 2; ++i) {
			cache_.push_back(std::make_unique<boost::asio::streambuf>());
		}
	}

	std::unique_ptr<boost::asio::streambuf> get(void) {
		if (cache_.empty()) {
			return std::make_unique<boost::asio::streambuf>();
		}
		auto buf = std::move(*cache_.rbegin());
		cache_.pop_back();
		return buf;
	}

	std::unique_ptr<boost::asio::streambuf> move_buffer(boost::asio::streambuf& buf, std::size_t move_size) {
		auto tmp_stream = get();
		tmp_stream->prepare(move_size);
		std::ostream os(&(*tmp_stream));
		os.write(boost::asio::buffer_cast<const char *>(buf.data()), move_size);
		buf.consume(move_size);
		return tmp_stream;
	}

	void release(std::unique_ptr<boost::asio::streambuf>& buf) {
		if (buf == nullptr) {
			return;
		}
		if (cache_.size() >= max_size_) {
			return;
		}
		if (buf->size() > 0) {
			buf->consume(buf->size());
		}
		cache_.push_back(std::move(buf));
		return;
	}

	std::unique_ptr<boost::asio::streambuf> get(const uint8_t* p, std::size_t length) {
		auto tmp_stream = get();
		tmp_stream->prepare(length);
		std::ostream os(&(*tmp_stream));
		os.write((const char *) p, length);
		return tmp_stream;
	}

	std::unique_ptr<boost::asio::streambuf> get(const char *str) {
		std::size_t size = strlen(str);
		auto tmp_stream = get();
		tmp_stream->prepare(size);
		std::ostream os(&(*tmp_stream));
		os.write(str, size);
		return tmp_stream;
	}
};

}
}

#endif
