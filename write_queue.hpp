#ifndef NEOSYSTEM_HTTP_WRITE_QUEUE_HPP_
#define NEOSYSTEM_HTTP_WRITE_QUEUE_HPP_

#include <vector>
#include <queue>

#include <boost/asio.hpp>

#include "streambuf_cache.hpp"


namespace neosystem {
namespace http {

class write_queue {
private:
	using streambuf_type = std::unique_ptr<boost::asio::streambuf>;
	using queue_type = std::queue<streambuf_type>;

	bool waiting_flag_;
	queue_type q_;
	std::vector<streambuf_type> writing_;
	std::vector<boost::asio::const_buffer> buffers_;

public:
	write_queue(void) : waiting_flag_(false) {
	}

	queue_type::size_type get_count(void) const { 
		return q_.size();
	}

	bool push(std::unique_ptr<boost::asio::streambuf>& buf) {
		q_.push(std::move(buf));
		if (waiting_flag_) {
			return false;
		}
		waiting_flag_ = true;
		return true;
	}

	bool is_empty(void) const {
		return q_.empty();
	}

	std::vector<boost::asio::const_buffer>& get_buffers(void) {
		writing_.reserve(q_.size());

		while (!q_.empty()) {
			auto *buf = &(*(q_.front()));
			const char *p = boost::asio::buffer_cast<const char *>(buf->data());
			buffers_.push_back(boost::asio::buffer(p, buf->size()));

			auto tmp = std::move(q_.front());
			q_.pop();
			writing_.push_back(std::move(tmp));
		}
		waiting_flag_ = true;
		return buffers_;
	}

	void clear_writing_buffer(streambuf_cache& cache) {
		waiting_flag_ = false;
		for (auto& e : writing_) {
			auto tmp = std::move(e);
			cache.release(tmp);
		}
		writing_.clear();
		buffers_.clear();
		return;
	}

	boost::asio::streambuf *front(void) {
		if (q_.empty()) {
			return nullptr;
		}

		auto *buf = &(*(q_.front()));
		waiting_flag_ = true;
		return buf;
	}

	boost::asio::streambuf *pop(streambuf_cache& cache) {
		waiting_flag_ = false;
		// 先頭にあるのは今書き込んだバッファ
		auto tmp = std::move(q_.front());
		cache.release(tmp);
		q_.pop();
		if (q_.empty()) return nullptr;

		// 次
		auto *buf = &(*(q_.front()));
		waiting_flag_ = true;
		return buf;
	}
};

}
}

#endif
