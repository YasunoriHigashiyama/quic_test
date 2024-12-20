#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP3_STREAM_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP3_STREAM_HPP_

#include <memory>
#include <filesystem>

#include <boost/noncopyable.hpp>

#include "application.hpp"
#include "common.hpp"
#include "log.hpp"
#include "streambuf_cache.hpp"
#include "http2_util.hpp"
#include "http3_common.hpp"
#include "http3_request_header.hpp"
#include "http3_dynamic_headers_table.hpp"
#include "write_queue.hpp"


template<typename SessionType>
class http3_stream : public std::enable_shared_from_this<http3_stream<SessionType>>, private boost::noncopyable {
public:
	using session_type = SessionType;
	using self_type = http3_stream<session_type>;
	using ptr_type = std::shared_ptr<http3_stream<session_type>>;

	struct http3_stream_data {
		ptr_type self;
		bool is_last;
		int32_t index;
		neosystem::http::streambuf_cache::buf_type buf;
	};

private:
	neosystem::wg::log::logger& logger_;

	boost::asio::io_context& io_context_;

	const int64_t stream_id_;
	session_type::ptr_type http3_session_;
	quicly_stream_t *stream_;

	neosystem::http::streambuf_cache& streambuf_cache_;
	neosystem::http::streambuf_cache::buf_type buf_;
	bool is_frame_header_received_;
	neosystem::http3::frame_type frame_type_;
	uint64_t frame_payload_length_;
	uint64_t remain_frame_payload_length_;

	neosystem::http::streambuf_cache::buf_type header_buf_;
	neosystem::http3::http3_request_header request_header_;

	boost::asio::posix::stream_descriptor descriptor_;
	boost::asio::posix::stream_descriptor upload_descriptor_;
	neosystem::http::streambuf_cache::buf_type file_read_buf_;
	std::size_t file_size_;
	int32_t current_index_;
	int32_t last_index_;

	neosystem::http3::http3_dynamic_headers_table& headers_;
	bool is_dynamic_encode_;

	neosystem::http::write_queue write_queue_;

	bool receive_frame_header(const uint8_t *p, std::size_t length, std::size_t& consume_length) {
		std::size_t frame_header_size = 0;

		uint64_t frame_type;
		int int_length = neosystem::http3::get_uint_value(p, length, frame_type);
		if (int_length == 0) {
			return false;
		}
		frame_type_ = neosystem::http3::to_enum_frame_type(frame_type);
		frame_header_size += int_length;
		if (length <= frame_header_size) {
			return false;
		}
		p += int_length;

		uint64_t payload_length;
		int_length = neosystem::http3::get_uint_value(p, length, payload_length);
		if (int_length == 0) {
			return false;
		}
		frame_payload_length_ = payload_length;
		remain_frame_payload_length_ = frame_payload_length_;
		is_frame_header_received_ = true;
		frame_header_size += int_length;
		consume_length += frame_header_size;

		neosystem::wg::log::info(logger_)() << S_ << "http3_stream::receive()  stream_id: " << stream_id_ <<
			", frame_payload_length: " << frame_payload_length_;
		return true;
	}

	bool receive_reserved_frame_payload(const uint8_t *p, std::size_t length, std::size_t& consume_length) {
		if (remain_frame_payload_length_ <= length) {
			consume_length += remain_frame_payload_length_;
			remain_frame_payload_length_ = frame_payload_length_ = 0;
			is_frame_header_received_ = false;
			return true;
		}
		consume_length += length;
		remain_frame_payload_length_ -= length;
		return false;
	}

	void parse_headers(void) {
		const uint8_t *p = boost::asio::buffer_cast<const uint8_t *>(header_buf_->data());
		std::size_t length = header_buf_->size(), consume_length = 0;

		uint64_t required_insert_count = neosystem::http2::get_int(8, p, length, consume_length);
		length -= consume_length;
		p += consume_length;

		bool s = (*p) & 0b10000000;

		uint64_t delta_base = neosystem::http2::get_int(7, p, length, consume_length);
		length -= consume_length;
		p += consume_length;

		std::size_t decoded_required_insert_count = decode_required_insert_count(required_insert_count);

		uint64_t base = 0;
		if (s == false) {
			base = decoded_required_insert_count + delta_base;
		} else {
			base = decoded_required_insert_count - delta_base - 1;
		}

		neosystem::wg::log::info(logger_)() << S_ << "http3_stream  required_insert_count: " << required_insert_count
			<< ", decode: " << decoded_required_insert_count
			<< ", s: " << (s ? "true" : "false") << ", delta_base: " << delta_base << ", base: " << base;

		is_dynamic_encode_ = (required_insert_count == 0) ? false : true;

		if (headers_.get_total() < decoded_required_insert_count) {
			neosystem::wg::log::info(logger_)() << S_ << "register waiting list";
			auto self = std::enable_shared_from_this<self_type>::shared_from_this();
			http3_session_->register_waiting_list(self);
			return;
		}
		neosystem::wg::log::info(logger_)() << S_ << "check OK (total: " << headers_.get_total() << ", decoded_required_insert_count: " << decoded_required_insert_count << ")";

		request_header_.parse(p, length, headers_, base);
		return;
	}

	std::size_t decode_required_insert_count(std::size_t encoded_insert_count) {
		auto max_entries = 4096 / 32;
		auto full_range = 2 * max_entries;
		if (encoded_insert_count == 0) {
			return 0;
		}
		if (encoded_insert_count > full_range) {
			return -1;
		}
		auto max_value = headers_.get_total() + max_entries;
		auto max_wrapped = (max_value / full_range) * full_range;
		auto req_insert_count = max_wrapped + encoded_insert_count - 1;

		if (req_insert_count > max_value) {
			if (req_insert_count <= full_range) {
				return -1;
			}
			req_insert_count -= full_range;
		}

		if (req_insert_count == 0) {
			return -1;
		}
		return req_insert_count;
	}

	void upload_file(const std::filesystem::path& request_path) {
		int fd;
		if ((fd = open(request_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NONBLOCK)) == -1) {
			neosystem::wg::log::error(logger_)() << S_ << "open error (request_pat: " << request_path << ")";
			response_404();
			return;
		}

		upload_descriptor_.assign(fd);
		upload_descriptor_.non_blocking(true);

		// TODO
		response_404();
		return;
	}

	void response_file(const std::filesystem::path& request_path) {
		int fd;
		if ((fd = open(request_path.c_str(), O_RDONLY | O_NONBLOCK)) == -1) {
			neosystem::wg::log::error(logger_)() << S_ << "open error (request_pat: " << request_path << ")";
			return;
		}

		struct stat s;
		if (fstat(fd, &s) != 0) {
			close(fd);
			neosystem::wg::log::error(logger_)() << S_ << "fstat error (request_pat: " << request_path << ")";
			return;
		}
		auto file_size = s.st_size;
		neosystem::wg::log::info(logger_)() << S_ << "file size (file_size: " << file_size << ")";

		descriptor_.assign(fd);
		descriptor_.non_blocking(true);
		file_size_ = file_size;

		response_200(file_size);
		current_index_ = last_index_ = -1;

		async_read(true);
		return;
	}

	void async_read(bool is_first) {
		auto self = std::enable_shared_from_this<self_type>::shared_from_this();

		file_read_buf_ = streambuf_cache_.get();
		file_read_buf_->prepare(16000);
		boost::asio::async_read(descriptor_, *file_read_buf_, boost::asio::transfer_at_least(1), [this, self, is_first](const boost::system::error_code& error, std::size_t) {
			neosystem::wg::log::info(logger_)() << S_ << "response data frame: " + file_size_;
			if (is_first) {
				response_data_frame(file_size_);
			}
			if (error) {
				if (error == boost::asio::error::eof) {
					// complete
					response_data(std::move(file_read_buf_), true);
					if (is_dynamic_encode_) {
						http3_session_->send_seection_acknowledgment(stream_id_);
					}
				} else {
					neosystem::wg::log::error(logger_)() << S_ << "error: " << error.message();
					response_data(std::move(file_read_buf_), true);
				}
				return;
			}
			response_data(std::move(file_read_buf_), false);
			async_read(false);
			return;
		});
		return;
	}

	void response_data_frame(std::size_t data_size) {
		std::size_t length = 4096, consume_length = 0;
		uint8_t buf[4096];
		uint8_t *p = buf;

		buf[0] = 0x0;
		++p;
		--length;

		neosystem::http3::write_uint_value(p, length, data_size, consume_length);
		p += consume_length;
		length -= consume_length;

		neosystem::wg::log::info(logger_)() << S_ << "send length: " << (4096 - length);
    	quicly_streambuf_egress_write(stream_, buf, 4096 - length);
		return;
	}

	void response_data(neosystem::http::streambuf_cache::buf_type buf, bool is_last) {
		std::size_t size = buf->size();
		if (is_last) {
			last_index_ = current_index_;
			neosystem::wg::log::info(logger_)() << S_ << "last !! (size: " << size << ", last_index_: " << last_index_ << ")";
			if (size == 0) {
				return;
			}
		}

		static const quicly_streambuf_sendvec_callbacks_t send_file_callbacks = {flatten_file_vec, discard_file_vec};
		http3_stream_data *data = new http3_stream_data();
		auto self = std::enable_shared_from_this<self_type>::shared_from_this();
		data->self = self;
		data->buf = std::move(buf);
		data->is_last = is_last;
		++current_index_;
		data->index = current_index_;
		quicly_sendbuf_vec_t vec = {&send_file_callbacks, (size_t) size, (void *) data};
		quicly_streambuf_egress_write_vec(stream_, &vec);
		return;
	}

	// TODO 作りがいまいちなので直す
	void response_200(std::size_t content_length) {
		std::size_t length = 4096, consume_length;
		uint8_t buf[4096];
		uint8_t *p = buf;
		buf[0] = 0x1;
		buf[2] = 0x0;
		buf[3] = 0x0;
		p += 4;
		length -=4;

		const char *name = ":status";
		neosystem::http2::write_encode_int(0b00100000, p, length, (uint32_t) strlen(name), 3, consume_length);
		p += consume_length;
		length -= consume_length;
		std::memcpy(p, name, strlen(name));
		p += strlen(name);
		length -= strlen(name);

		const char *value = "200";
		neosystem::http2::write_encode_int(0x0, p, length, (uint32_t) strlen(value), 7, consume_length);
		p += consume_length;
		length -= consume_length;
		std::memcpy(p, value, strlen(value));
		p += strlen(value);
		length -= strlen(value);

		name = "content-length";
		neosystem::http2::write_encode_int(0b00100000, p, length, (uint32_t) strlen(name), 3, consume_length);
		p += consume_length;
		length -= consume_length;
		std::memcpy(p, name, strlen(name));
		p += strlen(name);
		length -= strlen(name);

		std::string content_length_value = std::to_string(content_length);
		std::size_t header_value_length = content_length_value.size();
		neosystem::http2::write_encode_int(0x0, p, length, (uint32_t) header_value_length, 7, consume_length);
		p += consume_length;
		length -= consume_length;
		std::memcpy(p, content_length_value.c_str(), header_value_length);
		p += header_value_length;
		length -= header_value_length;

		buf[1] = 4096 - length - 2;
    	quicly_streambuf_egress_write(stream_, buf, 4096 - length);
		return;
	}

	void response_404(void) {
		std::size_t length = 4096, consume_length;
		uint8_t buf[4096];
		uint8_t *p = buf;
		buf[0] = 0x1;
		buf[2] = 0x0;
		buf[3] = 0x0;
		p += 4;
		length -=4;

		const char *name = ":status";
		neosystem::http2::write_encode_int(0b00100000, p, length, (uint32_t) strlen(name), 3, consume_length);
		neosystem::wg::log::info(logger_)() << S_ << "consume_length: " << consume_length;
		p += consume_length;
		length -= consume_length;
		std::memcpy(p, name, strlen(name));
		p += strlen(name);
		length -= strlen(name);

		const char *value = "404";
		neosystem::http2::write_encode_int(0x0, p, length, (uint32_t) strlen(value), 7, consume_length);
		neosystem::wg::log::info(logger_)() << S_ << "consume_length: " << consume_length;
		p += consume_length;
		length -= consume_length;
		std::memcpy(p, value, strlen(value));
		p += strlen(value);
		length -= strlen(value);

		name = "content-length";
		neosystem::http2::write_encode_int(0b00100000, p, length, (uint32_t) strlen(name), 3, consume_length);
		neosystem::wg::log::info(logger_)() << S_ << "consume_length: " << consume_length;
		p += consume_length;
		length -= consume_length;
		std::memcpy(p, name, strlen(name));
		p += strlen(name);
		length -= strlen(name);

		value = "0";
		neosystem::http2::write_encode_int(0x0, p, length, (uint32_t) strlen(value), 7, consume_length);
		neosystem::wg::log::info(logger_)() << S_ << "consume_length: " << consume_length;
		p += consume_length;
		length -= consume_length;
		std::memcpy(p, value, strlen(value));
		p += strlen(value);
		length -= strlen(value);

		buf[1] = 4096 - length - 2;
		neosystem::wg::log::info(logger_)() << S_ << "send length: " << (4096 - length);
    	quicly_streambuf_egress_write(stream_, buf, 4096 - length);

		quicly_streambuf_egress_shutdown(stream_);
		return;
	}

	void response(void) {

		neosystem::wg::log::info(logger_)() << S_
			<< "path: " << request_header_.get_request_path()
			<< ", method: '" << request_header_.get_request_method() << "'"
			<< ", " << (request_header_.get_request_path() == "/upload")
			<< ", " << (request_header_.get_request_method() == "POST")
			;
		if (request_header_.get_request_path() == "/upload" && request_header_.get_request_method() == "POST") {
			std::filesystem::path root("/var/www/html/upload/");
			std::filesystem::path tmp_path("/var/www/html/upload/tmp.dat");
			auto request_path = std::filesystem::weakly_canonical(tmp_path);
			neosystem::wg::log::info(logger_)() << S_ << "tmp_path: " << tmp_path << ", request_path: " << request_path;
			if (request_path.native().starts_with(root.native()) == false) {
				response_404();
				return;
			}
			upload_file(request_path);
			return;
		}

		std::filesystem::path root("/var/www/html/");
		std::filesystem::path tmp_path("/var/www/html/" + request_header_.get_request_path());
		auto request_path = std::filesystem::weakly_canonical(tmp_path);
		//neosystem::wg::log::info(logger_)() << S_ << "tmp_path: " << tmp_path << ", request_path: " << request_path;
		if (request_path.native().starts_with(root.native()) == false) {
			response_404();
			return;
		}
		if (std::filesystem::exists(request_path) == false) {
			neosystem::wg::log::info(logger_)() << S_ << "file not exist";
			response_404();
			return;
		}
		if (std::filesystem::is_directory(request_path)) {
			request_path /= "index.html";
			if (std::filesystem::exists(request_path) == false) {
				neosystem::wg::log::info(logger_)() << S_ << "file not exist";
				response_404();
				return;
			}
		}
		response_file(request_path);
		return;
	}

	bool receive_data_frame_payload(const uint8_t *p, std::size_t length, std::size_t& consume_length) {
		auto buf = streambuf_cache_.get();
		if (remain_frame_payload_length_ <= length) {
			std::ostream os(&(*buf));
			os.write((const char *) p, remain_frame_payload_length_);

			consume_length += remain_frame_payload_length_;
			remain_frame_payload_length_ = frame_payload_length_ = 0;
		} else {
			std::ostream os(&(*buf));
			os.write((const char *) p, length);
			consume_length += length;
			remain_frame_payload_length_ -= length;
		}

		if (!upload_descriptor_.is_open()) {
			return true;
		}

		async_write_file(buf);
		return false;
	}

	void async_write_file_impl(void) {
		auto self = std::enable_shared_from_this<self_type>::shared_from_this();
		auto *buf = write_queue_.front();
		boost::asio::async_write(upload_descriptor_, *buf, [this, self](const boost::system::error_code error, std::size_t s) {
			write_queue_.pop(streambuf_cache_);
			if (error) {
				neosystem::wg::log::error(logger_)() << S_ << " Error: " << error.message();
				return;
			}
			neosystem::wg::log::info(logger_)() << S_ << "write complete (size: " << s << ")";
			if (write_queue_.is_empty()) {
				// 書き込み待ちなし
				return;
			}
			async_write_file_impl();
			return;
		});
		return;
	}

	void async_write_file(std::unique_ptr<boost::asio::streambuf>& buf) {
		if (write_queue_.push(buf) == false) {
			return;
		}
		async_write_file_impl();
		return;
	}

	bool receive_headers_frame_payload(const uint8_t *p, std::size_t length, std::size_t& consume_length) {
		if (header_buf_ == nullptr) {
			header_buf_ = streambuf_cache_.get();
		}
		neosystem::wg::log::info(logger_)() << S_ << "http3_stream::receive_headers_frame_payload()  remain_frame_payload_length_: " << remain_frame_payload_length_ << ", length: " << length;
		if (remain_frame_payload_length_ <= length) {
			std::ostream os(&(*header_buf_));
			os.write((const char *) p, remain_frame_payload_length_);

			consume_length += remain_frame_payload_length_;
			remain_frame_payload_length_ = frame_payload_length_ = 0;
			is_frame_header_received_ = false;

			parse_headers();
			response();
			return true;
		}
		std::ostream os(&(*header_buf_));
		os.write((const char *) p, length);
		consume_length += length;
		remain_frame_payload_length_ -= length;
		return false;
	}

	bool receive_impl(const uint8_t *p, std::size_t length, std::size_t& consume_length) {
		consume_length = 0;

		while (1) {
			if (is_frame_header_received_ == false) {
				if (receive_frame_header(p + consume_length, length - consume_length, consume_length) == false) {
					return false;
				}
			}
			if (consume_length == length) {
				break;
			}
			bool result;
			switch (frame_type_) {
			case neosystem::http3::frame_type::reserved_frame:
				result = receive_reserved_frame_payload(p + consume_length, length - consume_length, consume_length);
				break;
			case neosystem::http3::frame_type::headers:
				result = receive_headers_frame_payload(p + consume_length, length - consume_length, consume_length);
				break;
			case neosystem::http3::frame_type::data:
				result = receive_data_frame_payload(p + consume_length, length - consume_length, consume_length);
				break;
			default:
				result = false;
				break;
			}
			if (result == false) {
				break;
			}
		}
		return true;
	}

public:
	http3_stream(int64_t stream_id, session_type::ptr_type& http3_session, quicly_stream_t *stream)
		: logger_(application::get_logger()), io_context_(http3_session->get_io_context()),
		stream_id_(stream_id), http3_session_(http3_session), stream_(stream),
		streambuf_cache_(http3_session->get_streambuf_cache()),
		is_frame_header_received_(false), descriptor_(io_context_), upload_descriptor_(io_context_),
		headers_(http3_session->get_headers()), is_dynamic_encode_(false) {
	}

	void receive(const uint8_t *p, std::size_t length) {
		neosystem::wg::log::info(logger_)() << S_ << hexdump(p, length);

		std::size_t consume_length = 0;
		if (buf_ != nullptr) {
			std::ostream os(&(*buf_));
			os.write((const char *) p, length);

			const uint8_t *data = boost::asio::buffer_cast<const uint8_t *>(buf_->data());
			receive_impl(data, buf_->size(), consume_length);
		} else {
			receive_impl(p, length, consume_length);
		}
		if (buf_ != nullptr) {
			if (length > consume_length) {
				buf_->consume(consume_length);
			} else {
				buf_->consume(buf_->size());
				streambuf_cache_.release(buf_);
			}
		} else{
			if (length > consume_length) {
				buf_ = streambuf_cache_.get(p + consume_length, length - consume_length);
			}
		}
		return;
	}

	bool flatten_response(http3_stream_data& data, void *buf, size_t len) {
		neosystem::wg::log::info(logger_)() << S_ << "http3_stream  flatten_response (len: " << len << ", size: " << data.buf->size() << ")";
		const uint8_t *p = boost::asio::buffer_cast<const uint8_t *>(data.buf->data());
		std::memcpy(buf, p, len);
		data.buf->consume(len);

		if (data.is_last) {
			neosystem::wg::log::info(logger_)() << S_ << "last !!";
		}
		return true;
	}

	void discard_vec(http3_stream_data& data) {
		if (last_index_ >= 0 && data.index == last_index_) {
			neosystem::wg::log::info(logger_)() << S_ << "last !! (last_index_: " << last_index_ << ")";
			quicly_streambuf_egress_shutdown(stream_);
		}
		return;
	}

	bool parse_headers_callback(void) {
		const uint8_t *p = boost::asio::buffer_cast<const uint8_t *>(header_buf_->data());
		std::size_t length = header_buf_->size(), consume_length = 0;

		uint64_t required_insert_count = neosystem::http2::get_int(8, p, length, consume_length);
		length -= consume_length;
		p += consume_length;

		bool s = (*p) & 0b10000000;

		uint64_t delta_base = neosystem::http2::get_int(7, p, length, consume_length);
		length -= consume_length;
		p += consume_length;

		std::size_t decoded_required_insert_count = decode_required_insert_count(required_insert_count);

		uint64_t base = 0;
		if (s == false) {
			base = decoded_required_insert_count + delta_base;
		} else {
			base = decoded_required_insert_count - delta_base - 1;
		}

		neosystem::wg::log::info(logger_)() << S_ << "http3_stream  required_insert_count: " << required_insert_count
			<< ", decode: " << decoded_required_insert_count
			<< ", s: " << (s ? "true" : "false") << ", delta_base: " << delta_base << ", base: " << base;

		is_dynamic_encode_ = (required_insert_count == 0) ? false : true;

		if (headers_.get_total() < decoded_required_insert_count) {
			neosystem::wg::log::info(logger_)() << S_ << "register waiting list";
			auto self = std::enable_shared_from_this<self_type>::shared_from_this();
			http3_session_->register_waiting_list(self);
			return false;
		}
		neosystem::wg::log::info(logger_)() << S_ << "check OK (total: " << headers_.get_total() << ", decoded_required_insert_count: " << decoded_required_insert_count << ")";

		request_header_.parse(p, length, headers_, base);
		return true;
	}
};

#endif
