#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP3_CTRL_STREAM_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP3_CTRL_STREAM_HPP_

#include <memory>

#include <boost/noncopyable.hpp>

#include "application.hpp"
#include "common.hpp"
#include "log.hpp"
#include "streambuf_cache.hpp"
#include "http3_common.hpp"
#include "http3_dynamic_headers_table.hpp"


template<typename SessionType>
class http3_ctrl_stream : public std::enable_shared_from_this<http3_ctrl_stream<SessionType>>, private boost::noncopyable {
public:
	using session_type = SessionType;
	using self_type = http3_ctrl_stream<session_type>;
	using ptr_type = std::shared_ptr<http3_ctrl_stream<session_type>>;

	enum class stream_type {
		control_stream,
		push_stream,
		qpack_encoder_stream,
		qpack_decoder_stream,
		reserved_stream,
	};

private:
	neosystem::wg::log::logger& logger_;
	int64_t stream_id_;
	session_type::ptr_type http3_session_;

	bool is_reserved_;
	bool is_stream_type_received_;
	stream_type stream_type1_;

	neosystem::http::streambuf_cache& streambuf_cache_;
	neosystem::http::streambuf_cache::buf_type buf_;
	bool is_frame_header_received_;
	neosystem::http3::frame_type frame_type_;
	uint64_t frame_payload_length_;
	uint64_t remain_frame_payload_length_;

	neosystem::http3::http3_dynamic_headers_table& headers_;

	template<typename T>
	stream_type to_enum_stream_type(T type) {
		switch (type) {
		case 0x0:
			return stream_type::control_stream;
		case 0x01:
			return stream_type::push_stream;
		case 0x2:
			return stream_type::qpack_encoder_stream;
		case 0x3:
			return stream_type::qpack_decoder_stream;
		}
		return stream_type::reserved_stream;
	}

	template<typename T>
	bool is_reserved_stream_type(T stream_type) {
		return (stream_type - 0x21) % 0x1f == 0;
	}

	bool receive_first(const uint8_t *p, std::size_t length, std::size_t& consume_length) {
		uint64_t stream_type;
		int int_length = neosystem::http3::get_uint_value(p, length, stream_type);
		if (int_length == 0) {
			return false;
		}
		is_reserved_ = is_reserved_stream_type(stream_type);
		stream_type1_ = to_enum_stream_type(stream_type);
		is_stream_type_received_ = true;

		consume_length += int_length;
		neosystem::wg::log::info(logger_)() << S_ << "http3_ctrl_stream::receive()  ctrl stream  stream_id: " << stream_id_ <<
			", length: " << length << ", int_length: " << int_length << ", is_reserved: " << (is_reserved_ ? "true" : "false") << ", stream_type: " << ((int) stream_type1_);
		return true;
	}

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

		neosystem::wg::log::info(logger_)() << S_ << "http3_ctrl_stream::receive()  ctrl stream  stream_id: " << stream_id_ <<
			", frame_payload_length: " << frame_payload_length_;
		return true;
	}

	bool receive_settings_frame(const uint8_t *p, std::size_t length, std::size_t& consume_length) {
		if (length == 0) {
			return true;
		}
		while (1) {
			std::size_t consume_frame = 0;
			uint64_t setting_type = 0, setting_value = 0;

			int int_length = neosystem::http3::get_uint_value(p, length, setting_type);
			if (int_length == 0) {
				break;
			}
			consume_frame += int_length;
			if (length <= int_length) {
				return false;
			}
			p += int_length;
			length -= int_length;

			int_length = neosystem::http3::get_uint_value(p, length, setting_value);
			if (int_length == 0) {
				break;
			}

			p += int_length;
			length -= int_length;

			neosystem::wg::log::info(logger_)() << S_ << "http3_ctrl_stream::receive()  type: " << setting_type << ", value: " << setting_value;

			consume_frame += int_length;
			remain_frame_payload_length_ -= consume_frame;
			consume_length += consume_frame;

			if (length == 0) {
				break;
			}
		}
		return true;
	}

	bool receive_encoder_instruction(const uint8_t *p, std::size_t length, std::size_t& consume_length) {
		if (length == 0) {
			return true;
		}
		int32_t insert_count = 0;
		while (1) {
			// TODO length check
			if (((*p) >> 7) & 0x01) {
				// Insert with Name Reference
				std::size_t int_length, total = 0;
				uint64_t name_index = neosystem::http2::get_int(6, p, length, int_length);
				bool is_static_table = *p & 0b01000000;
				p += int_length;
				length -= int_length;
				total += int_length;

				std::string name;
				const auto *name_header_ptr = neosystem::http3::find_http3_static_headers_table((uint32_t) name_index);
				if (name_header_ptr != nullptr) {
					name = name_header_ptr->name;
				}

				bool is_huffman = *p & 0b10000000;
				uint64_t value_length = neosystem::http2::get_int(7, p, length, int_length);
				p += int_length;
				length -= int_length;
				total += int_length;

				if (is_huffman) {
					std::string value;
					neosystem::http2::decode_huffman(value_length, p, value);
					neosystem::wg::log::info(logger_)() << S_ << name << ": " << value;
					headers_.add_header(name, value);
					++insert_count;
				} else {
					std::string value((const char *) p, value_length);
					neosystem::wg::log::info(logger_)() << S_ << name << ": " << value;
					headers_.add_header(name, value);
					++insert_count;
				}
				p += value_length;
				length -= value_length;
				total += value_length;
				consume_length += total;
			} else if (((*p) >> 6) & 0x01) {
				// Insert with Literal Name
				std::size_t int_length, total = 0;
				uint64_t name_length = neosystem::http2::get_int(5, p, length, int_length);
				bool is_huffman = *p & 0b00100000;
				p += int_length;
				length -= int_length;
				total += int_length;

				std::string name, value;
				if (is_huffman) {
					neosystem::http2::decode_huffman(name_length, p, name);
				} else {
					std::string tmp((const char *) p, name_length);
					name = tmp;
				}
				p += name_length;
				length -= name_length;
				total += name_length;

				uint64_t value_length = neosystem::http2::get_int(7, p, length, int_length);
				is_huffman = *p & 0b10000000;
				p += int_length;
				length -= int_length;
				total += int_length;

				if (is_huffman) {
					neosystem::http2::decode_huffman(value_length, p, value);
				} else {
					std::string tmp((const char *) p, value_length);
					value = tmp;
				}
				p += value_length;
				length -= value_length;
				total += value_length;
				consume_length += total;

				neosystem::wg::log::info(logger_)() << S_ << name << ": " << value;
				headers_.add_header(name, value);
				++insert_count;
			} else if (((*p) >> 5) & 0x01) {
				// Set Dynamic Table Capacity
				std::size_t int_length;
				uint64_t capacity = neosystem::http2::get_int(3, p, length, int_length);
				p += int_length;
				length -= int_length;
				consume_length += int_length;
				neosystem::wg::log::info(logger_)() << S_ << "capacity: " << capacity << ", int_length: " << int_length;
			} else if (((*p) >> 5) == 0x0) {
				// TODO duplicate
			} else {
				neosystem::wg::log::info(logger_)() << S_ << "unknown";
				break;
			}
			if (length <= 0) {
				break;
			}
		}
		http3_session_->send_insert_count_increment(insert_count);
		return true;
	}

	bool receive_impl(const uint8_t *p, std::size_t length, std::size_t& consume_length) {
		consume_length = 0;

		if (is_stream_type_received_ == false) {
			if (receive_first(p, length, consume_length) == false) {
				return false;
			}
		}
		if (is_reserved_) {
			consume_length = length;
			return true;
		}
		if (consume_length == length) {
			return true;
		}
		if (stream_type1_ == stream_type::qpack_encoder_stream) {
			//neosystem::wg::log::info(logger_)() << S_ << "consume_length: " << consume_length;
			return receive_encoder_instruction(p + consume_length, length - consume_length, consume_length);
		}

		if (is_frame_header_received_ == false) {
			if (receive_frame_header(p + consume_length, length - consume_length, consume_length) == false) {
				return false;
			}
		}
		if (consume_length == length) {
			return true;
		}

		if (is_frame_header_received_) {
			if (frame_type_ == neosystem::http3::frame_type::settings) {
				receive_settings_frame(p + consume_length, length - consume_length, consume_length);
			}
			if (remain_frame_payload_length_ == 0) {
				is_frame_header_received_ = false;
				remain_frame_payload_length_ = frame_payload_length_ = 0;
			}
		}
		return true;
	}

public:
	http3_ctrl_stream(int64_t stream_id, session_type::ptr_type& http3_session)
		: logger_(application::get_logger()), stream_id_(stream_id), http3_session_(http3_session),
		is_reserved_(false), is_stream_type_received_(false),
		streambuf_cache_(http3_session->get_streambuf_cache()),
		is_frame_header_received_(false), headers_(http3_session->get_headers()) {

		neosystem::wg::log::info(logger_)() << S_ << "ctrl stream  stream_id: " << stream_id_;
	}

	void receive(const uint8_t *p, std::size_t length) {
		neosystem::wg::log::info(logger_)() << S_ << hexdump(p, length);

		std::size_t consume_length = 0;
		bool complete = false;
		// TODO
		if (buf_ != nullptr) {
			std::ostream os(&(*buf_));
			os.write((const char *) p, length);

			const uint8_t *data = boost::asio::buffer_cast<const uint8_t *>(buf_->data());
			complete = receive_impl(data, buf_->size(), consume_length);
		} else {
			complete = receive_impl(p, length, consume_length);
		}
		if (complete) {
			is_stream_type_received_ = false;
			is_reserved_ = false;
			is_frame_header_received_ = false;
			neosystem::wg::log::info(logger_)() << S_ << "length: " << length << ", consume_length: " << consume_length;
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
};

#endif
