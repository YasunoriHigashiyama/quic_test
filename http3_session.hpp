#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP3_SESSION_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP3_SESSION_HPP_

#include <memory>
#include <vector>

#include <boost/noncopyable.hpp>

#include "common.hpp"
#include "log.hpp"
#include "streambuf_cache.hpp"
#include "http3_dynamic_headers_table.hpp"
#include "application.hpp"
#include "http2_util.hpp"
#include "http3_stream.hpp"


class http3_session : public std::enable_shared_from_this<http3_session>, private boost::noncopyable {
public:
	using self_type = http3_session;

	using ptr_type = std::shared_ptr<self_type>;

private:
	neosystem::wg::log::logger& logger_;
	boost::asio::io_context& io_context_;
	quicly_conn_t *quic_connection_;
	neosystem::http::streambuf_cache& streambuf_cache_;

	neosystem::http3::http3_dynamic_headers_table headers_;

	quicly_stream_t *encoder_stream_;
	quicly_stream_t *decoder_stream_;

	std::vector<std::shared_ptr<http3_stream<self_type>>> waiting_list_;

public:
	http3_session(boost::asio::io_context& io_context, quicly_conn_t *quic_connection, neosystem::http::streambuf_cache& streambuf_cache)
		: logger_(application::get_logger()), io_context_(io_context), quic_connection_(quic_connection), streambuf_cache_(streambuf_cache),
		headers_(4096), encoder_stream_(nullptr), decoder_stream_(nullptr) {
	}

	neosystem::http::streambuf_cache& get_streambuf_cache(void) {
		return streambuf_cache_;
	}

	boost::asio::io_context& get_io_context(void) {
		return io_context_;
	}

	neosystem::http3::http3_dynamic_headers_table& get_headers(void) {
		return headers_;
	}

	void open_qpack_encoder_stream(void) {
		quicly_stream_t *stream;
		int ret = quicly_open_stream(quic_connection_, &stream, 1);
		if (ret != 0) {
			return;
		}
		encoder_stream_ = stream;
		uint8_t buf[1] = {0x2};
		quicly_streambuf_egress_write(stream, buf, 1);
		quicly_stream_sync_sendbuf(stream, 1);
		return;
	}

	void open_qpack_decoder_stream(void) {
		quicly_stream_t *stream;
		int ret = quicly_open_stream(quic_connection_, &stream, 1);
		if (ret != 0) {
			return;
		}
		decoder_stream_ = stream;
		uint8_t buf[1] = {0x3};
		quicly_streambuf_egress_write(stream, buf, 1);
		quicly_stream_sync_sendbuf(stream, 1);
		return;
	}

	void send_seection_acknowledgment(uint64_t stream_id) {
		if (decoder_stream_ == nullptr) {
			return;
		}
		std::size_t consume_length = 0;
		uint8_t buf[16];
		uint8_t *p = buf;

		neosystem::http2::write_encode_int(0b10000000, p, 16, stream_id, 7, consume_length);
		neosystem::wg::log::info(logger_)() << S_ << "send section acknowledgment (stream_id: " << stream_id << ", consume_length: " << consume_length << ")";

		quicly_streambuf_egress_write(decoder_stream_, buf, consume_length);
		quicly_stream_sync_sendbuf(decoder_stream_, 1);
		return;
	}

	void send_insert_count_increment(uint32_t increment_count) {
		if (increment_count <= 0) {
			return;
		}

		if (!waiting_list_.empty()) {
			std::vector<std::shared_ptr<http3_stream<self_type>>> waiting_list(waiting_list_);
			for (const auto& s: waiting_list) {
				if (s->parse_headers_callback() == false) {
					waiting_list_.push_back(s);
				}
			}
		}

		if (decoder_stream_ == nullptr) {
			return;
		}
		std::size_t consume_length = 0;
		uint8_t buf[16];
		uint8_t *p = buf;

		neosystem::http2::write_encode_int(0x0, p, 16, (uint64_t) increment_count, 6, consume_length);
		neosystem::wg::log::info(logger_)() << S_ << "send insert count increment (increment_count: " << increment_count << ", consume_length: " << consume_length << ")";

		quicly_streambuf_egress_write(decoder_stream_, buf, consume_length);
		quicly_stream_sync_sendbuf(decoder_stream_, 1);
		return;
	}

	void send_settings_frame(void) {
		quicly_stream_t *stream;
		int is_client = quicly_is_client(quic_connection_);

		struct _st_quicly_conn_public_t *conn_public = (struct _st_quicly_conn_public_t *) quic_connection_;
		neosystem::wg::log::info(logger_)() << S_ << " send frame next: " << conn_public->local.uni.next_stream_id << ", is_client: " << is_client;

		int ret = quicly_open_stream(quic_connection_, &stream, 1);
		neosystem::wg::log::info(logger_)() << S_ << " send frame next: " << conn_public->local.uni.next_stream_id << ", stream_id: " << stream->stream_id;
		if (ret != 0) {
			neosystem::wg::log::info(logger_)() << S_ << "send settings frame error ?";
			return;
		}
		// TODO
		uint8_t buf[] = {0x0, 0x4, 0x5, 0x1, 0x0, 0x0, 0x7, 0x0};
		write_uint(buf + 4, 2, (uint16_t) 4096);
		write_uint(buf + 7, 1, (uint8_t) 8);
		quicly_streambuf_egress_write(stream, buf, 8);

		quicly_stream_sync_sendbuf(stream, 1);
		neosystem::wg::log::info(logger_)() << S_ << "send settings frame (stream_id: " << stream->stream_id << ")";
		return;
	}

	void register_waiting_list(const std::shared_ptr<http3_stream<self_type>>& ptr) {
		waiting_list_.push_back(ptr);
		return;
	}
};

#endif
