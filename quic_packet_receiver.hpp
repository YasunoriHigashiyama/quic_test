#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_QUIC_PACKET_RECEIVER_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_QUIC_PACKET_RECEIVER_HPP_

#include <boost/asio.hpp>
#include <boost/noncopyable.hpp>

#include <quicly.h>
#include <picotls.h>
#include <picotls/openssl.h>
#include <quicly/defaults.h>
#include <quicly/streambuf.h>
#include <t/util.h>

#include "arraybuf_cache.hpp"
#include "quic_functions.hpp"
#include "application.hpp"
#include "common.hpp"
#include "http3_session.hpp"
#include "streambuf_cache.hpp"


template<typename Server>
class quic_packet_receiver : public std::enable_shared_from_this<quic_packet_receiver<Server>>, private boost::noncopyable {
public:
	using server_type = Server;
	using self_type = quic_packet_receiver<server_type>;
	using ptr_type = std::shared_ptr<self_type>;
	using unique_ptr_type = std::unique_ptr<self_type>;

	using packet_vector_type = std::vector<std::shared_ptr<quicly_decoded_packet_t>>;
	using packet_vector_ptr_type = std::shared_ptr<packet_vector_type>;

	struct quic_connection_data {
		ptr_type receiver;
		http3_session::ptr_type session;
	};

private:
	neosystem::wg::log::logger& logger_;
	boost::asio::io_context& io_context_;

	quicly_cid_plaintext_t next_cid_;

	server_type& server_;
	uint32_t thread_id_;

	quicly_conn_t **conns_;
	size_t num_conns_;

	neosystem::http::streambuf_cache streambuf_cache_;

	quicly_context_t quic_context_;

	void init_quic_context1(void) {
		quic_context_ = quicly_spec_context;
		quic_context_.tls = &tlsctx_;

		stream_open_ = {&on_stream_open};
		quic_context_.stream_open = &stream_open_;

		closed_by_remote_ = {&on_closed_by_remote};
		quic_context_.closed_by_remote = &closed_by_remote_;

		save_resumption_token_ = {save_resumption_token_cb};
		quic_context_.save_resumption_token = &save_resumption_token_;

		generate_resumption_token_ = {&on_generate_resumption_token};
		quic_context_.generate_resumption_token = &generate_resumption_token_;

		setup_session_cache(quic_context_.tls);
		quicly_amend_ptls_context(quic_context_.tls);

		const char *cid_key = NULL;
		const char *cert_file = "server.cert";
		load_private_key(quic_context_.tls, "server.key");

		load_certificate_chain(quic_context_.tls, cert_file);

		static char random_key[17];
		tlsctx_.random_bytes(random_key, sizeof(random_key) - 1);
		cid_key = random_key;

		quic_context_.cid_encryptor = quicly_new_default_cid_encryptor(
			&ptls_openssl_bfecb,
			&ptls_openssl_aes128ecb,
			&ptls_openssl_sha256,
			ptls_iovec_init(cid_key, strlen(cid_key))
			);


		quic_context_.transport_params.max_streams_bidi = 100;
		quic_context_.transport_params.max_streams_uni = 100;

		quic_context_.transport_params.max_stream_data.bidi_local = 131072;
		quic_context_.transport_params.max_stream_data.bidi_remote = 131072;
		quic_context_.transport_params.max_stream_data.uni = 131072;

		quic_context_.initcwnd_packets = 13552;
		return;
	}

	void send_settings_frame(quicly_conn_t *conn) {
		quicly_stream_t *stream;
		int is_client = quicly_is_client(conn);

		struct _st_quicly_conn_public_t *conn_public = (struct _st_quicly_conn_public_t *) conn;
		neosystem::wg::log::info(logger_)() << S_ << " send frame next: " << conn_public->local.uni.next_stream_id << ", is_client: " << is_client;

		int ret = quicly_open_stream(conn, &stream, 1);
		neosystem::wg::log::info(logger_)() << S_ << " send frame next: " << conn_public->local.uni.next_stream_id << ", stream_id: " << stream->stream_id;
		if (ret == 0) {
			//uint8_t buf[] = {0x0, 0x4, 0x0};
    		//quicly_streambuf_egress_write(stream, buf, 3);

			uint8_t buf[] = {0x0, 0x4, 0x5, 0x1, 0x0, 0x0, 0x7, 0x0};
			write_uint(buf + 4, 2, (uint16_t) 4096);
			write_uint(buf + 7, 1, (uint8_t) 8);
    		quicly_streambuf_egress_write(stream, buf, 8);

			//quicly_streambuf_egress_shutdown(stream);
			quicly_stream_sync_sendbuf(stream, 1);
			neosystem::wg::log::info(logger_)() << S_ << "send settings frame (stream_id: " << stream->stream_id << ")";
			return;
		}
		neosystem::wg::log::info(logger_)() << S_ << "send settings frame error ?";
		return;
	}

	int validate_token(struct sockaddr *remote, ptls_iovec_t client_cid, ptls_iovec_t server_cid,
					   quicly_address_token_plaintext_t *token, const char **err_desc) {
		int64_t age;
		int port_is_equal;

		/* calculate and normalize age */
		if ((age = quic_context_.now->cb(quic_context_.now) - token->issued_at) < 0) {
			age = 0;
		}

		/* check address, deferring the use of port number match to type-specific checks */
		if (remote->sa_family != token->remote.sa.sa_family) {
			goto AddressMismatch;
		}
		switch (remote->sa_family) {
		case AF_INET: {
				  struct sockaddr_in *sin = (struct sockaddr_in *)remote;
				  if (sin->sin_addr.s_addr != token->remote.sin.sin_addr.s_addr) {
					  goto AddressMismatch;
				  }
				  port_is_equal = sin->sin_port == token->remote.sin.sin_port;
			  }
			break;
		case AF_INET6: {
				   struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)remote;
				   if (memcmp(&sin6->sin6_addr, &token->remote.sin6.sin6_addr, sizeof(sin6->sin6_addr)) != 0) {
					   goto AddressMismatch;
				   }
				   port_is_equal = sin6->sin6_port == token->remote.sin6.sin6_port;
			   }
			break;
		default:
			goto UnknownAddressType;
		}

		/* type-specific checks */
		switch (token->type) {
		case st_quicly_address_token_plaintext_t::QUICLY_ADDRESS_TOKEN_TYPE_RETRY:
			if (age > 30000) 
				goto Expired;
			if (!port_is_equal)
				goto AddressMismatch;
			if (!quicly_cid_is_equal(&token->retry.client_cid, client_cid))
				goto CIDMismatch;
			if (!quicly_cid_is_equal(&token->retry.server_cid, server_cid))
				goto CIDMismatch;
			break;
		case st_quicly_address_token_plaintext_t::QUICLY_ADDRESS_TOKEN_TYPE_RESUMPTION:
			if (age > 10 * 60 * 1000)
				goto Expired;
			break;
		default:
			assert(!"unexpected token type");
			abort();
			break;
		}

		/* success */
		*err_desc = NULL;
		return 1;

	AddressMismatch:
		*err_desc = "token address mismatch";
		return 0;
	UnknownAddressType:
		*err_desc = "unknown address type";
		return 0;
	Expired:
		*err_desc = "token expired";
		return 0;
	CIDMismatch:
		*err_desc = "CID mismatch";
		return 0;
	}

	void send_one_packet(const boost::asio::ip::udp::endpoint& sender_endpoint,
						 typename server_type::write_buffer_ptr_type buf, size_t size) {
		neosystem::wg::log::info(logger_)() << S_ << "send_one_packet()";
		server_.send_packet(sender_endpoint, buf, size);
		return;
	}

	int send_pending(const boost::asio::ip::udp::endpoint& sender_endpoint, quicly_conn_t *conn) {
		quicly_address_t dest, src;
		struct iovec packets[32];
		size_t num_packets = 32;
		int ret;

		typename server_type::write_buffer_ptr_type buf1 = std::make_shared<typename server_type::write_buffer_type>();
		
		neosystem::wg::log::info(logger_)() << S_ << "udp_payload_size: " << quicly_get_context(conn)->transport_params.max_udp_payload_size;
		if ((ret = quicly_send(conn, &dest, &src, packets, &num_packets, buf1->data(), buf1->size())) == 0 && num_packets != 0) {
			neosystem::wg::log::info(logger_)() << S_ << "send pending (ret: " << ret << ", num_packets: " << num_packets << ")";

			typename server_type::const_buffer_list_ptr_type buffers = std::make_shared<typename server_type::const_buffer_list_type>();
			for (size_t i = 0; i < num_packets; ++i) {
				buffers->push_back(boost::asio::buffer((const char *) packets[i].iov_base, packets[i].iov_len));
				neosystem::wg::log::info(logger_)() << S_ << "push back (iov_len: " << packets[i].iov_len << ")";
			}

			server_.send_packet(sender_endpoint, buf1, buffers);
		}
		return ret;
	}

	void receive_impl(boost::asio::ip::udp::endpoint sender_endpoint,
					  neosystem::http::arraybuf_cache::buf_type buf,
					  size_t bytes_recved,
					  const packet_vector_ptr_type& packets,
					  uint32_t new_thread_id) {
		struct sockaddr *sender = (struct sockaddr *) sender_endpoint.data();
		quicly_conn_t *conn = NULL;
		neosystem::wg::log::info(logger_)() << S_ << "receive_impl() (size: " << packets->size() << ", new_thread_id: " << new_thread_id << ")";
		int packet_index = 0;
		for (const auto& packet: *packets) {
			if (QUICLY_PACKET_IS_LONG_HEADER(packet->octets.base[0])) {
				neosystem::wg::log::info(logger_)() << S_ << "version: " << packet->version;
				if (packet->version != 0 && !quicly_is_supported_version(packet->version)) {
					typename server_type::write_buffer_ptr_type buf1 = std::make_shared<typename server_type::write_buffer_type>();
					size_t payload_len = quicly_send_version_negotiation(&quic_context_, packet->cid.src, packet->cid.dest.encrypted,
																		 quicly_supported_versions, buf1->data());
					assert(payload_len != SIZE_MAX);
					send_one_packet(sender_endpoint, buf1, payload_len);
					break;
				}
				/* there is no way to send response to these v1 packets */
				if (packet->cid.dest.encrypted.len > QUICLY_MAX_CID_LEN_V1 || packet->cid.src.len > QUICLY_MAX_CID_LEN_V1) {
					break;
				}
			}

			if (conn == NULL) {
				for (size_t i = 0; i != num_conns_; ++i) {
					if (quicly_is_destination(conns_[i], NULL, sender, &(*packet))) {
						conn = conns_[i];
						break;
					}
				}
			}

			if (conn != NULL) {
				uint32_t thread_id = packet->cid.dest.plaintext.thread_id;
				int ret = quicly_receive(conn, NULL, sender, &(*packet));
				neosystem::wg::log::info(logger_)() << S_ << "conn != NULL  (node_id: " << packet->cid.dest.plaintext.node_id
					<< ", thread_id: " << thread_id
					<< ", thread_id_: " << thread_id_
					<< ", new_thread_id: " << new_thread_id
					<< ", ret: " << ret
					<< ", packet_index: " << packet_index
					<< ")";
			} else if (QUICLY_PACKET_IS_INITIAL(packet->octets.base[0])) {
				/* long header packet; potentially a new connection */
				quicly_address_token_plaintext_t *token = NULL, token_buf;
				if (packet->token.len != 0) {
					const char *err_desc = NULL;
					int ret = quicly_decrypt_address_token(get_address_token_aead_dec(), &token_buf, packet->token.base,
														   packet->token.len, 0, &err_desc);
					if (ret == 0 &&
						validate_token(sender, packet->cid.src, packet->cid.dest.encrypted, &token_buf, &err_desc)) {
						token = &token_buf;
					}
				}
				neosystem::wg::log::info(logger_)() << S_ << "QUICLY_PACKET_IS_INITIAL (packet->token.len: " << packet->token.len << ")";
				/* new connection */
				int ret = quicly_accept(&conn, &quic_context_, NULL, sender, &(*packet), token, &next_cid_, NULL, NULL);
				if (ret == 0) {
					assert(conn != NULL);
					++next_cid_.master_id;
					conns_ = (quicly_conn_t **) realloc(conns_, sizeof(*conns_) * (num_conns_ + 1));
					assert(conns_ != NULL);
					conns_[num_conns_++] = conn;

					struct quic_connection_data *connection_data = new struct quic_connection_data();
					auto self = std::enable_shared_from_this<self_type>::shared_from_this();
					connection_data->receiver = self;
					auto http3_session_ptr = std::make_shared<http3_session>(io_context_, conn, streambuf_cache_);
					connection_data->session = http3_session_ptr;

					struct _st_quicly_conn_public_t *conn_public = (struct _st_quicly_conn_public_t *) conn;
					conn_public->data = connection_data;
					neosystem::wg::log::info(logger_)() << S_ << "next: " << conn_public->local.bidi.next_stream_id;

					http3_session_ptr->send_settings_frame();
					http3_session_ptr->open_qpack_encoder_stream();
					http3_session_ptr->open_qpack_decoder_stream();
				} else {
					assert(conn == NULL);
					uint32_t thread_id = packet->cid.dest.plaintext.thread_id;
					neosystem::wg::log::info(logger_)() << S_ << "other thread (node_id: " << packet->cid.dest.plaintext.node_id
						<< ", thread_id: " << thread_id
						<< ", thread_id_: " << thread_id_
						<< ", new_thread_id: " << new_thread_id
						<< ", might_be_client_generated: " << packet->cid.dest.might_be_client_generated
						<< ")";
					server_.forward_packet(thread_id, sender_endpoint, std::move(buf), bytes_recved, packets, new_thread_id);
					break;
				}
				neosystem::wg::log::info(logger_)() << S_ << "accept (ret: " << ret << ", num_conns_: " << num_conns_ << ", next_cid_.thread_id: " << next_cid_.thread_id << ")";
			} else if (!QUICLY_PACKET_IS_LONG_HEADER(packet->octets.base[0])) {
				uint32_t thread_id = packet->cid.dest.plaintext.thread_id;
				neosystem::wg::log::info(logger_)() << S_ << "other thread (node_id: " << packet->cid.dest.plaintext.node_id
					<< ", thread_id: " << thread_id
					<< ", thread_id_: " << thread_id_
					<< ", new_thread_id: " << new_thread_id
					<< ", might_be_client_generated: " << packet->cid.dest.might_be_client_generated
					<< ")";
				server_.forward_packet(thread_id, sender_endpoint, std::move(buf), bytes_recved, packets, new_thread_id);
				break;
			}
			++packet_index;
		}
		for (size_t i = 0; i != num_conns_; ++i) {
			if (quicly_get_first_timeout(conns_[i]) <= quic_context_.now->cb(quic_context_.now)) {
				//neosystem::wg::log::info(logger_)() << S_ << "quicly_get_first_timeout";
				if (send_pending(sender_endpoint, conns_[i]) != 0) {
					struct quic_connection_data *data = (struct quic_connection_data *) ((struct _st_quicly_conn_public_t *) conns_[i])->data;
					delete data;
					((struct _st_quicly_conn_public_t *) conns_[i])->data = nullptr;

					quicly_free(conns_[i]);
					memmove(conns_ + i, conns_ + i + 1, (num_conns_ - i - 1) * sizeof(*conns_));
					--i;
					--num_conns_;
				}
			} else {
				neosystem::wg::log::info(logger_)() << S_ << "quicly_get_first_timeout is false";
			}
		}
		return;
	}

public:
	quic_packet_receiver(boost::asio::io_context& io_context, server_type& server, uint16_t thread_id)
		: logger_(application::get_logger()), io_context_(io_context), server_(server), thread_id_(thread_id),
		conns_(nullptr), num_conns_(0), streambuf_cache_(128) {
		init_quic_context1();
		next_cid_.master_id = 0;
		next_cid_.path_id = 0;
		next_cid_.thread_id = thread_id;
		next_cid_.node_id = 0;
		neosystem::wg::log::info(logger_)() << S_ << "init (thread_id: " << thread_id << ")";
	}

	void forward_receive(const boost::asio::ip::udp::endpoint& sender_endpoint, neosystem::http::arraybuf_cache::buf_type buf, size_t bytes_recvd, uint32_t new_thread_id) {
		neosystem::wg::log::info(logger_)() << S_ << "forward receive packet (bytes_recvd: " << bytes_recvd << ")";
		boost::asio::post(io_context_, [this, sender_endpoint, b = std::move(buf), bytes_recvd, new_thread_id] mutable {
			size_t rret = bytes_recvd;
			size_t off = 0;
			const uint8_t *data = b->data();

			auto packet_list = std::make_shared<packet_vector_type>();
			while (off != rret) {
				std::shared_ptr<quicly_decoded_packet_t> packet = std::make_shared<quicly_decoded_packet_t>();
				if (quicly_decode_packet(&quic_context_, &(*packet), data, rret, &off) == SIZE_MAX) {
					break;
				}
				packet_list->push_back(packet);
			}

			receive_impl(sender_endpoint, std::move(b), bytes_recvd, packet_list, new_thread_id);
			return;
		});
		return;
	}

	void receive(const boost::asio::ip::udp::endpoint& sender_endpoint, neosystem::http::arraybuf_cache::buf_type buf, size_t bytes_recvd) {
		neosystem::wg::log::info(logger_)() << S_ << "receive packet (bytes_recvd: " << bytes_recvd << ")";
		boost::asio::post(io_context_, [this, sender_endpoint, b = std::move(buf), bytes_recvd] mutable {
			size_t rret = bytes_recvd;
			size_t off = 0;
			const uint8_t *data = b->data();

			auto packet_list = std::make_shared<packet_vector_type>();
			while (off != rret) {
				std::shared_ptr<quicly_decoded_packet_t> packet = std::make_shared<quicly_decoded_packet_t>();
				if (quicly_decode_packet(&quic_context_, &(*packet), data, rret, &off) == SIZE_MAX) {
					break;
				}
				packet_list->push_back(packet);
			}

			receive_impl(sender_endpoint, std::move(b), bytes_recvd, packet_list, 0);
			return;
		});
		return;
	}

	int get_thread_id(void) const { return thread_id_; }
};

#endif
