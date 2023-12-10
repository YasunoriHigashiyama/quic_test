#include <iostream>

#include <quicly.h>
#include <picotls.h>
#include <picotls/openssl.h>
#include <quicly/defaults.h>
#include <quicly/streambuf.h>
#include <t/util.h>

#include "quic_functions.hpp"
#include "http3_stream.hpp"
#include "http3_ctrl_stream.hpp"
#include "http3_session.hpp"
#include "udp_server.hpp"
#include "application.hpp"
#include "common.hpp"


ptls_save_ticket_t save_session_ticket_;
ptls_context_t tlsctx_;
ptls_key_exchange_algorithm_t *key_exchanges_[128];
ptls_cipher_suite_t *cipher_suites_[128];
ptls_on_client_hello_t on_client_hello_;

quicly_context_t quic_context_;
quicly_stream_open_t stream_open_;
quicly_closed_by_remote_t closed_by_remote_;
quicly_save_resumption_token_t save_resumption_token_;
quicly_generate_resumption_token_t generate_resumption_token_;

using http3_stream_type = http3_stream<http3_session>;
using http3_ctrl_stream_type = http3_ctrl_stream<http3_session>;
using quic_packet_receiver_type = quic_packet_receiver<udp_server>;

struct st_stream_data_wrapper_t {
	typename http3_stream_type::ptr_type stream;
	typename http3_ctrl_stream_type::ptr_type ctrl_stream;
};

struct st_stream_data_t {
	quicly_streambuf_t streambuf;
	struct st_stream_data_wrapper_t *wrapper;
};

static struct {
	ptls_aead_context_t *enc, *dec;
} g_address_token_aead;

static struct {
	ptls_iovec_t list[16];
	size_t count;
} negotiated_protocols;

static void server_on_receive(quicly_stream_t *, size_t, const void *, size_t);
static void on_stop_sending(quicly_stream_t *, int);
static void on_receive_reset(quicly_stream_t *, int);
static void init_tls_context(void);
static void on_streambuf_destroy(quicly_stream_t *, int);

static const quicly_stream_callbacks_t g_server_stream_callbacks = {
	on_streambuf_destroy,
	quicly_streambuf_egress_shift,
	quicly_streambuf_egress_emit,
	on_stop_sending,
	server_on_receive,
	on_receive_reset
};

void init_address_token_aead(void) {
	uint8_t secret[PTLS_MAX_DIGEST_SIZE];

	ptls_openssl_random_bytes(secret, ptls_openssl_sha256.digest_size);
	g_address_token_aead.enc = ptls_aead_new(&ptls_openssl_aes128gcm, &ptls_openssl_sha256, 1, secret, "");
	g_address_token_aead.dec = ptls_aead_new(&ptls_openssl_aes128gcm, &ptls_openssl_sha256, 0, secret, "");
	return;
}

ptls_aead_context_t *get_address_token_aead_enc(void) {
	return g_address_token_aead.enc;
}

ptls_aead_context_t *get_address_token_aead_dec(void) {
	return g_address_token_aead.dec;
}

int save_session_ticket_cb(ptls_save_ticket_t *, ptls_t *, ptls_iovec_t) {
	return 0;
}

int on_client_hello_cb(ptls_on_client_hello_t *_self, ptls_t *tls, ptls_on_client_hello_parameters_t *params) {

	neosystem::wg::log::logger& logger_ = application::get_logger();
	neosystem::wg::log::info(logger_)() << S_ << "on_client_hello_cb()";

	if (negotiated_protocols.count != 0) {
		size_t i, j;
		const ptls_iovec_t *x, *y;
		for (i = 0; i != negotiated_protocols.count; ++i) {
			x = negotiated_protocols.list + i;
			for (j = 0; j != params->negotiated_protocols.count; ++j) {
				y = params->negotiated_protocols.list + j;
				if (x->len == y->len && memcmp(x->base, y->base, x->len) == 0) {
					goto ALPN_Found;
				}
			}
		}
		return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
	ALPN_Found:
		int ret;
		if ((ret = ptls_set_negotiated_protocol(tls, (const char *)x->base, x->len)) != 0) {
			return ret;
		}
	}
	return 0;
}

int on_stream_open(quicly_stream_open_t *, quicly_stream_t *stream) {
	neosystem::wg::log::logger& logger_ = application::get_logger();

	int ret;

	neosystem::wg::log::info(logger_)() << S_ << "on_stream_open()  stream_id: " << stream->stream_id;

	if ((ret = quicly_streambuf_create(stream, sizeof(struct st_stream_data_t))) != 0) {
		return ret;
	}
	stream->callbacks = &g_server_stream_callbacks;

	if (stream->stream_id % 2 != 0) {
		neosystem::wg::log::info(logger_)() << S_ << "on_stream_open()  server stream ?  stream_id: " << stream->stream_id;
	}

	struct _st_quicly_conn_public_t *conn = (struct _st_quicly_conn_public_t *) stream->conn;
	typename quic_packet_receiver_type::quic_connection_data *connection_data = (typename quic_packet_receiver_type::quic_connection_data *) conn->data;

	struct st_stream_data_t *stream_data = (struct st_stream_data_t *) stream->data;
	stream_data->wrapper = new st_stream_data_wrapper_t();
	if (is_unidirection(stream->stream_id)) {
		stream_data->wrapper->ctrl_stream = std::make_shared<http3_ctrl_stream_type>(
			stream->stream_id, connection_data->session);
	} else {
		stream_data->wrapper->stream = std::make_shared<http3_stream_type>(
			stream->stream_id, connection_data->session, stream);
	}
	return 0;
}

static void server_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len) {
	neosystem::wg::log::logger& logger_ = application::get_logger();
	neosystem::wg::log::info(logger_)() << S_ << "server_on_receive()  len: " << len << ", off: " << off;

	if (len == 0 && !quicly_sendstate_is_open(&stream->sendstate)) {
		neosystem::wg::log::info(logger_)() << S_ << "server_on_receive()  not open";
		return;
	}
	if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0) {
		neosystem::wg::log::info(logger_)() << S_ << "server_on_receive()  not 0";
		return;
	}

	struct st_stream_data_t *stream_data = (struct st_stream_data_t *) stream->data;
	if (stream_data->wrapper != nullptr) {
		ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
		if (is_unidirection(stream->stream_id)) {
			stream_data->wrapper->ctrl_stream->receive(input.base, input.len);
		} else {
			stream_data->wrapper->stream->receive(input.base, input.len);
		}
	}
	return;
}

static void on_stop_sending(quicly_stream_t * /*stream*/, int /*err*/) {
	//assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
	//fprintf(stderr, "received STOP_SENDING: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
	return;
}

static void on_receive_reset(quicly_stream_t * /*stream*/, int /*err*/) {
	//assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
	//fprintf(stderr, "received RESET_STREAM: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
	return;
}

void on_closed_by_remote(quicly_closed_by_remote_t * /*self*/, quicly_conn_t * /*conn*/, int /*err*/, uint64_t /*frame_type*/,
								const char * /*reason*/, size_t /*reason_len*/) {

	neosystem::wg::log::logger& logger_ = application::get_logger();
	neosystem::wg::log::info(logger_)() << S_ << "on_closed_by_remote()";
	//if (QUICLY_ERROR_IS_QUIC_TRANSPORT(err)) {
	//	fprintf(stderr, "transport close:code=0x%" PRIx16 ";frame=%" PRIu64 ";reason=%.*s\n", QUICLY_ERROR_GET_ERROR_CODE(err),
	//			frame_type, (int)reason_len, reason);
	//} else if (QUICLY_ERROR_IS_QUIC_APPLICATION(err)) {
	//	fprintf(stderr, "application close:code=0x%" PRIx16 ";reason=%.*s\n", QUICLY_ERROR_GET_ERROR_CODE(err), (int)reason_len,
	//			reason);
	//} else if (err == QUICLY_ERROR_RECEIVED_STATELESS_RESET) {
	//	fprintf(stderr, "stateless reset\n");
	//} else if (err == QUICLY_ERROR_NO_COMPATIBLE_VERSION) {
	//	fprintf(stderr, "no compatible version\n");
	//} else {
	//	fprintf(stderr, "unexpected close:code=%d\n", err);
	//}
	return;
}

int save_resumption_token_cb(quicly_save_resumption_token_t * /*_self*/, quicly_conn_t * /*conn*/, ptls_iovec_t /*token*/) {
#if 0
	free(session_info.address_token.base);
	session_info.address_token = ptls_iovec_init(malloc(token.len), token.len);
	memcpy(session_info.address_token.base, token.base, token.len);

	return save_session(quicly_get_remote_transport_parameters(conn));
#else
	neosystem::wg::log::logger& logger_ = application::get_logger();
	neosystem::wg::log::info(logger_)() << S_ << "save_resumption_token_cb()";
	return 0;
#endif
}

int on_generate_resumption_token(quicly_generate_resumption_token_t *, quicly_conn_t *, ptls_buffer_t *buf,
										quicly_address_token_plaintext_t *token) {
	return quicly_encrypt_address_token(ptls_openssl_random_bytes, g_address_token_aead.enc, buf, buf->off, token);
}

void init_tls_context(void) {
	for (size_t i = 0; ptls_openssl_cipher_suites[i] != NULL; ++i) {
		cipher_suites_[i] = ptls_openssl_cipher_suites[i];
	}

	save_session_ticket_ = {
		save_session_ticket_cb
	};

	tlsctx_ = {
		.random_bytes = ptls_openssl_random_bytes,
		.get_time = &ptls_get_time,
		.key_exchanges = key_exchanges_,
		.cipher_suites = cipher_suites_,
		.require_dhe_on_psk = 1,
		.save_ticket = &save_session_ticket_
	};

	on_client_hello_ = {on_client_hello_cb};
	tlsctx_.on_client_hello = &on_client_hello_;
	return;
}

void init_quic_context(void) {
	init_tls_context();

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

	key_exchanges_[0] = &ptls_openssl_secp256r1;

	const char *cid_key = NULL;
	const char *cert_file = "server.cert";
	load_private_key(quic_context_.tls, "server.key");

	load_certificate_chain(quic_context_.tls, cert_file);

	static char random_key[17];
	tlsctx_.random_bytes(random_key, sizeof(random_key) - 1);
	cid_key = random_key;

	quic_context_.cid_encryptor = quicly_new_default_cid_encryptor(
		//&ptls_openssl_bfecb,
		&ptls_openssl_aes128ecb,
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

	negotiated_protocols.count = 0;
	negotiated_protocols.list[negotiated_protocols.count++] = ptls_iovec_init("h3", strlen("h3"));
	return;
}

void on_streambuf_destroy(quicly_stream_t *stream, int err) {
	struct st_stream_data_t *stream_data = (struct st_stream_data_t *) stream->data;
	if (stream_data->wrapper != nullptr) {
		delete stream_data->wrapper;
	}

	quicly_streambuf_destroy(stream, err);
	return;
}

int get_int_length(uint8_t v) {
	uint8_t u = v >> 6;
	return 1 << u;
}

bool get_uint64(const uint8_t *p, std::size_t length, uint64_t& value) {
	if (length < sizeof(uint64_t)) {
		return false;
	}
	uint64_t v = *p &0x3F;
	for (int i = 1; i < 8; ++i) {
		v = (v << 8) + *(p + i);
	}
	value = v;
	return true;
}

std::string hexdump(const uint8_t *p, size_t l) {
	std::stringstream result;
	result << l << "bytes\n";

	while (l != 0) {
		int i;
		result << "   ";
		for (i = 0; i < 16; ++i) {
			uint8_t value = *p++;
			result << (boost::format("   %02X") % (uint32_t) value);
			if (--l == 0) {
				break;
			}
		}
		result << "\n";
	}
	return result.str();
}

bool is_unidirection(int64_t stream_id) {
	if (stream_id >= 0 && stream_id & 0x2) {
		return true;
	}
	return false;
}

int flatten_file_vec(quicly_sendbuf_vec_t *vec, void *buf, size_t /*off*/, size_t len) {
	http3_stream_type::http3_stream_data *data = (http3_stream_type::http3_stream_data *) vec->cbdata;
	return data->self->flatten_response(*data, buf, len) ? 0 : 1;
}

void discard_file_vec(quicly_sendbuf_vec_t *vec) {
	http3_stream_type::http3_stream_data *data = (http3_stream_type::http3_stream_data *) vec->cbdata;
	if (data == nullptr) {
		return;
	}
	data->self->discard_vec(*data);
	delete data;
	return;
}
