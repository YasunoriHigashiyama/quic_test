#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_QUIC_FUNCTIONS_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_QUIC_FUNCTIONS_HPP_

#include <cstring>

#include <endian.h>

#include <string>

#include <picotls.h>
#include <picotls/openssl.h>


extern ptls_save_ticket_t save_session_ticket_;
extern ptls_context_t tlsctx_;
extern ptls_key_exchange_algorithm_t *key_exchanges_[128];
extern ptls_cipher_suite_t *cipher_suites_[128];
extern ptls_on_client_hello_t on_client_hello_;

extern quicly_stream_open_t stream_open_;
extern quicly_closed_by_remote_t closed_by_remote_;
extern quicly_save_resumption_token_t save_resumption_token_;
extern quicly_generate_resumption_token_t generate_resumption_token_;

void init_address_token_aead(void);
ptls_aead_context_t *get_address_token_aead_enc(void);
ptls_aead_context_t *get_address_token_aead_dec(void);

int save_session_ticket_cb(ptls_save_ticket_t *, ptls_t *, ptls_iovec_t);
int on_client_hello_cb(ptls_on_client_hello_t *, ptls_t *, ptls_on_client_hello_parameters_t *);
int on_stream_open(quicly_stream_open_t *, quicly_stream_t *);
void on_closed_by_remote(quicly_closed_by_remote_t *, quicly_conn_t *, int, uint64_t, const char *, size_t);
int save_resumption_token_cb(quicly_save_resumption_token_t *, quicly_conn_t *, ptls_iovec_t);
int on_generate_resumption_token(quicly_generate_resumption_token_t *, quicly_conn_t *, ptls_buffer_t *, quicly_address_token_plaintext_t *);
void init_quic_context(void);

int get_int_length(uint8_t);
bool get_uint64(const uint8_t *, std::size_t, uint64_t&);
std::string hexdump(const uint8_t *, size_t);
bool is_unidirection(int64_t);

int flatten_file_vec(quicly_sendbuf_vec_t *, void *, size_t, size_t);
void discard_file_vec(quicly_sendbuf_vec_t *);

template<typename T>
bool get_uint(const uint8_t *p, std::size_t length, T& value) {
	if (length < sizeof(T)) {
		return false;
	}
	uint64_t v = *p & 0x3F;
	for (int i = 1; i < sizeof(T); ++i) {
		v = (v << 8) + *(p + i);
	}
	value = v;
	return true;
}

template<typename T>
bool write_uint(uint8_t *p, std::size_t length, T value) {
	if (length < sizeof(T)) {
		return false;
	}
	T tmp = 0;
	switch (sizeof(T)) {
	case 1:
		*p = (uint8_t) value;
		break;
	case 2:
		tmp = htons((uint16_t) value);
		std::memcpy(p, &tmp, sizeof(T));
		*p = *p | 0b01000000;
		break;
	case 4:
		tmp = htonl((uint32_t) value);
		std::memcpy(p, &tmp, sizeof(T));
		*p = *p | 0b10000000;
		break;
	case 8:
		tmp = htobe64(value);
		std::memcpy(p, &tmp, sizeof(T));
		*p = *p | 0b11000000;
		break;
	}
	return true;
}

#endif
