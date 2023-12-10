#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP3_SESSION_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP3_SESSION_HPP_

#include <memory>

#include <boost/noncopyable.hpp>

#include "common.hpp"
#include "log.hpp"
#include "streambuf_cache.hpp"


class http3_session : public std::enable_shared_from_this<http3_session>, private boost::noncopyable {
public:
	using self_type = http3_session;

	using ptr_type = std::shared_ptr<self_type>;

private:
	boost::asio::io_context& io_context_;
	quicly_conn_t *quic_connection_;
	neosystem::http::streambuf_cache& streambuf_cache_;

public:
	http3_session(boost::asio::io_context& io_context, quicly_conn_t *quic_connection, neosystem::http::streambuf_cache& streambuf_cache)
		: io_context_(io_context), quic_connection_(quic_connection), streambuf_cache_(streambuf_cache) {
	}

	neosystem::http::streambuf_cache& get_streambuf_cache(void) {
		return streambuf_cache_;
	}

	boost::asio::io_context& get_io_context(void) {
		return io_context_;
	}
};

#endif
