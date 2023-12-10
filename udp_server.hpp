#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_UDP_SERVER_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_UDP_SERVER_HPP_

#include <vector>

#include <boost/asio.hpp>

#include "arraybuf_cache.hpp"
#include "log.hpp"
#include "quic_packet_receiver.hpp"


class udp_server {
public:
	using self_type = udp_server;
	using packet_receiver_type = quic_packet_receiver<self_type>;
	using write_buffer_type = std::array<uint8_t, 640000>;
	using write_buffer_ptr_type = std::shared_ptr<write_buffer_type>;

	using const_buffer_type = boost::asio::const_buffer;
	using const_buffer_list_type = std::vector<const_buffer_type>;
	using const_buffer_list_ptr_type = std::shared_ptr<const_buffer_list_type>;

private:
	neosystem::wg::log::logger& logger_;

	boost::asio::io_context& io_context_;
	boost::asio::ip::udp::socket socket_;
	boost::asio::ip::udp::endpoint sender_endpoint_;

	neosystem::http::arraybuf_cache cache_;

	neosystem::http::arraybuf_cache::buf_type recv_buf_;

	int index_;
	std::shared_ptr<std::vector<packet_receiver_type::ptr_type>> packet_receiver_list_;

	void async_receive_from(void);

public:
	udp_server(boost::asio::io_context&, short);

	void run(void);

	void set_packet_receiver_list(const std::shared_ptr<std::vector<packet_receiver_type::ptr_type>>& packet_receiver_list) {
		index_ = 0;
		packet_receiver_list_ = packet_receiver_list;
		return;
	}

	void send_packet(const boost::asio::ip::udp::endpoint&, const write_buffer_ptr_type&, size_t);
	void send_packet(const boost::asio::ip::udp::endpoint&, const write_buffer_ptr_type&, const const_buffer_list_ptr_type&);

	void forward_packet(uint32_t, const boost::asio::ip::udp::endpoint&, neosystem::http::arraybuf_cache::buf_type, size_t,
						const std::shared_ptr<std::vector<std::shared_ptr<quicly_decoded_packet_t>>>&, uint32_t);
};

#endif
