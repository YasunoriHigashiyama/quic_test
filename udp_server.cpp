#include "udp_server.hpp"
#include "application.hpp"
#include "common.hpp"


udp_server::udp_server(boost::asio::io_context& io_context, short port)
	: logger_(application::get_logger()),
	io_context_(io_context),
	socket_(io_context, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), port)),
	cache_(1024) {
}

void udp_server::run(void) {
	async_receive_from();
	return;
}

void udp_server::async_receive_from(void) {
	recv_buf_ = cache_.get();

	socket_.async_receive_from(
		boost::asio::buffer(*recv_buf_), sender_endpoint_,
		[this](const boost::system::error_code& error, size_t bytes_recvd) {
			neosystem::wg::log::info(logger_)() << S_ << "receive packet (bytes_recvd: " << bytes_recvd << ")";
			if (error) {
				neosystem::wg::log::error(logger_)() << S_ << error.message();
				async_receive_from();
				return;
			}

			if (index_ >= packet_receiver_list_->size()) {
				index_ = 0;
			}
			(*packet_receiver_list_)[index_]->receive(sender_endpoint_, std::move(recv_buf_), bytes_recvd);
			++index_;
			async_receive_from();
			return;
		}
	);
	return;
}

void udp_server::send_packet(const boost::asio::ip::udp::endpoint& sender_endpoint,
							 const write_buffer_ptr_type& buffer,
							 size_t size) {
	socket_.async_send_to(
		boost::asio::buffer(buffer->data(), size), sender_endpoint,
		[this, buffer](const boost::system::error_code& error, size_t) {
			neosystem::wg::log::info(logger_)() << S_ << "async_send_to() complete (error: " << error << ")";
			return;
		}
	);
	return;
}

void udp_server::send_packet(const boost::asio::ip::udp::endpoint& sender_endpoint,
							 const write_buffer_ptr_type& buffer,
							 const std::shared_ptr<std::vector<boost::asio::const_buffer>>& buffers) {
	//socket_.async_send_to(
	//	*buffers, sender_endpoint,
	//	[this, buffer, buffers](const boost::system::error_code& error, size_t) {
	//		neosystem::wg::log::info(logger_)() << S_ << "async_send_to() complete (count: " << buffers->size() << ", error: " << error << ")";
	//		return;
	//	}
	//);
	for (auto b: *buffers) {
		socket_.async_send_to(
			b, sender_endpoint,
			[this, buffer, buffers](const boost::system::error_code& error, size_t) {
				neosystem::wg::log::info(logger_)() << S_ << "async_send_to() complete (error: " << error << ")";
				return;
			}
		);
	}
	return;
}

void udp_server::forward_packet(uint32_t thread_id, const boost::asio::ip::udp::endpoint& sender_endpoint,
								neosystem::http::arraybuf_cache::buf_type buf, size_t bytes_recved, const std::shared_ptr<std::vector<std::shared_ptr<quicly_decoded_packet_t>>>& packets,
								uint32_t new_thread_id) {
	boost::asio::post(io_context_, [this, thread_id, sender_endpoint, b = std::move(buf), packets, bytes_recved, new_thread_id] mutable {
		if (thread_id < 0 || thread_id - 1 >= packet_receiver_list_->size()) {
			neosystem::wg::log::info(logger_)() << S_ << "unexpected thread ID (threadId: " << thread_id << ", new_thread_id: " << new_thread_id << ", to: " << (*packet_receiver_list_)[new_thread_id]->get_thread_id() << ")";
			(*packet_receiver_list_)[new_thread_id]->forward_receive(sender_endpoint, std::move(b), bytes_recved, new_thread_id + 1);
			return;
		}
		neosystem::wg::log::info(logger_)() << S_ << "forward packet (threadId: " << thread_id << ")";
		(*packet_receiver_list_)[thread_id - 1]->forward_receive(sender_endpoint, std::move(b), bytes_recved, new_thread_id + 1);
		return;
	});
	return;
}
