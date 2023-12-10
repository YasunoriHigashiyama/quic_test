#include <iostream>
#include <thread>
#include <functional>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "common.hpp"
#include "application.hpp"
#include "udp_server.hpp"
#include "quic_packet_receiver.hpp"
#include "quic_functions.hpp"
#include "http3_static_headers_table.hpp"
#include "http2_huffman.hpp"


using namespace neosystem::wg;

log::logger application::logger_;

/**
 * applicationの実装クラス
 * */
class application_impl {
public:
	using packet_receiver_type = quic_packet_receiver<udp_server>;

private:
	log::logger& logger_;

	boost::asio::io_context io_context_;
	udp_server udp_server_;

public:
	application_impl(void)
		: logger_(application::get_logger()), udp_server_(io_context_, 4433) {
	}

	int run(void) {
		init_quic_context();

		neosystem::http3::init_http3_static_headers_table();
		neosystem::http2::init_huffman();

		int thread_count = std::thread::hardware_concurrency();
		//int thread_count = 1;
		if (thread_count <= 0) {
			thread_count = 1;
		}
		log::info(logger_)() << "application start (thread count: " << thread_count << ")";
		init_address_token_aead();
		std::vector<std::unique_ptr<std::thread>> packet_receiver_threads;
		std::vector<std::unique_ptr<boost::asio::io_context>> io_context_list;
		std::shared_ptr<std::vector<packet_receiver_type::ptr_type>> quic_packet_receiver_list =
			std::make_shared<std::vector<packet_receiver_type::ptr_type>>();
		for (uint16_t i = 0; i < thread_count; ++i) {
			auto context = std::make_unique<boost::asio::io_context>(1);
			auto receiver = std::make_shared<packet_receiver_type>(*context, udp_server_, i + 1);

			quic_packet_receiver_list->push_back(std::move(receiver));
			io_context_list.push_back(std::move(context));
		}
		for (uint16_t i = 0; i < thread_count; ++i) {
			auto p = std::make_unique<std::thread>([this, &io_context_list, i] {
				boost::asio::io_context& context = *(io_context_list[i]);

				boost::asio::signal_set signals(context, SIGINT, SIGTERM);
				signals.async_wait([&context] (const boost::system::error_code&, int) {
					context.stop();
					return;
				});

				neosystem::wg::log::info(logger_)() << S_ << "start packet receive thread (id: " << (i + 1) << ")";
				context.run();
				neosystem::wg::log::info(logger_)() << S_ << "end packet receive thread";
				return;
			});
			packet_receiver_threads.push_back(std::move(p));
		}

		boost::asio::signal_set signals(io_context_, SIGINT, SIGTERM);
		signals.async_wait([this] (const boost::system::error_code&, int) {
			io_context_.stop();
			return;
		});

		udp_server_.set_packet_receiver_list(quic_packet_receiver_list);
		udp_server_.run();
		io_context_.run();

		for (int i = 0; i < thread_count; ++i) {
			packet_receiver_threads[i]->join();
		}
		return 0;
	}
};


/*!
  コンストラクタ
 */
application::application(void) : impl_(nullptr) {
	impl_ = new application_impl();
}

/*!
  デストラクタ
 */
application::~application(void) {
	if (impl_) {
		delete impl_;
	}
}

int application::run(void) {
	return impl_->run();
}
