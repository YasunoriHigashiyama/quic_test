#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_APPLICATION_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_APPLICATION_HPP_

#include <memory>
#include <thread>

#include "log.hpp"


class application_impl;

class application {
private:
	application_impl *impl_;
	static neosystem::wg::log::logger logger_;

public:
	application(void);
	~application(void);

	int run(void);

	static neosystem::wg::log::logger& get_logger(void) {
		return logger_;
	}
};

#endif
