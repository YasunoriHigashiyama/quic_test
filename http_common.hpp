#ifndef NEOSYSTEM_HTTP_HTTP_COMMON_HPP_
#define NEOSYSTEM_HTTP_HTTP_COMMON_HPP_

#include <string>
#include <vector>


namespace neosystem {
namespace http {

enum class http_method_type {
	GET,
	HEAD,
	POST,
	PUT,
	DELETE,
	OPTIONS,
	TRACE,
	CONNECT,
	PATCH,
	UNKNOWN
};

struct header {
	std::string name;
	std::string value;
};

using headers_type = std::vector<header>;

}
}

#endif
