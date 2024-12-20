#ifndef NEOSYSTEM_HTTP3_HTTP3_DYNAMIC_HEADERS_TABLE_HPP_
#define NEOSYSTEM_HTTP3_HTTP3_DYNAMIC_HEADERS_TABLE_HPP_

#include <vector>

#include "http_common.hpp"


namespace neosystem {
namespace http3 {

class http3_dynamic_headers_table {
private:
	std::size_t capacity_;
	std::size_t total_;
	std::size_t deleted_;
	std::vector<neosystem::http::header> headers_;

public:
	http3_dynamic_headers_table(std::size_t capacity) : capacity_(capacity), total_(0), deleted_(0) {
	}

	void add_header(const std::string& name, const std::string& value) {
		neosystem::http::header header;
		header.name = name;
		header.value = value;
		add_header(header);
		return;
	}

	void add_header(const neosystem::http::header& header) {
		headers_.push_back(header);
		++total_;
		return;
	}

	const neosystem::http::header *get_header(std::size_t index_arg) const {
		std::size_t index = index_arg - deleted_;
		if (index >= headers_.size()) {
			return nullptr;
		}
		return &(headers_[index]);
	}

	std::size_t get_total(void) const {
		return total_;
	}
};

}
}

#endif
