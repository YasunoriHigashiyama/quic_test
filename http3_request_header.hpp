#ifndef NEOSYSTEM_HTTP3_HTTP3_REQUEST_HEADER_HPP_
#define NEOSYSTEM_HTTP3_HTTP3_REQUEST_HEADER_HPP_

#include <iostream>

#include "http_common.hpp"
#include "http2_util.hpp"
#include "common.hpp"
#include "application.hpp"
#include "http3_static_headers_table.hpp"
#include "http2_huffman.hpp"


namespace neosystem {
namespace http3 {

namespace http = neosystem::http;

class http3_request_header {
public:
	using cookie_map_type = std::unordered_map<std::string, std::string>;

private:
	std::string authority_;
	std::string method_;
	std::string scheme_;
	std::string path_;

	http::headers_type headers_;
	cookie_map_type cookie_;

	std::size_t content_length_;
	bool has_invalid_request_header_;

	bool is_index_field_line(uint8_t v) {
		return (v & 0b10000000) == 0b10000000;
	}

	bool is_index_field_line_with_post_base_index(uint8_t v) {
		return (v & 0b11110000) == 0b00010000;
	}

	bool is_literal_field_line_with_name_reference(uint8_t v) {
		return (v & 0b11000000) == 0b01000000;
	}

	bool is_literal_field_line_with_post_base_name_reference(uint8_t v) {
		return (v >> 4) == 0;
	}

	bool is_literal_field_line_with_literal_name(uint8_t v) {
		return (v & 0b11100000) == 0b00100000;
	}

	bool is_huffman(uint8_t v) {
		return v & 0b10000000;
	}

	bool is_huffman2(uint8_t v) {
		return v & 0b00001000;
	}

	void append_cookie(http::header& h, const std::string& value) {
		if (h.value != "") {
			h.value += "; ";
		}
		h.value += value;
		// TODO
		//http::parse_cookie(value, cookie_);
		return;
	}

	bool move_header(http::header& cookie_header, const http::header& h) {
		neosystem::wg::log::logger& logger_ = application::get_logger();
		neosystem::wg::log::info(logger_)() << S_ << "header (" << h.name << ": " << h.value << ")";
		if (h.name == "cookie") {
			append_cookie(cookie_header, h.value);
		} else if (h.name == ":authority") {
			authority_ = std::move(h.value);
		} else if (h.name == ":method") {
			if (method_ != "") {
				return false;
			}
			method_ = std::move(h.value);
		} else if (h.name == ":scheme") {
			if (scheme_ != "") {
				return false;
			}
			scheme_ = std::move(h.value);
		} else if (h.name == ":path") {
			if (path_ != "") {
				return false;
			}
			path_ = std::move(h.value);
		} else if (h.name == "host" && authority_ == "") {
			authority_ = std::move(h.value);
		} else if (strcasecmp(h.name.c_str(), "X-POPPO-ID") == 0) {
			has_invalid_request_header_ = true;
			return true;
		} else {
			if (h.name == "content-length") {
				content_length_ = atoi(h.value.c_str());
			}
			headers_.emplace(headers_.end(), std::move(h.name), std::move(h.value));
		}
		return true;
	}

	bool is_valid_header(bool& allow_pseudo_header, const http::header& h) {
		if (allow_pseudo_header) {
			if (h.name[0] != ':') {
				allow_pseudo_header = false;
			}
		} else {
			if (h.name[0] == ':') {
				return false;
			}
			if (h.name == "te" && h.value != "trailers") {
				return false;
			}
		}
		return true;
	}

	bool is_valid_header(const http::header& h) {
		for (char c : h.name) {
			if (isupper(c) != 0) {
				return false;
			}
		}
		if (h.name[0] == ':') {
			if (h.name != ":authority" && h.name != ":method" && h.name != ":scheme" && h.name != ":path") {
				return false;
			}
		} else {
			if (h.name == "connection") {
				return false;
			}
			if (h.name == "te" && h.value != "trailers") {
				return false;
			}
		}
		return true;
	}

	bool set_header(http::header& cookie_header, const http::header& h) {
		if (h.name == "cookie") {
			append_cookie(cookie_header, h.value);
		} else if (h.name == ":authority") {
			authority_ = h.value;
		} else if (h.name == ":method") {
			if (method_ != "") {
				return false;
			}
			method_ = h.value;
		} else if (h.name == ":scheme") {
			if (scheme_ != "") {
				return false;
			}
			scheme_ = h.value;
		} else if (h.name == ":path") {
			if (path_ != "") {
				return false;
			}
			path_ = h.value;
		} else if (h.name == "host" && authority_ == "") {
			authority_ = h.value;
		} else if (strcasecmp(h.name.c_str(), "X-POPPO-ID") == 0) {
			return true;
		} else {
			if (h.name == "content-length") {
				content_length_ = atoi(h.value.c_str());
			}
			headers_.push_back(h);
		}
		return true;
	}

public:
	http3_request_header(void) : content_length_(0), has_invalid_request_header_(false) {
	}

	uint32_t parse(const uint8_t *p, std::size_t length) {
		//std::size_t consume_length;
		//const http::header *header_ptr;
		std::size_t remain = length;
		http::header cookie_header = {"cookie", ""};
		bool allow_pseudo_header = true;

		content_length_ = 0;
		has_invalid_request_header_ = false;

		neosystem::wg::log::logger& logger_ = application::get_logger();
		std::size_t st_length = length;
		std::size_t prev_length = length;
		while (true) {
			if (is_index_field_line(*p)) {
				std::size_t consume_length = 0;
				uint64_t tmp = neosystem::http2::get_int(6, p, length, consume_length);
				if (consume_length == 0) {
					neosystem::wg::log::error(logger_)() << S_ << "invalid int";
					break;
				}
				bool is_static_table = (*p & 0b01000000) ? true : false;
				if (is_static_table) {
					const neosystem::http::header *header = neosystem::http3::find_http3_static_headers_table(tmp);
					neosystem::wg::log::info(logger_)() << S_ << header->name << ": " << header->value;
					if (is_valid_header(allow_pseudo_header, *header) == false) {
						// TODO
						return 0;
					}
					if (set_header(cookie_header, *header) == false) {
						// TODO
						return 0;
					}
				} else {
					// TODO
					neosystem::wg::log::info(logger_)() << S_ << "index: " << tmp << ", consume_length: " << consume_length << ", T: " << (*p & 0b01000000);
				}
				p += consume_length;
				length -= consume_length;
			} else if (is_index_field_line_with_post_base_index(*p)) {
				std::size_t consume_length = 0;
				uint64_t tmp = neosystem::http2::get_int(4, p, length, consume_length);
				if (consume_length == 0) {
					neosystem::wg::log::error(logger_)() << S_ << "invalid int";
					break;
				}
				neosystem::wg::log::info(logger_)() << S_ << "index: " << tmp << ", consume_length: " << consume_length;
				p += consume_length;
				length -= consume_length;
				// TODO
			} else if (is_literal_field_line_with_name_reference(*p)) {
				std::size_t consume_length = 0;
				uint64_t tmp = neosystem::http2::get_int(4, p, length, consume_length);
				if (consume_length == 0) {
					neosystem::wg::log::error(logger_)() << S_ << "invalid int";
					break;
				}
				bool is_static_table = (*p & 0b00010000) ? true : false;
				neosystem::http::header h;
				if (is_static_table) {
					const neosystem::http::header *header = neosystem::http3::find_http3_static_headers_table(tmp);
					neosystem::wg::log::info(logger_)() << S_ << header->name << ": " << header->value;
					h.name = header->name;
				} else {
					neosystem::wg::log::info(logger_)() << S_ << "index: " << tmp << ", T: " << (*p & 0b00010000);
				}
				p += consume_length;
				length -= consume_length;

				uint64_t value_length = neosystem::http2::get_int(7, p, length, consume_length);
				bool huffman_flag = is_huffman(*p);
				p += consume_length;
				length -= consume_length;
				if (huffman_flag) {
					neosystem::http2::decode_huffman(value_length, p, h.value);
					neosystem::wg::log::info(logger_)() << S_ << "header value: " << h.value;
				} else {
					std::string value((const char *) p, value_length);
					neosystem::wg::log::info(logger_)() << S_ << "header value: " << value;
					h.value = value;
				}

				if (is_valid_header(h) == false) {
					// TODO
					return 0;
				}
				if (is_valid_header(allow_pseudo_header, h) == false) {
					// TODO
					return 0;
				}
				if (move_header(cookie_header, h) == false) {
					// TODO
					return 0;
				}

				p += value_length;
				length -= value_length;
			} else if (is_literal_field_line_with_post_base_name_reference(*p)) {
				neosystem::http::header h;
				std::size_t consume_length = 0;
				uint64_t tmp = neosystem::http2::get_int(3, p, length, consume_length);
				if (consume_length == 0) {
					neosystem::wg::log::error(logger_)() << S_ << "invalid int";
					break;
				}
				// TODO
				neosystem::wg::log::info(logger_)() << S_ << "index: " << tmp << ", consume_length: " << consume_length;
				p += consume_length;
				length -= consume_length;

				uint64_t value_length = neosystem::http2::get_int(7, p, length, consume_length);
				bool huffman_flag = is_huffman(*p);
				p += consume_length;
				length -= consume_length;
				if (huffman_flag) {
					neosystem::http2::decode_huffman(value_length, p, h.value);
					neosystem::wg::log::info(logger_)() << S_ << "header value: " << h.value;
				} else {
					std::string value((const char *) p, value_length);
					neosystem::wg::log::info(logger_)() << S_ << "header value: " << value;
					h.value = value;
				}

				if (is_valid_header(h) == false) {
					// TODO
					return 0;
				}
				if (is_valid_header(allow_pseudo_header, h) == false) {
					// TODO
					return 0;
				}
				if (move_header(cookie_header, h) == false) {
					// TODO
					return 0;
				}

				p += value_length;
				length -= value_length;
				neosystem::wg::log::info(logger_)() << S_ << "value_length: " << value_length << ", length: " << length;
			} else if (is_literal_field_line_with_literal_name(*p)) {
				neosystem::http::header h;
				std::size_t consume_length = 0;
				uint64_t name_length = neosystem::http2::get_int(3, p, length, consume_length);
				if (consume_length == 0) {
					neosystem::wg::log::error(logger_)() << S_ << "invalid int";
					break;
				}
				bool huffman_flag = is_huffman2(*p);
				p += consume_length;
				length -= consume_length;
				if (huffman_flag) {
					neosystem::http2::decode_huffman(name_length, p, h.name);
					neosystem::wg::log::info(logger_)() << S_ << "header name: " << h.name;
				} else {
					std::string name((const char *) p, name_length);
					neosystem::wg::log::info(logger_)() << S_ << "header name: " << name;
					h.name = name;
				}

				p += name_length;
				length -= name_length;

				uint64_t value_length = neosystem::http2::get_int(7, p, length, consume_length);
				huffman_flag = is_huffman(*p);
				p += consume_length;
				length -= consume_length;
				if (huffman_flag) {
					neosystem::http2::decode_huffman(value_length, p, h.value);
					neosystem::wg::log::info(logger_)() << S_ << "header value: " << h.value;
				} else {
					std::string value((const char *) p, value_length);
					neosystem::wg::log::info(logger_)() << S_ << "header value: " << value;
					h.value = value;
				}

				if (is_valid_header(h) == false) {
					// TODO
					return 0;
				}
				if (is_valid_header(allow_pseudo_header, h) == false) {
					// TODO
					return 0;
				}
				if (move_header(cookie_header, h) == false) {
					// TODO
					return 0;
				}

				p += value_length;
				length -= value_length;
				neosystem::wg::log::info(logger_)() << S_ << "name_length: " << name_length << ", value_length: " << value_length;
			}
			neosystem::wg::log::info(logger_)() << S_ << "length: " << length;
			if (length == 0) {
				break;
			}
			if (prev_length == length) {
				neosystem::wg::log::error(logger_)() << S_ << "parse error";
				break;
			}
			if (st_length < length) {
				neosystem::wg::log::error(logger_)() << S_ << "parse error";
				break;
			}
			prev_length = length;
		}
		if (cookie_header.value != "") {
			headers_.push_back(cookie_header);
		}
		if (path_ == "" || method_ == "" || scheme_ == "") {
			// TODO
			//return ERROR_CODE_PROTOCOL_ERROR;
		}
		return 0;
	}

	const http::headers_type& get_headers(void) const { return headers_; }
	const char *get_request_method_as_str(void) const { return method_.c_str(); }
	const char *get_request_method_as_lower_str(void) const { return method_.c_str(); }
	//http::http_method_type get_request_method(void) const { return http::str_to_method(method_); }
	const std::string& get_request_path(void) const { return path_; }
	const std::string& get_host(void) const { return authority_; }

	cookie_map_type::const_iterator find_cookie(const std::string& key) const {
		return cookie_.find(key);
	}

	bool exists_cookie(const std::string& key) const {
		const auto it = find_cookie(key);
		if (it == cookie_.end()) {
			return false;
		}
		return true;
	}

	const std::string find_header(const std::string& header_name) const {
		for (const auto& header : headers_) {
			if (strcasecmp(header.name.c_str(), header_name.c_str()) == 0) {
				return header.value;
			}
		}
		return "";
	}

	std::size_t get_content_length(void) const { return content_length_; }
	bool has_invalid_request_header(void) const { return has_invalid_request_header_; }
};

}
}

#endif
