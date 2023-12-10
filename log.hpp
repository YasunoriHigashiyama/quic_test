#ifndef NEOSYSTEM_WG_LOG_HPP_
#define NEOSYSTEM_WG_LOG_HPP_

#include <ostream>

#include <boost/noncopyable.hpp>


namespace neosystem {
namespace wg {
namespace log {

/*!
  ログレベル
 */
enum class log_level_type {
	ERROR = 3,
	WARNING = 4,
	INFO = 6,
	DEBUG = 7,
	TRACE = 8,
};

class config;
class stream;


/*!
  log書き込みクラス
 */
class logger : private boost::noncopyable {
private:
	config *conf_;
	stream *stream_;

public:
	logger(void);
	~logger(void);

	void lock(void);
	void unlock(void);
	void write_start(log_level_type);
	void write_end(log_level_type);
	std::ostream& operator()(log_level_type);

	void head(bool);
	void level(log_level_type);
	void rotation_size(int);
	void rotation_count(int);
	bool file(const std::string&);
};


/*!
  log書き込みを行うクラス
 */
class writer : private boost::noncopyable {
private:
	logger& l_;
	log_level_type level_;
	std::ios_base::fmtflags flags_;
	bool moved_flag_;

public:
	writer(logger&, log_level_type);
	writer(writer&&);
	~writer(void);

	std::ostream& operator()(void);
};

log_level_type string_to_level(const std::string&);
const char *level_to_string(log_level_type);

writer trace(logger&);
writer debug(logger&);
writer info(logger&);
writer warning(logger&);
writer error(logger&);

}
}
}

#endif
