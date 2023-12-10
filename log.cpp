#include <fstream>
#include <iomanip>
#include <thread>
#include <mutex>
#include <filesystem>
#include <utility>

#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/device/null.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include "log.hpp"


namespace neosystem {
namespace wg {
namespace log {


/*!
  ログの設定保持クラス
 */
class config {
private:
	log_level_type level_;  //!< ログレベル
	bool need_head_; //!< 行の先頭に日付等を出力するか

	/*!
	  ログローテーションの設定保持構造体
	 */
	struct RotationConfig {
		int rotation_size;  //!< ローテーションするサイズ上限
		int file_count;     //!< ファイル数

		RotationConfig(void) : rotation_size(5368709), file_count(8) {
		}
	} rotation_;

public:
	config(void) : level_(log_level_type::DEBUG), need_head_(true), rotation_() {
	}

	log_level_type get_level(void) const { return level_; }
	bool get_need_head(void) const { return need_head_; }
	int get_rotation_size(void) const { return rotation_.rotation_size; }
	int get_rotation_count(void) const { return rotation_.file_count; }

	void set_level(log_level_type i) { level_ = i; }
	void set_need_head(bool b) { need_head_ = b; }
	void set_rotation_size(int i) { rotation_.rotation_size = i; }
	void set_rotation_count(int i) { rotation_.file_count = i; }
};


/*!
  ログ出力先ストリームの管理を行うクラス
 */
class stream {
private:
	const config& conf_;             //!< ログの設定
	std::mutex mutex_;        //!< 出力先の保護用
	std::ofstream stream_;           //!< 出力先ストリーム
	boost::iostreams::stream<boost::iostreams::null_sink> null_;    //!< ログレベルが指定未満の場合に使うストリーム
	std::filesystem::path path_;   //!< 出力先ファイルパス
	std::string host_;               //!< ホスト名

	/*!
	  指定ログファイルのオープン

	  @param[in] path ログファイルのパス

	  @return 成功したらtrueを返す
	 */
	bool open(const std::string& path) {
		if (path.empty() || path == "stdout") return false;
		try {
			stream_.open(path.c_str(), std::ios::app);
			if (!stream_) {
				std::cerr << "open log file error. (" << path << ")" << std::endl;
				return false;
			}
		} catch (...) {
			std::cerr << "open log file error. (" << path << ")" << std::endl;
			return false;
		}
		return true;
	}

	/*!
	  ログの日付等の出力

	  @param[in] stream 書き込み先
	  @param[in] host ホスト名
	  @param[in] level ログレベル
	 */
	static void write_head(std::ostream& stream, const std::string& host, log_level_type level) {
		boost::posix_time::ptime now = boost::posix_time::microsec_clock::local_time();

		write_date_time(stream, now);
		stream << " " << host << " [" << getpid() << ":" << std::this_thread::get_id() << "] (" <<
			std::setw(5) << std::setfill(' ') << std::left << level_to_string(level) << std::right << "): "
			;
		return;
	}

	static void write_date_time(std::ostream& stream, const boost::posix_time::ptime& t) {
		boost::posix_time::time_facet *f = new boost::posix_time::time_facet("%Y/%m/%d %T.%f");
		stream.imbue(std::locale(stream.getloc(), f));
		stream << t;
		return;
	}

	/*!
	  ファイルローテーション

	  @param[in] path 現在のファイルのパス
	 */
	bool rotate(const std::filesystem::path& path) {
		bool ret = false;

		if (path.empty()) return false;
		try {
			const boost::uintmax_t size = std::filesystem::file_size(path);
			if (size < (boost::uintmax_t) conf_.get_rotation_size()) return false;

			if (stream_.is_open()) stream_.close();
			ret = true;
			std::filesystem::path src, dst;
			std::string tmp;
			for (int i = conf_.get_rotation_count() - 1; i > 0; --i) {
				if(i == 1){
					src = path;
				} else {
					tmp = ".";
					tmp += boost::lexical_cast<std::string>(i - 1);
					src = path.string() + tmp;
				}
				if (std::filesystem::exists(src)) {
					tmp = ".";
					tmp += boost::lexical_cast<std::string>(i);
					dst = path.string() + tmp;
					std::filesystem::rename(src, dst);
				}
			}
		} catch (std::filesystem::filesystem_error& e) {
			std::cerr << e.what() << std::endl;
		}
		return ret;
	}

public:
	/*!
	  コンストラクタ

	  @param[in] conf config
	 */
	stream(const config& conf) : conf_(conf), null_(boost::iostreams::null_sink()) {
		boost::system::error_code ec;
		host_ = boost::asio::ip::host_name(ec);
		if (ec) {
			host_ = "unknown";
		}
	}

	/*!
	  デストラクタ
	 */
	~stream(void) {
		if (stream_.is_open()) {
			stream_.close();
		}
	}

	/*!
	  書き込み先のファイルの設定とオープン

	  @param[in] f ファイルのパスを指定する。空文字列を渡した場合ログの出力先はstd::coutになる。

	  @return 成功したらtrue
	 */
	bool set_path_and_open_file(const std::string& f) {
		std::lock_guard<std::mutex> l(mutex_);
		path_ = f;
		if (f.empty()) {
			if (stream_.is_open()) stream_.close();
			return true;
		}
		return open(f);
	}

	/*!
	  ログレベルに対応したストリームを返す

	  @param[in] l ログレベル

	  @return ストリーム
	 */
	std::ostream& get_stream(log_level_type l) {
		if (l > conf_.get_level()) return null_;
		if (stream_.is_open() == false) return std::cout;
		try {
			if (rotate(path_) != false) open(path_.string());
			if (stream_.is_open() == false) return std::cout;
		} catch (...) {
			return std::cout;
		}
		return stream_;
	}

	/*!
	  必要であればログの先頭文字列を書く

	  @param[in] l ログレベル
	 */
	void write_start(log_level_type l) {
		if (l > conf_.get_level()) return;
		if (conf_.get_need_head()) write_head((stream_.is_open() == false) ? std::cout : stream_, host_, l);
		return;
	}

	/*!
	  改行を出力する

	  @param[in] l ログレベル
	 */
	void write_end(log_level_type l) {
		if (l > conf_.get_level()) return;
		if (stream_.is_open() == false) {
			std::cout << std::endl;
		} else {
			stream_ << std::endl;
		}
		return;
	}

	/*!
	  mutexをlockする
	 */
	void lock(void) {
		mutex_.lock();
	}

	/*!
	  mutexをunlockする
	 */
	void unlock(void) {
		mutex_.unlock();
	}
};


/*!
  コンストラクタ
 */
logger::logger(void)
	: conf_(new config()), stream_(new stream(*conf_)) {
}

/*!
  デストラクタ
 */
logger::~logger(void) {
	delete conf_;
	delete stream_;
}

bool logger::file(const std::string& f) {
	return stream_->set_path_and_open_file(f);
}

void logger::head(bool b) {
	conf_->set_need_head(b);
	return;
}

void logger::level(log_level_type i) {
	conf_->set_level(i);
	return;
}

void logger::rotation_size(int i) {
	conf_->set_rotation_size(i);
	return;
}

void logger::rotation_count(int i) {
	conf_->set_rotation_count(i);
	return;
}

/*!
  書き込みストリームの取得

  @param[in] l ログレベル

  @return ストリーム
 */
std::ostream& logger::operator()(log_level_type l) {
	return stream_->get_stream(l);
}

/*!
  ログの先頭部分の出力

  @param[in] l ログレベル
 */
void logger::write_start(log_level_type l) {
	stream_->write_start(l);
	return;
}

/*!
  改行の出力

  @param[in] l ログレベル
 */
void logger::write_end(log_level_type l) {
	stream_->write_end(l);
	return;
}

/*!
  出力をlockする
 */
void logger::lock(void) {
	stream_->lock();
	return;
}

/*!
  出力をunlockする
 */
void logger::unlock(void) {
	stream_->unlock();
	return;
}


/*!
  コンストラクタ

  @param[in] l logger
  @param[in] level ログレベル
 */
writer::writer(logger& l, log_level_type level)
	: l_(l), level_(level), moved_flag_(false) {
	l_.lock();
	flags_ = l_(level).flags();
	l_.write_start(level);
}

writer::writer(writer&& other)
	: l_(other.l_), level_(other.level_), flags_(other.flags_), moved_flag_(false) {
	other.moved_flag_ = true;
}

/*!
  デストラクタ
 */
writer::~writer(void) {
	if (moved_flag_ == false) {
		l_(level_).flags(flags_);
		l_.write_end(level_);
		l_.unlock();
	}
}

/*!
  書き込みストリームの取得

  @return ログを書き込むストリーム
 */
std::ostream& writer::operator()(void) {
	return l_(level_);
}


writer trace(logger& l) {
	return writer(l, log_level_type::TRACE);
}

writer debug(logger& l) {
	return writer(l, log_level_type::DEBUG);
}

writer info(logger& l) {
	return writer(l, log_level_type::INFO);
}

writer warning(logger& l) {
	return writer(l, log_level_type::WARNING);
}

writer error(logger& l) {
	return writer(l, log_level_type::ERROR);
}

/*!
  文字列をログレベルに変換する

  大文字と小文字は区別しない
  "ERROR"->ERROR
  "WARNING"->WARNING
  "INFO"->INFO
  "DEBUG"->DEBUG
  "TRACE"->TRACE

  @param[in] s 変換元文字列

  @return ログレベル

  @warning 文字列がどのログレベルにも適さない場合、ログレベルERRORを返す
 */
log_level_type string_to_level(const std::string& s) {
#ifdef WIN32
	if (stricmp(s.c_str(), "ERROR") == 0) {
		return log_level_type::ERROR;
	}
	else if (stricmp(s.c_str(), "WARNING") == 0 || stricmp(s.c_str(), "WARN") == 0) {
		return log_level_type::WARNING;
	}
	else if (stricmp(s.c_str(), "INFO") == 0) {
		return log_level_type::INFO;
	}
	else if (stricmp(s.c_str(), "DEBUG") == 0) {
		return log_level_type::DEBUG;
	}
	else if (stricmp(s.c_str(), "TRACE") == 0) {
		return log_level_type::TRACE;
	}
#else
	if (strcasecmp(s.c_str(), "ERROR") == 0) {
		return log_level_type::ERROR;
	} else if (strcasecmp(s.c_str(), "WARNING") == 0 || strcasecmp(s.c_str(), "WARN") == 0) {
		return log_level_type::WARNING;
	} else if (strcasecmp(s.c_str(), "INFO") == 0) {
		return log_level_type::INFO;
	} else if (strcasecmp(s.c_str(), "DEBUG") == 0) {
		return log_level_type::DEBUG;
	} else if (strcasecmp(s.c_str(), "TRACE") == 0) {
		return log_level_type::TRACE;
	}
#endif
	return log_level_type::ERROR;
}

/*!
  ログレベルを表示文字列に変換する

  @param[in] l ログレベル

  @return 表示文字列へのポインタ
 */
const char *level_to_string(log_level_type l) {
	switch (l) {
	case log_level_type::ERROR:
		return "ERROR";
	case log_level_type::WARNING:
		return "WARN";
	case log_level_type::INFO:
		return "INFO";
	case log_level_type::DEBUG:
		return "DEBUG";
	case log_level_type::TRACE:
		return "TRACE";
	}
	return "undefined";
}

}
}
}
