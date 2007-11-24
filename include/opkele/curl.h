#ifndef __OPKELE_CURL_H
#define __OPKELE_CURL_H

#include <curl/curl.h>

namespace opkele {

    namespace util {

	class curl_t {
	    public:
		CURL *_c;

		curl_t() : _c(0) { }
		curl_t(CURL *c) : _c(c) { }
		~curl_t() throw() { if(_c) curl_easy_cleanup(_c); }

		curl_t& operator=(CURL *c) { if(_c) curl_easy_cleanup(_c); _c=c; return *this; }

		operator const CURL*(void) const { return _c; }
		operator CURL*(void) { return _c; }
	};

    }

}

#endif /* __OPKELE_CURL_H */
