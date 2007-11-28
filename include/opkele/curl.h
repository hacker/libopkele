#ifndef __OPKELE_CURL_H
#define __OPKELE_CURL_H

#include <cassert>
#include <curl/curl.h>

namespace opkele {

    namespace util {

	class curl_t {
	    public:
		CURL *_c;

		curl_t() : _c(0) { }
		curl_t(CURL *c) : _c(c) { }
		virtual ~curl_t() throw();

		curl_t& operator=(CURL *c);

		operator const CURL*(void) const { return _c; }
		operator CURL*(void) { return _c; }

		CURLcode misc_sets();

		template<typename PT>
		    inline CURLcode easy_setopt(CURLoption o,PT p) { assert(_c); return curl_easy_setopt(_c,o,p); }
		CURLcode easy_perform() { assert(_c); return curl_easy_perform(_c); }
		template<typename IT>
		    inline CURLcode easy_getinfo(CURLINFO i,IT p) { assert(_c); return curl_easy_getinfo(_c,i,p); }

		static inline CURL *easy_init() { return curl_easy_init(); }

		virtual size_t write(void *p,size_t s,size_t nm) { return 0; }
		CURLcode set_write();

		virtual int progress(double dlt,double dln,double ult,double uln) { return 0; }
		CURLcode set_progress();

		virtual size_t header(void *p,size_t s,size_t nm) { return s*nm; }
		CURLcode set_header();
	};

    }

}

#endif /* __OPKELE_CURL_H */
