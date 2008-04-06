#ifndef __OPKELE_CURL_H
#define __OPKELE_CURL_H

#include <cassert>
#include <string>
#include <algorithm>
#include <curl/curl.h>

namespace opkele {
    using std::min;
    using std::string;

    namespace util {

	class curl_slist_t {
	    public:
		curl_slist *_s;

		curl_slist_t() : _s(0) { }
		curl_slist_t(curl_slist *s) : _s(s) { }
		virtual ~curl_slist_t() throw();

		curl_slist_t& operator=(curl_slist *s);

		operator const curl_slist*(void) const { return _s; }
		operator curl_slist*(void) { return _s; }

		void append(const char *str);
		void append(const string& str) {
		    append(str.c_str()); }
	};

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
		inline CURLcode easy_setopt(CURLoption o,const curl_slist_t& p) {
		    assert(_c); return curl_easy_setopt(_c,o,(const curl_slist*)p); }
		CURLcode easy_perform() { assert(_c); return curl_easy_perform(_c); }
		template<typename IT>
		    inline CURLcode easy_getinfo(CURLINFO i,IT p) { assert(_c); return curl_easy_getinfo(_c,i,p); }

		static inline CURL *easy_init() { return curl_easy_init(); }

		virtual size_t write(void* /* p */,size_t /* s */,size_t /* nm */) { return 0; }
		CURLcode set_write();

		virtual int progress(double /* dlt */,double /* dln*/ ,double /* ult */,double /* uln */) { return 0; }
		CURLcode set_progress();

		virtual size_t header(void* /* p */,size_t s,size_t nm) { return s*nm; }
		CURLcode set_header();
	};

	template<int lim>
	    class curl_fetch_string_t : public curl_t {
		public:
		    curl_fetch_string_t(CURL *c)
			: curl_t(c) { }
		    ~curl_fetch_string_t() throw() { }

		    string response;

		    size_t write(void *p,size_t size,size_t nmemb) {
			size_t bytes = size*nmemb;
			size_t get = min(lim-response.length(),bytes);
			response.append((const char *)p,get);
			return get;
		    }
	    };

	typedef curl_fetch_string_t<16384> curl_pick_t;


    }

}

#endif /* __OPKELE_CURL_H */
