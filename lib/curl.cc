#include <opkele/exception.h>
#include <opkele/curl.h>

#include "config.h"

namespace opkele {

    namespace util {

	curl_slist_t::~curl_slist_t() throw() {
	    if(_s)
		curl_slist_free_all(_s);
	}

	curl_slist_t& curl_slist_t::operator=(curl_slist *s) {
	    if(_s)
		curl_slist_free_all(_s);
	    _s = s;
	    return *this;
	}

	void curl_slist_t::append(const char *str) {
	    curl_slist *s = curl_slist_append(_s,str);
	    if(!s)
		throw opkele::exception(OPKELE_CP_ "failed to curl_slist_append()");
	    _s=s;
	}

	curl_t::~curl_t() throw() {
	    if(_c)
		curl_easy_cleanup(_c);
	}

	curl_t& curl_t::operator=(CURL *c) {
	    if(_c)
		curl_easy_cleanup(_c);
	    _c = c;
	    return *this;
	}

	CURLcode curl_t::misc_sets() {
	    assert(_c);
	    CURLcode r;
	    (r=easy_setopt(CURLOPT_FOLLOWLOCATION,1))
	    || (r=easy_setopt(CURLOPT_MAXREDIRS,5))
	    || (r=easy_setopt(CURLOPT_DNS_CACHE_TIMEOUT,120))
	    || (r=easy_setopt(CURLOPT_DNS_USE_GLOBAL_CACHE,1))
	    || (r=easy_setopt(CURLOPT_USERAGENT,PACKAGE_NAME"/"PACKAGE_SRC_VERSION))
	    || (r=easy_setopt(CURLOPT_TIMEOUT,20))
#ifdef	DISABLE_CURL_SSL_VERIFYHOST
	    || (r=easy_setopt(CURLOPT_SSL_VERIFYHOST,0))
#endif
#ifdef	DISABLE_CURL_SSL_VERIFYPEER
	    || (r=easy_setopt(CURLOPT_SSL_VERIFYPEER,0))
#endif
	    ;
	    return r;
	}

	static size_t _write(void *p,size_t s,size_t nm,void *stream) {
	    return ((curl_t*)stream)->write(p,s,nm);
	}

	CURLcode curl_t::set_write() {
	    assert(_c);
	    CURLcode r;
	    (r = easy_setopt(CURLOPT_WRITEDATA,this))
	    || (r = easy_setopt(CURLOPT_WRITEFUNCTION,_write));
	    return r;
	}

	static int _progress(void *cp,double dlt,double dln,double ult,double uln) {
	    return ((curl_t*)cp)->progress(dlt,dln,ult,uln);
	}

	CURLcode curl_t::set_progress() {
	    assert(_c);
	    CURLcode r;
	    (r = easy_setopt(CURLOPT_PROGRESSDATA,this))
	    || (r = easy_setopt(CURLOPT_PROGRESSFUNCTION,_progress))
	    || (r = easy_setopt(CURLOPT_NOPROGRESS,0));
	    return r;
	}

	static size_t _header(void *p,size_t s,size_t nm,void *stream) {
	    return ((curl_t*)stream)->header(p,s,nm);
	}

	CURLcode curl_t::set_header() {
	    assert(_c);
	    CURLcode r;
	    (r = easy_setopt(CURLOPT_HEADERDATA,this))
	    || (r=easy_setopt(CURLOPT_HEADERFUNCTION,_header));
	    return r;
	}

    }

}
