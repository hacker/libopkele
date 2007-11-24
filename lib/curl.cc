#include <opkele/curl.h>

#include "config.h"

namespace opkele {

    namespace util {

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

    }

}
