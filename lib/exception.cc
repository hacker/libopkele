#include <openssl/err.h>
#include <curl/curl.h>
#include <opkele/exception.h>

namespace opkele {

#   ifndef OPKELE_HAVE_KONFORKA

    exception::~exception() throw() {
    }
    const char *exception::what() const throw() {
	return _what.c_str();
    }
    
#   endif

    exception_openssl::exception_openssl(OPKELE_E_PARS)
	: _error(ERR_peek_last_error()),
	_ssl_string(ERR_error_string(_error,0)),
	exception(OPKELE_E_CONS_ w+" ["+_ssl_string+']') {
	}

    exception_curl::exception_curl(OPKELE_E_PARS)
	: _error(CURLE_OK),
	exception_network(OPKELE_E_CONS) { }
    exception_curl::exception_curl(OPKELE_E_PARS,CURLcode e)
	: _error(e),
	_curl_string(curl_easy_strerror(e)),
	exception_network(OPKELE_E_CONS_ w+" ["+curl_easy_strerror(e)+']') {
	}

}
