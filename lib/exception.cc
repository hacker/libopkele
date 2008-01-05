#include <openssl/err.h>
#include <curl/curl.h>
#include <opkele/exception.h>
#include <opkele/debug.h>

namespace opkele {

#   ifndef OPKELE_HAVE_KONFORKA

    exception::exception(const string& w)
	: _what(w)
    {
	DOUT_("throwing exception(\""<<w<<"\")");
    }

    exception::~exception() throw() {
    }
    const char *exception::what() const throw() {
	return _what.c_str();
    }

#   else
    
    exception::exception(const string& fi,const string& fu,int l,const string& w)
	: konforka::exception(fi,fu,l,w)
    {
	DOUT_("throwing exception(\""<<w<<"\")");
	DOUT_(" from "<<fi<<':'<<fu<<':'<<l);
    }

#   endif

    exception_openssl::exception_openssl(OPKELE_E_PARS)
	: exception(OPKELE_E_CONS_ w+" ["+ERR_error_string(ERR_peek_last_error(),0)+']'),
	_error(ERR_peek_last_error()),
	_ssl_string(ERR_error_string(_error,0)) {
	}

    exception_curl::exception_curl(OPKELE_E_PARS)
	: exception_network(OPKELE_E_CONS), _error(CURLE_OK) { }
    exception_curl::exception_curl(OPKELE_E_PARS,CURLcode e)
	: exception_network(OPKELE_E_CONS_ w+" ["+curl_easy_strerror(e)+']'),
	_error(e), _curl_string(curl_easy_strerror(e)) { }

    exception_tidy::exception_tidy(OPKELE_E_PARS)
	: exception(OPKELE_E_CONS), _rc(0) { }
    exception_tidy::exception_tidy(OPKELE_E_PARS,int r)
	: exception(OPKELE_E_CONS),
	_rc(r) { }

}
