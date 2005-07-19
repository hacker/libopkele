#ifndef __OPKELE_EXCEPTION_H
#define __OPKELE_EXCEPTION_H

/**
 * @file
 * @brief opkele exceptions
 */

#include <curl/curl.h>

#include <opkele/opkele-config.h>
#ifdef OPKELE_HAVE_KONFORKA
# include <konforka/exception.h>
/**
 * the exception parameters declaration
 */
# define OPKELE_E_PARS const string& fi,const string&fu,int l,const string& w
/**
 * the exception parameters list to pass to constructor
 */
# define OPKELE_E_CONS_ fi,fu,l,
/**
 * the exception codepoint specification
 */
# define OPKELE_CP_ CODEPOINT,
/**
 * the simple rethrow of konforka-based exception
 */
# define OPKELE_RETHROW catch(konforka::exception& e) { e.see(CODEPOINT); throw }
#else /* OPKELE_HAVE_KONFORKA */
# include <exception>
# include <string>
/**
 * the exception parameter declaration
 */
# define OPKELE_E_PARS const string& w
/**
 * the dummy prefix for exception parameters list to prepend in the absence of
 * konforka library
 */
# define OPKELE_E_CONS_ 
/**
 * the dummy placeholder for konforka exception codepoint specification
 */
# define OPKELE_CP_
/**
 * the dummy define for the konforka-based rethrow of exception
 */
# define OPKELE_RETHROW
#endif /* OPKELE_HAVE_KONFORKA */
/**
 * the exception parameters list to pass to constructor
 */
# define OPKELE_E_CONS OPKELE_E_CONS_ w

/*
 * @brief the main opkele namespace
 */
namespace opkele {
    using std::string;

    /**
     * the base opkele exception class
     */
    class exception : public
#   ifdef OPKELE_HAVE_KONFORKA
		      konforka::exception
#   else
                      std::exception
#   endif
    {
	public:
#           ifdef OPKELE_HAVE_KONFORKA
	    explicit
		exception(const string& fi,const string& fu,int l,const string& w)
		    : konforka::exception(fi,fu,l,w) { }
#           else /* OPKELE_HAVE_KONFORKA */
	    string _what;
	    explicit
		exception(const string& w)
		    : _what(w) { } 
	    virtual ~exception() throw();
	    virtual const char * what() const throw();
#           endif /* OPKELE_HAVE_KONFORKA */
    };

    /**
     * thrown in case of failed conversion
     */
    class failed_conversion : public exception {
	public:
	    failed_conversion(OPKELE_E_PARS)
		: exception(OPKELE_E_CONS) { }
    };
    /**
     * thrown in case of failed lookup (either parameter or persistent store)
     */
    class failed_lookup : public exception {
	public:
	    failed_lookup(OPKELE_E_PARS)
		: exception(OPKELE_E_CONS) { }
    };
    /**
     * thrown in case of bad input (either local or network)
     */
    class bad_input : public exception {
	public:
	    bad_input(OPKELE_E_PARS)
		: exception(OPKELE_E_CONS) { }
    };

    /**
     * thrown on failed assertion
     */
    class failed_assertion : public exception {
	public:
	    failed_assertion(OPKELE_E_PARS)
		: exception(OPKELE_E_CONS) { }
    };

    /**
     * thrown if the handle being retrieved is invalid
     */
    class invalid_handle : public exception {
	public:
	    invalid_handle(OPKELE_E_PARS)
		: exception(OPKELE_E_CONS) { }
    };
    /**
     * thrown if the handle passed to check_authentication request is not
     * stateless
     */
    class stateful_handle : public exception {
	public:
	    stateful_handle(OPKELE_E_PARS)
		: exception(OPKELE_E_CONS) { }
    };

    /**
     * thrown if check_authentication request fails
     */
    class failed_check_authentication : public exception {
	public:
	    failed_check_authentication(OPKELE_E_PARS)
		: exception(OPKELE_E_CONS) { }
    };

    /**
     * thrown if the id_res request result is negative
     */
    class id_res_failed : public exception {
	public:
	    id_res_failed(OPKELE_E_PARS)
		: exception(OPKELE_E_CONS) { }
    };
    /**
     * thrown if the user_setup_url is provided with negative response
     */
    class id_res_setup : public id_res_failed {
	public:
	    string setup_url;
	    id_res_setup(OPKELE_E_PARS,const string& su)
		: id_res_failed(OPKELE_E_CONS), setup_url(su) { }
	    ~id_res_setup() throw() { }
    };
    /**
     * thrown in case of signature mismatch
     */
    class id_res_mismatch : public id_res_failed {
	public:
	    id_res_mismatch(OPKELE_E_PARS)
		: id_res_failed(OPKELE_E_CONS) { }
    };

    /**
     * openssl malfunction occured
     */
    class exception_openssl : public exception {
	public:
	    unsigned long _error;
	    string _ssl_string;
	    exception_openssl(OPKELE_E_PARS);
	    ~exception_openssl() throw() { }
    };

    /**
     * network operation related error occured
     */
    class exception_network : public exception {
	public:
	    exception_network(OPKELE_E_PARS)
		: exception(OPKELE_E_CONS) { }
    };

    /**
     * network operation related error occured, specifically, related to
     * libcurl
     */
    class exception_curl : public exception_network {
	public:
	    CURLcode _error;
	    string _curl_string;
	    exception_curl(OPKELE_E_PARS);
	    exception_curl(OPKELE_E_PARS,CURLcode e);
	    ~exception_curl() throw() { }
    };

}

#endif /* __OPKELE_EXCEPTION_H */
