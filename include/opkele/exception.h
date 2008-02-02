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
 * open function-try-block
 */
# define OPKELE_FUNC_TRY try
/**
 * the simple rethrow of konforka-based exception
 */
# define OPKELE_RETHROW catch(konforka::exception& e) { e.see(CODEPOINT); throw; }
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
 * the dummy define for the opening function-try-block
 */
# define OPKELE_FUNC_TRY
/**
 * the dummy define for the konforka-based rethrow of exception
 */
# define OPKELE_RETHROW
#endif /* OPKELE_HAVE_KONFORKA */
/**
 * the exception parameters list to pass to constructor
 */
# define OPKELE_E_CONS OPKELE_E_CONS_ w

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
		exception(const string& fi,const string& fu,int l,const string& w);
#           else /* OPKELE_HAVE_KONFORKA */
	    string _what;
	    explicit exception(const string& w);
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
	    id_res_setup(OPKELE_E_PARS,const string& su="")
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
     * thrown if the association has expired before it could've been verified.
     */
    class id_res_expired_on_delivery : public id_res_failed {
	public:
	    id_res_expired_on_delivery(OPKELE_E_PARS)
		: id_res_failed(OPKELE_E_CONS) { }
    };

    /**
     * thown when the user cancelled authentication process.
     */
    class id_res_cancel : public id_res_failed {
	public:
	    id_res_cancel(OPKELE_E_PARS)
		: id_res_failed(OPKELE_E_CONS) { }
    };

    /**
     * thrown in case of nonce reuse or otherwise imperfect nonce.
     */
    class id_res_bad_nonce : public id_res_failed {
	public:
	    id_res_bad_nonce(OPKELE_E_PARS)
		: id_res_failed(OPKELE_E_CONS) { }
    };

    /**
     * thrown if return_to didn't pass verification
     */
    class id_res_bad_return_to : public id_res_failed {
	public:
	    id_res_bad_return_to(OPKELE_E_PARS)
		: id_res_failed(OPKELE_E_CONS) { }
    };

    /**
     * thrown if OP isn't authorized to make an assertion
     */
    class id_res_unauthorized : public id_res_failed {
	public:
	    id_res_unauthorized(OPKELE_E_PARS)
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

    /**
     * htmltidy related error occured
     */
    class exception_tidy : public exception {
	public:
	    int _rc;
	    exception_tidy(OPKELE_E_PARS);
	    exception_tidy(OPKELE_E_PARS,int r);
	    ~exception_tidy() throw() { }
    };

    /**
     * exception thrown in case of failed discovery
     */
    class failed_discovery : public exception {
	public:
	    failed_discovery(OPKELE_E_PARS)
		: exception(OPKELE_E_CONS) { }
    };

    /**
     * unsuccessfull xri resolution
     */
    class failed_xri_resolution : public failed_discovery {
	public:
	    long _code;
	    failed_xri_resolution(OPKELE_E_PARS,long _c=-1)
		: failed_discovery(OPKELE_E_CONS), _code(_c) { }
    };

    /**
     * not implemented (think pure virtual) member function executed, signfies
     * programmer error
     */
    class not_implemented : public exception {
	public:
	    not_implemented(OPKELE_E_PARS)
		: exception(OPKELE_E_CONS) { }
    };

    /**
     * internal error, indicates internal libopkele problem
     */
    class internal_error : public exception {
	public:
	    internal_error(OPKELE_E_PARS)
		: exception(OPKELE_E_CONS) { }
    };

    /**
     * thrown in case of unsupported parameter encountered (e.g. unsupported
     * association type).
     */
    class unsupported : public exception {
	public:
	    unsupported(OPKELE_E_PARS)
		: exception(OPKELE_E_CONS) { }
    };

    /**
     * thrown by associations store related functions in case of dumb RP.
     */
    class dumb_RP : public exception {
	public:
	    dumb_RP(OPKELE_E_PARS)
		: exception(OPKELE_E_CONS) { }
    };

    /**
     * thrown by endpoint-queue related function if endpoint is being
     * accessed but there's no endpoint available.
     */
    class no_endpoint : public exception {
	public:
	    no_endpoint(OPKELE_E_PARS)
		: exception(OPKELE_E_CONS) { }
    };

    /**
     * thrown while processing OpenID request in OP. Signifies invalid realm
     */
    class bad_realm : public exception {
	public:
	    bad_realm(OPKELE_E_PARS)
		: exception(OPKELE_E_CONS) { }
    };

    /**
     * thrown when attempting to retrieve return_to of one-way request
     */
    class no_return_to : public exception {
	public:
	    no_return_to(OPKELE_E_PARS)
		: exception(OPKELE_E_CONS) { }
    };

    /**
     * thrown when querying identity of non-identity related request
     */
    class non_identity : public exception {
	public:
	    non_identity(OPKELE_E_PARS)
		: exception(OPKELE_E_CONS) { }
    };

    /**
     * thrown if return_to URL doesn't match realm
     */
    class bad_return_to : public exception {
	public:
	    bad_return_to(OPKELE_E_PARS)
		: exception(OPKELE_E_CONS) { }
    };

}

#endif /* __OPKELE_EXCEPTION_H */
