#include <opkele/verify_op.h>
#include <opkele/discovery.h>
#include <opkele/exception.h>
#include <opkele/util.h>
#include <opkele/uris.h>

namespace opkele {
    using std::output_iterator_tag;

    class __RP_verifier_good_input : public exception {
	public:
	    __RP_verifier_good_input(OPKELE_E_PARS)
		: exception(OPKELE_E_CONS) { }
    };

    class RP_verifier : public iterator<output_iterator_tag,openid_endpoint_t,void> {
	public:
	    const string& return_to;
	    int seen;

	    RP_verifier(const string& rt)
		: return_to(rt), seen(0) { }

	    RP_verifier& operator*() { return *this; }
	    RP_verifier& operator=(const openid_endpoint_t& oep) {
		if(util::uri_matches_realm(return_to,oep.uri))
		    throw __RP_verifier_good_input(OPKELE_CP_ "Found matching realm");
		return *this;
	    }

	    RP_verifier& operator++() { ++seen; return *this; }
	    RP_verifier& operator++(int) { ++seen; return *this; }
    };

    void verify_OP::verify_return_to() {
	basic_OP::verify_return_to();
	try {
	    RP_verifier rpv(return_to);
	    string drealm = realm;
	    string::size_type csss = drealm.find("://*.");
	    if(csss==4 || csss==5)
		drealm.replace(csss+3,1,"www");
	    const char *rtt[] = { STURI_OPENID20_RT, 0 };
	    yadiscover(rpv,drealm,rtt,false);
	    if(rpv.seen)
		throw bad_return_to(OPKELE_CP_ "return_to URL doesn't match any found while doing discovery on RP");
	}catch(__RP_verifier_good_input&) {
	}catch(bad_return_to& brt) {
	    throw;
	}catch(exception_network&) { }
    }

}
