#include <iostream>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <opkele/exception.h>
#include <opkele/prequeue_rp.h>
#include <opkele/discovery.h>
#include <opkele/uris.h>
#include <opkele/data.h>
#include <opkele/util.h>
#include <opkele/curl.h>
#include <opkele/debug.h>

namespace opkele {

    class __OP_verifier_good_input : public exception {
	public:
	    __OP_verifier_good_input(OPKELE_E_PARS)
		: exception(OPKELE_E_CONS) { }
    };

    class OP_verifier : public iterator<output_iterator_tag,openid_endpoint_t,void> {
	public:
	    const string& OP;
	    const string& id;

	    OP_verifier(const string& o,const string& i)
		: OP(o), id(i) { }

	    OP_verifier& operator*() { return *this; }
	    OP_verifier& operator=(const openid_endpoint_t& oep) {
		if(oep.uri==OP) {
		    if(oep.claimed_id==IDURI_SELECT20
			    || oep.local_id==IDURI_SELECT20 )
			throw bad_input(OPKELE_CP_ "claimed_id is an OP-Id");
		    if(oep.local_id==id)
			throw __OP_verifier_good_input(OPKELE_CP_ "Found corresponding endpoint");
		}
		return *this;
	    }

	    OP_verifier& operator++() { return *this; }
	    OP_verifier& operator++(int) { return *this; }
    };

    void prequeue_RP::verify_OP(const string& OP,const string& claimed_id,const string& id) const {
	try {
	    discover(OP_verifier(OP,id),claimed_id);
	    throw id_res_unauthorized(OPKELE_CP_
		    "OP is not authorized to make an assertion regarding the identity");
	}catch(__OP_verifier_good_input& ovgi) {
	}
    }

    class endpoint_queuer : public iterator<output_iterator_tag,openid_endpoint_t,void> {
	public:
	    prequeue_RP& rp;

	    endpoint_queuer(prequeue_RP& r) : rp(r) { }

	    endpoint_queuer& operator*() { return *this; }
	    endpoint_queuer& operator=(const openid_endpoint_t& oep) {
		rp.queue_endpoint(oep); return *this; }

	    endpoint_queuer& operator++() { return *this; }
	    endpoint_queuer& operator++(int) { return *this; }
    };

    void prequeue_RP::initiate(const string& usi) {
	begin_queueing();
	set_normalized_id( discover(endpoint_queuer(*this),usi) );
	end_queueing();
    }

    void prequeue_RP::set_normalized_id(const string&) {
    }

    const string prequeue_RP::get_normalized_id() const {
	throw not_implemented(OPKELE_CP_ "get_normalized_id() is not implemented");
    }

    const string prequeue_RP::discover(openid_endpoint_output_iterator it,
	    const string& id) const {
	return idiscover(it,id);
    }

}
