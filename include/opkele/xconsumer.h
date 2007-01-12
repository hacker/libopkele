#ifndef __OPKELE_XCONSUMER_H
#define __OPKELE_XCONSUMER_H

/**
 * @file
 * @brief OpenID consumer with built-in extension chain
 */

#include <opkele/extension_chain.h>
#include <opkele/consumer.h>

/**
 * @brief the main opkele namespace
 */
namespace opkele {

    /**
     * Extended OpenID consumer implementation with built in
     * extensions chain.
     */
    class xconsumer_t : public consumer_t, public extension_chain_t {
	public:

	    string checkid_immediate(const string& identity,const string& return_to,const string& trust_root="",extension_t *ext=0) {
		return consumer_t::checkid_immediate(identity,return_to,trust_root,this);
	    }
	    string chekid_setup(const string& identity,const string& return_to,const string& trust_root="",extension_t *ext=0) {
		return consumer_t::checkid_setup(identity,return_to,trust_root,this);
	    }
	    string checkid_(mode_t mode,const string& identity,const string& return_to,const string& trust_root="",extension_t *ext=0) {
		return consumer_t::checkid_(mode,identity,return_to,trust_root,this);
	    }
	    void id_res(const params_t& pin,const string& identity="",extension_t *ext=0) {
		consumer_t::id_res(pin,identity,this);
	    }

    };

}

#endif /* __OPKELE_XCONSUMER_H */
