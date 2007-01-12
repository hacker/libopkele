#ifndef __OPKELE_XSERVER_H
#define __OPKELE_XSERVER_H

/**
 * @file
 * @brief OpenID server with built-in extension chain
 */

#include <opkele/extension_chain.h>
#include <opkele/server.h>

/**
 * @brief the main opkele namespace
 */
namespace opkele {

    /**
     * Extended OpenID server implementationwith built in
     * extensions chain.
     */
    class xserver_t : public server_t, public extension_chain_t {
	public:

	    void checkid_immediate(const params_t& pin,string& return_to,params_t& pout,extension_t *ext=0) {
		server_t::checkid_immediate(pin,return_to,pout,this);
	    }
	    void checkid_setup(const params_t& pin,string& return_to,params_t& pout,extension_t *ext=0) {
		server_t::checkid_setup(pin,return_to,pout,this);
	    }
	    void checkid_(mode_t mode,const params_t& pin,string& return_to,params_t& pout,extension_t *ext=0) {
		server_t::checkid_(mode,pin,return_to,pout,this);
	    }
    };

}

#endif /* __OPKELE_XSERVER_H */
