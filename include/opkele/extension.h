#ifndef __OPKELE_EXTENSION_H
#define __OPKELE_EXTENSION_H

/**
 * @file
 * @brief extensions framework basics
 */

#include <opkele/opkele-config.h>
#include <opkele/types.h>

namespace opkele {

    /**
     * OpenID extension hooks base class
     */
    class extension_t {
	public:

	    virtual ~extension_t() { }

	    /**
	     * hook called by RP before submitting the message to OP.
	     * @param om openid message to be submit
	     */
	    virtual void rp_checkid_hook(basic_openid_message& om);

	    /**
	     * hook called by RP after verifying information received from OP.
	     * @param om openid message received
	     * @param sp signed part of the message
	     */
	    virtual void rp_id_res_hook(const basic_openid_message& om,
		    const basic_openid_message& sp);

	    /**
	     * hook called by OP after parsing incoming message
	     * @param inm message received from RP
	     */
	    virtual void op_checkid_hook(const basic_openid_message& inm);
	    /**
	     * hook called by OP before signing the reply to RP
	     * @param oum message to be sent to RP
	     */
	    virtual void op_id_res_hook(basic_openid_message& oum);

	    virtual void checkid_hook(basic_openid_message& om) OPKELE_DEPRECATE;
	    virtual void id_res_hook(const basic_openid_message& om,
		    const basic_openid_message& sp) OPKELE_DEPRECATE;
	    virtual void checkid_hook(const basic_openid_message& inm,basic_openid_message& oum);

	    /**
	     * Casts the object to pointer to itself. For convenient passing
	     * of pointer.
	     */
	    operator extension_t*(void) { return this; }
    };

}

#endif /* __OPKELE_EXTENSION_H */
