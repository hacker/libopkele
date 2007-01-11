#ifndef __OPKELE_EXTENSION_H
#define __OPKELE_EXTENSION_H

/**
 * @file
 * @brief extensions framework basics
 */

#include <opkele/types.h>

/**
 * @brief the main opkele namespace
 */
namespace opkele {

    /**
     * OpenID extension hooks base class
     */
    class extension_t {
	public:
	    /**
	     * hook called by consumer before submitting data to OpenID server.
	     * It is supposed to manipulate parameters list.
	     * @param p parameters about to be submitted to server
	     * @param identity identity being verified. It may differ from the
	     * one available in parameters list in case of delegation
	     */
	    virtual void checkid_hook(params_t& p,const string& identity);
	    /**
	     * hook called by consumer after identity information received from
	     * OpenID server is verified.
	     * @param p parameters received from server
	     * @param sp signed parameters received from server with 'openid.'
	     * leader stripped
	     * @param identity identity confirmed. May differ from the one
	     * available in parameters list in case of delegation. May also be
	     * empty which means - extract one from parameters
	     */
	    virtual void id_res_hook(const params_t& p,const params_t& sp,const string& identity);

	    /**
	     * hook called by server before returning information to consumer.
	     * The hook may manipulate output parameters. It is important to
	     * note that modified pout["signed"] is used for signing response.
	     * @param pin request parameters list
	     * @param put response parameters list
	     */
	    virtual void checkid_hook(const params_t& pin,params_t& pout);

	    /**
	     * Casts the object to pointer to itself. For convenient passing
	     * of pointer.
	     */
	    operator extension_t*(void) { return this; }
    };

}

#endif /* __OPKELE_EXTENSION_H */
