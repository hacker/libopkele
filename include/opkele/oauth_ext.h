#ifndef __OPKELE_OAUTH_EXT_H
#define __OPKELE_OAUTH_EXT_H

/**
 * @file
 * @brief OAuth extension
 */

#include <opkele/extension.h>

namespace opkele {

    /**
     * OpenID OAuth extension
     * http://step2.googlecode.com/svn/spec/openid_oauth_extension/latest/openid_oauth_extension.html
     */
    class oauth_ext_t : public extension_t {
	public:
	    std::string m_consumer, m_scope, m_request_token;

	    /**
	     * Consumer constructor.
	     * @param fr required fields
	     * @see fields_required
	     * @param fo optional fields
	     * @see fields_optional
	     * @param pu policy url
	     * @see policy_url
	     */
	    oauth_ext_t(const char *consumer = "", const char *scope = "") : m_consumer(consumer), m_scope(scope) { }

	    virtual void rp_checkid_hook(basic_openid_message& om);
	    virtual void rp_id_res_hook(const basic_openid_message& om,
		    const basic_openid_message& sp);
	    virtual void op_checkid_hook(const basic_openid_message& inm);
	    virtual void op_id_res_hook(basic_openid_message& oum);

	    virtual void checkid_hook(basic_openid_message& om);
	    virtual void id_res_hook(const basic_openid_message& om,
		    const basic_openid_message& sp);
	    virtual void checkid_hook(const basic_openid_message& inm,
		    basic_openid_message& oum);

	    /**
	     * Function called after parsing sreg request to set up response
	     * fields. The default implementation tries to send as much fields
	     * as we have. The function is supposed to set the data and
	     * fields_response.
	     * @see fields_response
	     * @param inm incoming openid message
	     * @param oum outgoing openid message
	     */
	    virtual void setup_response(const basic_openid_message& inm,
		    basic_openid_message& oum);

	    virtual void setup_response();

    };
}

#endif /* __OPKELE_OAUTH_EXT_H */

