#ifndef __OPKELE_CONSUMER_H
#define __OPKELE_CONSUMER_H

#include <opkele/types.h>
#include <opkele/extension.h>

/**
 * @file
 * @brief OpenID consumer-side functionality
 */

namespace opkele {

    /**
     * implementation of basic consumer functionality
     */
    class consumer_t {
	public:

	    /**
	     * store association. The function should be overridden in the real
	     * implementation to provide persistent associations store.
	     * @param server the OpenID server
	     * @param handle association handle
	     * @param secret the secret associated with the server and handle
	     * @param expires_in the number of seconds until the handle is expired
	     * @return the auto_ptr<> for the newly allocated association_t object
	     */
	    virtual assoc_t store_assoc(const string& server,const string& handle,const secret_t& secret,int expires_in) = 0;
	    /**
	     * retrieve stored association. The function should be overridden
	     * in the real implementation to provide persistent assocations
	     * store.
	     * @param server the OpenID server
	     * @param handle association handle
	     * @return the autho_ptr<> for the newly allocated association_t object
	     * @throw failed_lookup in case of error
	     */
	    virtual assoc_t retrieve_assoc(const string& server,const string& handle) = 0;
	    /**
	     * invalidate stored association. The function should be overridden
	     * in the real implementation of the consumer.
	     * @param server the OpenID server
	     * @param handle association handle
	     */
	    virtual void invalidate_assoc(const string& server,const string& handle) = 0;
	    /**
	     * retrieve any unexpired association for the server. If the
	     * function is not overridden in the real implementation, the new
	     * association will be established for each request.
	     * @param server the OpenID server
	     * @return the auto_ptr<> for the newly allocated association_t object
	     * @throw failed_lookup in case of absence of the handle
	     */
	    virtual assoc_t find_assoc(const string& server);

	    /**
	     * retrieve the metainformation contained in link tags from the
	     * page pointed by url. the function may implement caching of the
	     * information.
	     * @param url url to harvest for link tags
	     * @param server reference to the string object where to put
	     * openid.server value
	     * @param delegate reference to the string object where to put the
	     * openid.delegate value (if any)
	     */
	    virtual void retrieve_links(const string& url,string& server,string& delegate);

	    /**
	     * perform the associate request to OpenID server.
	     * @param server the OpenID server
	     * @return the auto_ptr<> for the newly allocated association_t
	     * object, representing established association
	     * @throw exception in case of error
	     */
	    assoc_t associate(const string& server);
	    /**
	     * prepare the parameters for the checkid_immediate
	     * request.
	     * @param identity the identity to verify
	     * @param return_to the return_to url to pass with the request
	     * @param trust_root the trust root to advertise with the request
	     * @param ext pointer to an extension(s) hooks object
	     * @return the location string
	     * @throw exception in case of error
	     */
	    virtual string checkid_immediate(const string& identity,const string& return_to,const string& trust_root="",extension_t *ext=0);
	    /**
	     * prepare the parameters for the checkid_setup
	     * request.
	     * @param identity the identity to verify
	     * @param return_to the return_to url to pass with the request
	     * @param trust_root the trust root to advertise with the request
	     * @param ext pointer to an extension(s) hooks object
	     * @return the location string
	     * @throw exception in case of error
	     */
	    virtual string checkid_setup(const string& identity,const string& return_to,const string& trust_root="",extension_t *ext=0);
	    /**
	     * the actual implementation behind checkid_immediate() and
	     * checkid_setup() functions.
	     * @param mode checkid_* mode - either mode_checkid_immediate or mode_checkid_setup
	     * @param identity the identity to verify
	     * @param return_to the return_to url to pass with the request
	     * @param trust_root the trust root to advertise with the request
	     * @param ext pointer to an extension(s) hooks object
	     * @return the location string
	     * @throw exception in case of error
	     */
	    virtual string checkid_(mode_t mode,const string& identity,const string& return_to,const string& trust_root="",extension_t *ext=0);
	    /**
	     * verify the id_res response
	     * @param pin the response parameters
	     * @param identity the identity being checked (if not specified,
	     * @param ext pointer to an extension(s) hooks object
	     * extracted from the openid.identity parameter
	     * @throw id_res_mismatch in case of signature mismatch
	     * @throw id_res_setup in case of openid.user_setup_url failure
	     * (supposedly checkid_immediate only)
	     * @throw id_res_failed in case of failure
	     * @throw exception in case of other failures
	     */
	    virtual void id_res(const params_t& pin,const string& identity="",extension_t *ext=0);
	    /**
	     * perform a check_authentication request.
	     * @param server the OpenID server
	     * @param p request parameters
	     */
	    void check_authentication(const string& server,const params_t& p);

	    /**
	     * make URL canonical, by adding http:// and trailing slash, if needed.
	     * @param url
	     * @return canonicalized url
	     */
	    static string canonicalize(const string& url);

    };

}

#endif /* __OPKELE_CONSUMER_H */
