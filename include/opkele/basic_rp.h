#ifndef __OPKELE_BASIC_RP_H
#define __OPKELE_BASIC_RP_H

#include <string>
#include <opkele/types.h>
#include <opkele/extension.h>

namespace opkele {
    using std::string;

    class basic_RP {
	public:

	    virtual ~basic_RP() { }

	    /**
	     * @name Global persistent store API
	     * These are functions related to the associations with OP storage
	     * and retrieval and nonce records. They provide an interface to
	     * the persistent storage which is shared by all sessions. If the
	     * implementor prefers the dumb mode instead, the function should
	     * throw dumb_RP exception instead.
	     * @see opkele::dumb_RP
	     * @{
	     */
	    /**
	     * Store association and return allocated association object.
	     * @param OP OP endpoint
	     * @param handle association handle
	     * @param type association type
	     * @param secret association secret
	     * @params expires_in the number of seconds association expires in
	     * @return the association object
	     * @throw dumb_RP for dumb RP
	     */
	    virtual assoc_t store_assoc(
		    const string& OP,const string& handle,
		    const string& type,const secret_t& secret,
		    int expires_in) = 0;
	    /**
	     * Find valid unexpired association with an OP.
	     * @param OP OP endpoint URL
	     * @return association found
	     * @throw failed_lookup if no association found
	     * @throw dumb_RP for dumb RP
	     */
	    virtual assoc_t find_assoc(
		    const string& OP) = 0;
	    /**
	     * Retrieve valid association handle for an OP by handle.
	     * @param OP OP endpoint URL
	     * @param handle association handle
	     * @return association found
	     * @throw failed_lookup if no association found
	     * @throw dumb_RP for dumb RP
	     */
	    virtual assoc_t retrieve_assoc(
		    const string& OP,const string& handle) = 0;
	    /**
	     * Invalidate association with OP
	     * @param OP OP endpoint URL
	     * @param handle association handle
	     * @throw dumb_RP for dumb RP
	     */
	    virtual void invalidate_assoc(const string& OP,const string& handle) = 0;

	    /**
	     * Check the nonce validity. That is, check that we haven't
	     * accepted request with this nonce from this OP, yet. May involve
	     * cutting off by the timestamp and checking the rest against the
	     * store of seen nonces.
	     * @param OP OP endpoint URL
	     * @param nonce nonce value
	     * @throw id_res_bad_nonce if the nonce is not to be accepted, i.e.
	     * either too old or seen.
	     */
	    virtual void check_nonce(const string& OP,const string& nonce) = 0;
	    /**
	     * @}
	     */

	    /**
	     * @name Session persistent store API
	     * @{
	     */
	    /**
	     * Retrieve OpenID endpoint being currently used for
	     * authentication. If there is no endpoint available, throw a
	     * no_endpoint exception.
	     * @return reference to the service endpoint object
	     * @see next_endpoint
	     * @throw no_endpoint if no endpoint available
	     */
	    virtual const openid_endpoint_t& get_endpoint() const = 0;
	    /**
	     * Advance to the next endpoint to try.
	     * @see get_endpoint()
	     * @throw no_endpoint if there are no more endpoints
	     */
	    virtual void next_endpoint() = 0;
	    /**
	     * @}
	     */

	    /**
	     * @name Site particulars API
	     * @{
	     */
	    /**
	     * Return an absolute URL of the page being processed, includining
	     * query parameters. It is used to validate return_to URL on
	     * positive assertions.
	     * @return fully qualified url of the page being processed.
	     */
	    virtual const string get_this_url() const = 0;
	    /**
	     * @}
	     */

	    /**
	     * @name OpenID actions
	     * @{
	     */
	    /**
	     * Initiates authentication session, doing discovery, normalization
	     * and whatever implementor wants to do at this point.
	     * @param usi User-supplied identity
	     */
	    virtual void initiate(const string& usi) = 0;
	    /**
	     * Prepare checkid_request.
	     * @param rv reference to the openid message to prepare
	     * @param mode checkid_setup or checkid_immediate
	     * @param return_to the URL OP should redirect to after completion
	     * @param realm authentication realm to pass to OP
	     * @param ext pointer to extension to use in request preparation
	     * @return reference to the openid message
	     */
	    basic_openid_message& checkid_(
		    basic_openid_message& rv,
		    mode_t mode,
		    const string& return_to,const string& realm,
		    extension_t *ext=0);
	    /**
	     * Verify assertion at the end of round-trip.
	     * @param om incoming openid message
	     * @param ext pointer to extention to use in parsing assertion
	     * @throw id_res_setup if checkid_immediate request could not be
	     * completed
	     * @throw id_res_cancel if authentication request was canceled
	     * @throw id_res_mismatch in case of signature mismatch
	     * @throw id_res_bad_return_to if return_to url seems to be
	     * tampered with
	     * @throw id_res_unauthorized if OP is not authorized to make
	     * assertions regarding the identity
	     */
	    void id_res(const basic_openid_message& om,extension_t *ext=0);

	    /**
	     * Establish association with OP
	     * @param OP OP to establish association with
	     * @throw dumb_RP if for a dumb RP
	     */
	    virtual assoc_t associate(const string& OP);
	    /**
	     * Check authentication with OP and invalidate handle if requested
	     * and confirmed
	     * @param OP OP to check with
	     * @param om message to check
	     * @throw failed_check_authentication if OP fails to confirm
	     * authenticity of the assertion
	     */
	    void check_authentication(const string& OP,const basic_openid_message& om);
	    /**
	     * @}
	     */

	    /**
	     * @name Miscellanea
	     * @{
	     */
	    /**
	     * Verify OP authority. Return normally if OP is authorized to make
	     * an assertion, throw an exception otherwise.
	     * @param OP OP endpoint
	     * @param claimed_id claimed identity
	     * @param identity OP-Local identifier
	     * @throw id_res_unauthorized if OP is not authorized to make
	     * assertion regarding this identity.
	     */
	    virtual void verify_OP(const string& OP,
		    const string& claimed_id,const string& identity) const = 0;
	    /**
	     * @}
	     */
    };

}

#endif /* __OPKELE_BASIC_RP_H */
