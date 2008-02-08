#ifndef __OPKELE_BASIC_OP_H
#define __OPKELE_BASIC_OP_H

#include <string>
#include <opkele/types.h>
#include <opkele/extension.h>

namespace opkele {
    using std::string;

    /**
     * Implementation of basic OP functionality
     */
    class basic_OP {
	public:
	    /**
	     * The request mode for the request being processed
	     */
	    mode_t mode;
	    /**
	     * association used in transaction. reset in case of dumb operation
	     */
	    assoc_t assoc;
	    /**
	     * true if the request is openid2 request
	     */
	    bool openid2;
	    /**
	     * The return_to RP endpoint
	     */
	    string return_to;
	    /**
	     * The realm we authenticate for
	     */
	    string realm;
	    /**
	     * Claimed identifier
	     */
	    string claimed_id;
	    /**
	     * The OP-Local identifier
	     */
	    string identity;
	    /**
	     * The invalidate handle for the reply request
	     */
	    string invalidate_handle;

	    virtual ~basic_OP() { }

	    void reset_vars();

	    /**
	     * @name Request information access
	     * Setting and retrieval of the information pertaining to the request being processed
	     * @{
	     */
	    /**
	     * Check if the RP expects us to get back to them.
	     * @return true if RP supplied return_to URL
	     */
	    bool has_return_to() const;
	    /**
	     * Find out where the RP is waiting for us.
	     * @return the return_to URL supplied
	     * @throw no_return_to if no return_to is supplied with the request
	     */
	    const string& get_return_to() const;

	    /**
	     * Find out what realm we are authenticating user for
	     * @return the realm
	     */
	    const string& get_realm() const;

	    /**
	     * Check if request is about identity
	     * @return true if so
	     */
	    bool has_identity() const;
	    /**
	     * Get claimed identifier supplied with the request
	     * @return claimed identifier
	     * @throw non_identity if request is not about identity
	     */
	    const string& get_claimed_id() const;
	    /**
	     * Get the identity (OP-Local identifier) being confirmed
	     * @return identity
	     * @throw non_identity if request is not about identity
	     */
	    const string& get_identity() const;

	    /**
	     * Is identifier supposed to be selected on our side?
	     * @return true if identity is a special identifier select URI
	     */
	    bool is_id_select() const;

	    /**
	     * Select the identity for identifier select request
	     * @param cid claimed identifier
	     * @param lid local identifier
	     */
	    void select_identity(const string& cid,const string& lid);
	    /**
	     * Set claimed identifier (for instance if it's supposed to have
	     * fragment part)
	     * @param cid claimed identifier
	     */
	    void set_claimed_id(const string& cid);
	    /**
	     * @}
	     */

	    /** @name OpenID operations
	     * @{
	     */
	    /**
	     * Establish association with RP
	     * @param oum reply message
	     * @param inm request message
	     */
	    basic_openid_message& associate(
		    basic_openid_message& oum,
		    const basic_openid_message& inm);

	    /**
	     * Parse the checkid_* request. The function parses input message,
	     * retrieves the information needed for further processing,
	     * verifies what can be verified at this stage.
	     * @param inm incoming OpenID message
	     * @param ext extension/chain of extensions supported
	     */
	    void checkid_(const basic_openid_message& inm,extension_t *ext=0);
	    /**
	     * Build and sign a positive assertion message
	     * @param om outpu OpenID message
	     * @param ext extension/chain of extensions supported
	     * @return reference to om
	     */
	    basic_openid_message& id_res(basic_openid_message& om,
		    extension_t *ext=0);
	    /**
	     * Build a 'cancel' negative assertion
	     * @param om output OpenID message
	     * @return reference to om
	     */
	    basic_openid_message& cancel(basic_openid_message& om);
	    /**
	     * Build an 'error' reply
	     * @param om output OpenID message
	     * @param error a human-readable message indicating the cause
	     * @param contact contact address for the server administrator (can be empty)
	     * @param reference a reference token (can be empty)
	     * @return reference to om
	     */
	    basic_openid_message& error(basic_openid_message& om,
		    const string& error,const string& contact,
		    const string& reference );
	    /**
	     * Build a setup_needed reply to checkid_immediate request
	     * @param oum output OpenID message
	     * @param inm incoming OpenID request being processed
	     * @return reference to oum
	     */
	    basic_openid_message& setup_needed(
		    basic_openid_message& oum,const basic_openid_message& inm);

	    /**
	     * Process check_authentication request
	     * @param oum output OpenID message
	     * @param inm incoming request
	     * @return reference to oum
	     */
	    basic_openid_message& check_authentication(
		    basic_openid_message& oum,const basic_openid_message& inm);
	    /**
	     * @}
	     */

	    /**
	     * Verify return_to url. The default implementation checks whether
	     * return_to URI matches the realm
	     * @throw bad_realm in case of invalid realm
	     * @throw bad_return_to if return_to doesn't match the realm
	     * @see verify_OP::verify_return_to()
	     */
	    virtual void verify_return_to();

	    /**
	     * @name Global persistent store API
	     * These functions are related to the associations with RPs storage
	     * and retrieval and nonce management.
	     * @{
	     */
	    /**
	     * Allocate association.
	     * @param type association type
	     * @param kl association key length
	     * @param sl true if the association is stateless
	     * @return association object
	     */
	    virtual assoc_t alloc_assoc(const string& type,size_t kl,bool sl) = 0;
	    /**
	     * Retrieve valid unexpired association
	     * @param handle association handle
	     * @return association object
	     */
	    virtual assoc_t retrieve_assoc(const string& handle) = 0;
	    /**
	     * Allocate nonce.
	     * @param nonce input-output parameter containing timestamp part of
	     * the nonce on input
	     * @param sl true if the nonce is
	     * @return reference to nonce
	     * @throw failed_lookup if no such valid unexpired association
	     * could be retrieved
	     */
	    virtual string& alloc_nonce(string& nonce) = 0;
	    /**
	     * Check nonce validity
	     * @param nonce nonce to check
	     * @return true if nonce found and isn't yet invalidated
	     */
	    virtual bool check_nonce(const string& nonce) = 0;
	    /**
	     * Invalidate nonce
	     * @param nonce nonce to check
	     */
	    virtual void invalidate_nonce(const string& nonce) = 0;
	    /**
	     * @}
	     */

	    /**
	     * @name Site particulars API
	     * @{
	     */
	    /**
	     * Query the absolute URL of the op endpoint
	     * @return fully qualified url of the OP endpoint
	     */
	    virtual const string get_op_endpoint() const = 0;
	    /**
	     * @}
	     */

    };
}

#endif /* __OPKELE_BASIC_OP_H */
