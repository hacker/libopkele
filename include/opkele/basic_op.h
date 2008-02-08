#ifndef __OPKELE_BASIC_OP_H
#define __OPKELE_BASIC_OP_H

#include <string>
#include <opkele/types.h>
#include <opkele/extension.h>

namespace opkele {
    using std::string;

    class basic_OP {
	public:
	    mode_t mode;
	    assoc_t assoc;
	    bool openid2;
	    string return_to;
	    string realm;
	    string claimed_id;
	    string identity;
	    string invalidate_handle;

	    void reset_vars();

	    bool has_return_to() const;
	    const string& get_return_to() const;

	    const string& get_realm() const;

	    bool has_identity() const;
	    const string& get_claimed_id() const;
	    const string& get_identity() const;

	    bool is_id_select() const;

	    void select_identity(const string& c,const string& i);
	    void set_claimed_id(const string& c);

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
	     * @see verify_op::verify_return_to()
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
