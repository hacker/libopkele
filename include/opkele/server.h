#ifndef __OPKELE_SERVER_H
#define __OPKELE_SERVER_H

/**
 * @file
 * @brief OpenID server-side functionality
 */

#include <opkele/types.h>
#include <opkele/extension.h>

/**
 * @brief the main opkele namespace
 */
namespace opkele {

    /**
     * implementation of basic server functionality
     */
    class server_t {
	public:

	    /**
	     * allocate the new association. The function should be overridden
	     * in the real implementation to provide persistent assocations
	     * store.
	     * @param mode the mode of request being processed to base the
	     * statelessness of the association upon
	     * @return the auto_ptr<> for the newly allocated association_t object
	     */
	    virtual assoc_t alloc_assoc(mode_t mode) = 0;
	    /**
	     * retrieve the association. The function should be overridden in
	     * the reqal implementation to provide persistent assocations
	     * store.
	     * @param h association handle
	     * @return the auto_ptr<> for the newly allocated association_t object
	     * @throw failed_lookup in case of failure
	     */
	    virtual assoc_t retrieve_assoc(const string& h) = 0;

	    /**
	     * validate the identity.
	     * @param assoc association object
	     * @param pin incoming request parameters
	     * @param identity being verified
	     * @param trust_root presented in the request
	     * @throw exception if identity can not be confirmed
	     */
	    virtual void validate(const association_t& assoc,const params_t& pin,const string& identity,const string& trust_root) = 0;


	    /**
	     * process the associate request.
	     * @param pin the incoming request parameters
	     * @param pout the store for the response parameters
	     */
	    void associate(const params_t& pin,params_t& pout);
	    /**
	     * process the checkid_immediate request.
	     * @param pin the incoming request parameters
	     * @param return_to reference to the object to store return_to url to
	     * @param pout the response parameters
	     * @param ext pointer to the extension hooks object
	     * @throw exception in case of errors or negative reply
	     */
	    void checkid_immediate(const params_t& pin,string& return_to,params_t& pout,extension_t *ext=0);
	    /**
	     * process the checkid_setup request.
	     * @param pin the incoming request parameters
	     * @param return_to reference to the object to store return_to url to
	     * @param pout the response parameters
	     * @param ext pointer to the extension hooks object
	     * @throw exception in case of errors or negative reply
	     */
	    void checkid_setup(const params_t& pin,string& return_to,params_t& pout,extension_t *ext=0);
	    /**
	     * the actual functionality behind checkid_immediate() and
	     * checkid_setup()
	     * @param mode the request being processed (either
	     * mode_checkid_immediate or mode_checkid_setup)
	     * @param pin the incoming request parameters
	     * @param return_to reference to the object to store return_to url to
	     * @param pout the response parameters
	     * @param ext pointer to the extension hooks object
	     * @throw exception in case of errors or negative reply
	     */
	    void checkid_(mode_t mode,const params_t& pin,string& return_to,params_t& pout,extension_t *ext=0);
	    /**
	     * process the check_authentication request.
	     * @param pin incoming request parameters
	     * @param pout response parameters
	     */
	    void check_authentication(const params_t& pin,params_t& pout);
    };

}

#endif /* __OPKELE_SERVER_H */
