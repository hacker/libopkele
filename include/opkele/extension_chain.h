#ifndef __OPKELE_EXTENSION_CHAIN_H
#define __OPKELE_EXTENSION_CHAIN_H

/**
 * @file
 * @brief extension chain extension
 */

#include <list>
#include <opkele/extension.h>

/**
 * @brief the main opkele namespace
 */
namespace opkele {
    using std::list;

    /**
     * OpenID extensions chain used to combine extensions, it is actually an
     * stl list of pointers to extensions.
     */
    class extension_chain_t : public extension_t, public list<extension_t*> {
	public:

	    /**
	     * Default constructor creates an empty chain
	     */
	    extension_chain_t() { }
	    /**
	     * Create extension chain with a single extension in it
	     */
	    extension_chain_t(extension_t *e) { push_back(e); }

	    /**
	     * Implementation of consumer's checkid hook
	     */
	    virtual void checkid_hook(params_t& p,const string& identity);
	    /**
	     * Implementation of consumer's id_res hook
	     */
	    virtual void id_res_hook(const params_t& p,const params_t& sp,const string& identity);
	    /**
	     * Implementation of server's checkid_hook
	     */
	    virtual void checkid_hook(const params_t& pin,params_t& pout);
    };

}

#endif /* __OPKELE_EXTENSION_CHAIN_H */
