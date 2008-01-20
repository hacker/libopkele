#ifndef __OPKELE_EXTENSION_CHAIN_H
#define __OPKELE_EXTENSION_CHAIN_H

/**
 * @file
 * @brief extension chain extension
 */

#include <list>
#include <opkele/extension.h>

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

	    virtual void checkid_hook(basic_openid_message& om);
	    virtual void id_res_hook(const basic_openid_message& om,const basic_openid_message& sp);
	    virtual void checkid_hook(const basic_openid_message& inm,basic_openid_message& oum);
    };

}

#endif /* __OPKELE_EXTENSION_CHAIN_H */
