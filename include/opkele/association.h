#ifndef __OPKELE_ASSOCIATION_H
#define __OPKELE_ASSOCIATION_H

#include <time.h>
#include <opkele/types.h>

/**
 * @file
 * @brief reference implementation of association_t
 */

namespace opkele {

    /**
     * reference implementation of association_t class.
     */
    class association : public association_t {
	public:
	    /**
	     * OpenID server name
	     */
	    string _server;
	    /**
	     * association handle
	     */
	    string _handle;
	    /**
	     * association type
	     */
	    string _assoc_type;
	    /**
	     * the secret
	     */
	    secret_t _secret;
	    /**
	     * expiration time
	     */
	    time_t _expires;
	    /**
	     * statelessness of the assoc_handle
	     */
	    bool _stateless;

	    /**
	     * @param __server the server name
	     * @param __handle association handle
	     * @param __assoc_type association type
	     * @param __secret the secret
	     * @param __expires expiration time
	     * @param __stateless statelessness of the assoc_handle
	     */
	    association(const string& __server, const string& __handle,
		    const string& __assoc_type, const secret_t& __secret,
		    time_t __expires, bool __stateless)
		: _server(__server), _handle(__handle), _assoc_type(__assoc_type),
		_secret(__secret), _expires(__expires), _stateless(__stateless) { }

	    virtual string server() const { return _server; }
	    virtual string handle() const { return _handle; }
	    virtual string assoc_type() const { return _assoc_type; }
	    virtual secret_t secret() const { return _secret; }
	    virtual int expires_in() const { return _expires-time(0); }
	    virtual bool stateless() const { return _stateless; }
    };

}

#endif /* __OPKELE_ASSOCIATION_H */
