#ifndef __OPKELE_AX_H
#define __OPKELE_AX_H

/**
 * @file
 * @brief Attribute Exchange extension
 */

#include <opkele/extension.h>

namespace opkele {

    /**
     * OpenID simple registration extension implementation
     * http://openid.net/specs/openid-simple-registration-extension-1_0.html
     */
    class ax_t : public extension_t {
	public:
            /** special "count" value for add_attribute to request fetching "as many values as possible". */
	    static const int UNLIMITED_COUNT = -1; 

	    /** 
             * Optional URL for receiving future attribute updates.
             * Set it before checkid_setup to send up the URL; read it after id_res to get it back.
             */
	    std::string update_url;

	    /**
	     * Consumer constructor.
	     */
	    ax_t() : alias_count(0) { }

	    /** Adds an attribute to request during checkid_setup. */
	    void add_attribute(const char *uri, bool required, const char *alias = NULL, int count = 1);

            /** Returns an attribute fetched for the given type-uri during id_res. */
	    std::string get_attribute(const char *uri, int index = 0);
	    /** Returns the number of values fetched for the given type-uri during id_res. */
	    size_t get_attribute_count(const char *uri);

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

	protected:
	    /** Stores attributes to request fetching during checkid_setup. */
	    struct ax_attr_t {
		std::string uri;
		std::string alias;
		bool required;
		int count;
	    };
	    std::vector<ax_attr_t> attrs;
	    unsigned int alias_count; // auto-incr counter for auto-named aliases

	    /** Stores results from fetch response during id_res. */
	    std::map<std::string, std::vector<std::string> > response_attrs;
    };
}

#endif /* __OPKELE_SREG_H */

