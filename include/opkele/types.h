#ifndef __OPKELE_TYPES_H
#define __OPKELE_TYPES_H

/**
 * @file
 * @brief various types declarations
 */

#include <ostream>
#include <vector>
#include <string>
#include <map>
#include <memory>

namespace opkele {
    using std::vector;
    using std::string;
    using std::map;
    using std::ostream;
    using std::auto_ptr;

    /**
     * the OpenID operation mode
     */
    typedef enum _mode_t {
	mode_associate,
	mode_checkid_immediate,
	mode_checkid_setup,
	mode_check_association
    } mode_t;

    /**
     * the association secret container
     */
    class secret_t : public vector<unsigned char> {
	public:

	    /**
	     * xor the secret and hmac together and encode, using base64
	     * @param key_sha1 pointer to the sha1 digest
	     * @param rv reference to the return value
	     */
	    void enxor_to_base64(const unsigned char *key_sha1,string& rv) const;
	    /**
	     * decode base64-encoded secret and xor it with the sha1 digest
	     * @param key_sha1 pointer to the message digest
	     * @param b64 base64-encoded secret value
	     */
	    void enxor_from_base64(const unsigned char *key_sha1,const string& b64);
	    /**
	     * plainly encode to base64 representation
	     * @param rv reference to the return value
	     */
	    void to_base64(string& rv) const;
	    /**
	     * decode cleartext secret from base64
	     * @param b64 base64-encoded representation of the secret value
	     */
	    void from_base64(const string& b64);
    };

    /**
     * Interface to the association.
     */
    class association_t {
	public:

	    /**
	     * retrieve the server with which association was established.
	     * @return server name
	     */
	    virtual string server() const = 0;
	    /**
	     * retrieve the association handle.
	     * @return handle
	     */
	    virtual string handle() const = 0;
	    /**
	     * retrieve the association type.
	     * @return association type
	     */
	    virtual string assoc_type() const = 0;
	    /**
	     * retrieve the association secret.
	     * @return association secret
	     */
	    virtual secret_t secret() const = 0; 
	    /**
	     * retrieve the number of seconds the association expires in.
	     * @return seconds till expiration
	     */
	    virtual int expires_in() const = 0;
	    /**
	     * check whether the association is stateless.
	     * @return true if stateless
	     */
	    virtual bool stateless() const = 0;
    };

    /**
     * the auto_ptr<> for association_t object type
     */
    typedef auto_ptr<association_t> assoc_t;

    /**
     * request/response parameters map
     */
    class params_t : public map<string,string> {
	public:

	    /**
	     * check whether the parameter is present.
	     * @param n the parameter name
	     * @return true if yes
	     */
	    bool has_param(const string& n) const;
	    /**
	     * retrieve the parameter (const version)
	     * @param n the parameter name
	     * @return the parameter value
	     * @throw failed_lookup if there is no such parameter
	     */
	    const string& get_param(const string& n) const;
	    /**
	     * retrieve the parameter.
	     * @param n the parameter name
	     * @return the parameter value
	     * @throw failed_lookup if there is no such parameter
	     */
	    string& get_param(const string& n);

	    /**
	     * parse the OpenID key/value data.
	     * @param kv the OpenID key/value data
	     */
	    void parse_keyvalues(const string& kv);
	    /**
	     * sign the fields.
	     * @param secret the secret used for signing
	     * @param sig reference to the string, containing base64-encoded
	     * result
	     * @param slist the comma-separated list of fields to sign
	     * @param prefix the string to prepend to parameter names
	     */
	    void sign(secret_t secret,string& sig,const string& slist,const char *prefix=0) const;

	    /**
	     * append parameters to the URL as a GET-request parameters.
	     * @param url the base URL
	     * @param prefix the string to prepend to parameter names
	     * @return the ready-to-use location
	     */
	    string append_query(const string& url,const char *prefix = "openid.") const;
    };

    /**
     * dump the key/value pairs for the parameters to the stream.
     * @param o output stream
     * @param p the parameters
     */
    ostream& operator << (ostream& o,const params_t& p);

}

#endif /* __OPKELE_TYPES_H */
