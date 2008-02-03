#ifndef __OPKELE_TYPES_H
#define __OPKELE_TYPES_H

/**
 * @file
 * @brief various types declarations
 */

#include <cstring>
#include <ostream>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <list>
#include <opkele/iterator.h>
#include <opkele/tr1-mem.h>

namespace opkele {
    using std::vector;
    using std::string;
    using std::map;
    using std::ostream;
    using std::multimap;
    using std::set;
    using std::list;
    using std::iterator;
    using std::forward_iterator_tag;

    /**
     * the OpenID operation mode
     */
    typedef enum _mode_t {
	mode_unknown = 0,
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
	     * @param key_d pointer to the message digest
	     * @param rv reference to the return value
	     */
	    void enxor_to_base64(const unsigned char *key_d,string& rv) const;
	    /**
	     * decode base64-encoded secret and xor it with the message digest
	     * @param key_d pointer to the message digest
	     * @param b64 base64-encoded secret value
	     */
	    void enxor_from_base64(const unsigned char *key_d,const string& b64);
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

	    virtual ~association_t() { }

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
	    /**
	     * check whether the association is expired.
	     * @return true if expired
	     */
	    virtual bool is_expired() const = 0;
    };

    /**
     * the shared_ptr<> for association_t object type
     */
    typedef tr1mem::shared_ptr<association_t> assoc_t;

    class basic_openid_message {
	public:
	    typedef list<string> fields_t;
	    typedef util::forward_iterator_proxy<
		string,const string&,const string*
		> fields_iterator;

	    basic_openid_message() { }
	    basic_openid_message(const basic_openid_message& x);
	    void copy_to(basic_openid_message& x) const;

	    virtual bool has_field(const string& n) const = 0;
	    virtual const string& get_field(const string& n) const = 0;

	    virtual bool has_ns(const string& uri) const;
	    virtual string get_ns(const string& uri) const;

	    virtual fields_iterator fields_begin() const = 0;
	    virtual fields_iterator fields_end() const = 0;

	    virtual string append_query(const string& url) const;
	    virtual string query_string() const;


	    virtual void reset_fields();
	    virtual void set_field(const string& n,const string& v);
	    virtual void reset_field(const string& n);

	    virtual void from_keyvalues(const string& kv);
	    virtual void to_keyvalues(ostream& o) const;

	    virtual void to_htmlhiddens(ostream& o) const;

	    void add_to_signed(const string& fields);
	    string find_ns(const string& uri,const char *pfx) const;
	    string allocate_ns(const string& uri,const char *pfx);
    };

    class openid_message_t : public basic_openid_message, public map<string,string> {
	public:
	    openid_message_t() { }
	    openid_message_t(const basic_openid_message& x)
		: basic_openid_message(x) { }

	    void copy_to(basic_openid_message& x) const;

	    bool has_field(const string& n) const;
	    const string& get_field(const string& n) const;
	    virtual fields_iterator fields_begin() const;
	    virtual fields_iterator fields_end() const;

	    void reset_fields();
	    void set_field(const string& n,const string& v);
	    void reset_field(const string& n);
    };

    /**
     * request/response parameters map
     */
    class params_t : public openid_message_t {
	public:

	    /**
	     * check whether the parameter is present.
	     * @param n the parameter name
	     * @return true if yes
	     */
	    bool has_param(const string& n) const {
		return has_field(n); }
	    /**
	     * retrieve the parameter (const version)
	     * @param n the parameter name
	     * @return the parameter value
	     * @throw failed_lookup if there is no such parameter
	     */
	    const string& get_param(const string& n) const {
		return get_field(n); }

	    /**
	     * parse the OpenID key/value data.
	     * @param kv the OpenID key/value data
	     */
	    void parse_keyvalues(const string& kv) {
		from_keyvalues(kv); }

	    string append_query(const string& url,const char *prefix="openid.") const;

    };

    struct openid_endpoint_t {
	string uri;
	string claimed_id;
	string local_id;

	openid_endpoint_t() { }
	openid_endpoint_t(const string& u,const string& cid,const string& lid)
	    : uri(u), claimed_id(cid), local_id(lid) { }

	bool operator==(const openid_endpoint_t& x) const {
	    return uri==x.uri && local_id==x.local_id; }
	bool operator<(const openid_endpoint_t& x) const {
	    int c;
	    return (c=strcmp(uri.c_str(),x.uri.c_str()))
		? (c<0) : (strcmp(local_id.c_str(),x.local_id.c_str())<0); }
    };

}

#endif /* __OPKELE_TYPES_H */
