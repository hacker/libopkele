#ifndef __OPKELE_BASIC_OP_H
#define __OPKELE_BASIC_OP_H

#include <string>
#include <opkele/types.h>
#include <opkele/extension.h>

namespace opkele {
    using std::string;

    class basic_op {
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

	    basic_openid_message& associate(
		    basic_openid_message& oum,
		    const basic_openid_message& inm);

	    void checkid_(const basic_openid_message& inm,extension_t *ext=0);
	    basic_openid_message& id_res(basic_openid_message& om);
	    basic_openid_message& cancel(basic_openid_message& om);
	    basic_openid_message& error(basic_openid_message& om,
		    const string& error,const string& contact,
		    const string& reference );
	    basic_openid_message& setup_needed(
		    basic_openid_message& oum,const basic_openid_message& inm);

	    basic_openid_message& check_authentication(
		    basic_openid_message& oum,const basic_openid_message& inm);

	    virtual void verify_return_to();

	    virtual assoc_t alloc_assoc(const string& t,size_t kl,bool sl) = 0;
	    virtual assoc_t retrieve_assoc(const string& h) = 0;

	    virtual string& alloc_nonce(string& nonce,bool sl) = 0;
	    virtual bool check_nonce(const string& nonce) = 0;
	    virtual void invalidate_nonce(const string& nonce) = 0;

	    virtual const string get_op_endpoint() const = 0;

    };
}

#endif /* __OPKELE_BASIC_OP_H */
