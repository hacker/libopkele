#include <opkele/types.h>
#include <opkele/exception.h>
#include <opkele/util.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <mimetic/mimetic.h>

namespace opkele {
    using namespace std;

    bool params_t::has_param(const string& n) const {
	return find(n)!=end();
    }
    const string& params_t::get_param(const string& n) const {
	const_iterator i = find(n);
	if(i==end())
	    throw failed_lookup(OPKELE_CP_ n+": no such parameter");
	return i->second;
    }
    string& params_t::get_param(const string& n) {
	iterator i = find(n);
	if(i==end())
	    throw failed_lookup(OPKELE_CP_ n+": no such parameter");
	return i->second;
    }

    void params_t::parse_keyvalues(const string& kv) {
	clear();
	string::size_type p = 0;
	while(true) {
	    string::size_type co = kv.find(':',p);
	    if(co==string::npos)
		break;
	    string::size_type nl = kv.find('\n',co+1);
	    if(nl==string::npos)
		throw bad_input(OPKELE_CP_ "malformed input");
	    insert(value_type(kv.substr(p,co-p),kv.substr(co+1,nl-co-1)));
	    p = nl+1;
	}
    }

    void params_t::sign(secret_t secret,string& sig,const string& slist,const char *prefix) const {
	string kv;
	string::size_type p = 0;
	while(true) {
	    string::size_type co = slist.find(',',p);
	    string f = (co==string::npos)?slist.substr(p):slist.substr(p,co-p);
	    kv += f;
	    kv += ':';
	    if(prefix) f.insert(0,prefix);
	    kv += get_param(f);
	    kv += '\n';
	    if(co==string::npos)
		break;
	    p = co+1;
	}
	unsigned int md_len = 0;
	unsigned char *md = HMAC(
		EVP_sha1(),
		&(secret.front()),secret.size(),
		(const unsigned char *)kv.data(),kv.length(),
		0,&md_len);
	mimetic::Base64::Encoder b(0);
	sig.erase();
	mimetic::encode(
		md,md+md_len, b,
		back_insert_iterator<string>(sig) );
    }

    string params_t::append_query(const string& url,const char *prefix) const {
	string rv = url;
	bool p = true;
	if(rv.find('?')==string::npos) {
	    rv += '?';
	    p = false;
	}
	for(const_iterator i=begin();i!=end();++i) {
	    if(p)
		rv += '&';
	    else
		p = true;
	    rv += prefix;
	    rv += i->first;
	    rv += '=';
	    rv += util::url_encode(i->second);
	}
	return rv;
    }

    ostream& operator << (ostream& o,const params_t& p) {
	for(params_t::const_iterator i=p.begin();i!=p.end();++i)
	    o << i->first << ':' << i->second << '\n';
	return o;
    }

}
