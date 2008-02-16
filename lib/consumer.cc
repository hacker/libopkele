#include <algorithm>
#include <cassert>
#include <cstring>
#include <opkele/util.h>
#include <opkele/util-internal.h>
#include <opkele/curl.h>
#include <opkele/exception.h>
#include <opkele/data.h>
#include <opkele/consumer.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <iostream>

#include "config.h"

#include <pcre.h>

namespace opkele {
    using namespace std;
    using util::curl_t;
    using util::curl_pick_t;

    class pcre_matches_t {
	public:
	    int *_ov;
	    int _s;

	    pcre_matches_t() : _ov(0), _s(0) { }
	    pcre_matches_t(int s) : _ov(0), _s(s) {
		if(_s&1) ++_s;
		_s += _s>>1;
		_ov = new int[_s];
	    }
	    ~pcre_matches_t() throw() { if(_ov) delete[] _ov; }

	    int begin(int i) const { return _ov[i<<1]; }
	    int end(int i) const { return _ov[(i<<1)+1]; }
	    int length(int i) const { int t=i<<1; return _ov[t+1]-_ov[t]; }
    };

    class pcre_t {
	public:
	    pcre *_p;

	    pcre_t() : _p(0) { }
	    pcre_t(pcre *p) : _p(p) { }
	    pcre_t(const char *re,int opts) : _p(0) {
		static const char *errptr; static int erroffset;
		_p = pcre_compile(re,opts,&errptr,&erroffset,NULL);
		if(!_p)
		    throw internal_error(OPKELE_CP_ string("Failed to compile regexp: ")+errptr);
	    }
	    ~pcre_t() throw() { if(_p) (*pcre_free)(_p); }

	    pcre_t& operator=(pcre *p) { if(_p) (*pcre_free)(_p); _p=p; return *this; }

	    operator const pcre*(void) const { return _p; }
	    operator pcre*(void) { return _p; }

	    int exec(const string& s,pcre_matches_t& m) {
		if(!_p)
		    throw internal_error(OPKELE_CP_ "Trying to execute absent regexp");
		return pcre_exec(_p,NULL,s.c_str(),s.length(),0,0,m._ov,m._s);
	    }
    };

    assoc_t consumer_t::associate(const string& server) {
	util::dh_t dh = DH_new();
	if(!dh)
	    throw exception_openssl(OPKELE_CP_ "failed to DH_new()");
	dh->p = util::dec_to_bignum(data::_default_p);
	dh->g = util::dec_to_bignum(data::_default_g);
	if(!DH_generate_key(dh))
	    throw exception_openssl(OPKELE_CP_ "failed to DH_generate_key()");
	string request = 
	    "openid.mode=associate"
	    "&openid.assoc_type=HMAC-SHA1"
	    "&openid.session_type=DH-SHA1"
	    "&openid.dh_consumer_public=";
	request += util::url_encode(util::bignum_to_base64(dh->pub_key));
	curl_pick_t curl = curl_pick_t::easy_init();
	if(!curl)
	    throw exception_curl(OPKELE_CP_ "failed to initialize curl");
	CURLcode r;
	(r=curl.misc_sets())
	|| (r=curl.easy_setopt(CURLOPT_URL,server.c_str()))
	|| (r=curl.easy_setopt(CURLOPT_POST,1))
	|| (r=curl.easy_setopt(CURLOPT_POSTFIELDS,request.data()))
	|| (r=curl.easy_setopt(CURLOPT_POSTFIELDSIZE,request.length()))
	|| (r=curl.set_write())
	;
	if(r)
	    throw exception_curl(OPKELE_CP_ "failed to set curly options",r);
	if( (r=curl.easy_perform()) )
	    throw exception_curl(OPKELE_CP_ "failed to perform curly request",r);
	params_t p; p.parse_keyvalues(curl.response);
	if(p.has_param("assoc_type") && p.get_param("assoc_type")!="HMAC-SHA1")
	    throw bad_input(OPKELE_CP_ "unsupported assoc_type");
	string st;
	if(p.has_param("session_type")) st = p.get_param("session_type");
	if((!st.empty()) && st!="DH-SHA1")
	    throw bad_input(OPKELE_CP_ "unsupported session_type");
	secret_t secret;
	if(st.empty()) {
	    secret.from_base64(p.get_param("mac_key"));
	}else{
	    util::bignum_t s_pub = util::base64_to_bignum(p.get_param("dh_server_public"));
	    vector<unsigned char> ck(DH_size(dh)+1);
	    unsigned char *ckptr = &(ck.front())+1;
	    int cklen = DH_compute_key(ckptr,s_pub,dh);
	    if(cklen<0)
		throw exception_openssl(OPKELE_CP_ "failed to DH_compute_key()");
	    if(cklen && (*ckptr)&0x80) {
		(*(--ckptr)) = 0; ++cklen;
	    }
	    unsigned char key_sha1[SHA_DIGEST_LENGTH];
	    SHA1(ckptr,cklen,key_sha1);
	    secret.enxor_from_base64(key_sha1,p.get_param("enc_mac_key"));
	}
	int expires_in = 0;
	if(p.has_param("expires_in")) {
	    expires_in = util::string_to_long(p.get_param("expires_in"));
	}else if(p.has_param("issued") && p.has_param("expiry")) {
	    expires_in = util::w3c_to_time(p.get_param("expiry"))-util::w3c_to_time(p.get_param("issued"));
	}else
	    throw bad_input(OPKELE_CP_ "no expiration information");
	return store_assoc(server,p.get_param("assoc_handle"),secret,expires_in);
    }

    string consumer_t::checkid_immediate(const string& identity,const string& return_to,const string& trust_root,extension_t *ext) {
	return checkid_(mode_checkid_immediate,identity,return_to,trust_root,ext);
    }
    string consumer_t::checkid_setup(const string& identity,const string& return_to,const string& trust_root,extension_t *ext) {
	return checkid_(mode_checkid_setup,identity,return_to,trust_root,ext);
    }
    string consumer_t::checkid_(mode_t mode,const string& identity,const string& return_to,const string& trust_root,extension_t *ext) {
	params_t p;
	if(mode==mode_checkid_immediate)
	    p["mode"]="checkid_immediate";
	else if(mode==mode_checkid_setup)
	    p["mode"]="checkid_setup";
	else
	    throw bad_input(OPKELE_CP_ "unknown checkid_* mode");
	string iurl = canonicalize(identity);
	string server, delegate;
	retrieve_links(iurl,server,delegate);
	p["identity"] = delegate.empty()?iurl:delegate;
	if(!trust_root.empty())
	    p["trust_root"] = trust_root;
	p["return_to"] = return_to;
	try {
	    string ah = find_assoc(server)->handle();
	    p["assoc_handle"] = ah;
	}catch(failed_lookup& fl) {
	    string ah = associate(server)->handle();
	    p["assoc_handle"] = ah;
	}
	if(ext) ext->checkid_hook(p);
	return p.append_query(server);
    }

    void consumer_t::id_res(const params_t& pin,const string& identity,extension_t *ext) {
	if(pin.has_param("openid.user_setup_url"))
	    throw id_res_setup(OPKELE_CP_ "assertion failed, setup url provided",pin.get_param("openid.user_setup_url"));
	string server,delegate;
	retrieve_links(identity.empty()?pin.get_param("openid.identity"):canonicalize(identity),server,delegate);
	params_t ps;
	try {
	    assoc_t assoc = retrieve_assoc(server,pin.get_param("openid.assoc_handle"));
	    if(assoc->is_expired())
		throw id_res_expired_on_delivery(OPKELE_CP_ "retrieve_assoc() has returned expired handle");
	    const string& sigenc = pin.get_param("openid.sig");
	    vector<unsigned char> sig;
	    util::decode_base64(sigenc,sig);
	    const string& slist = pin.get_param("openid.signed");
	    string kv;
	    string::size_type p = 0;
	    while(true) {
		string::size_type co = slist.find(',',p);
		string f = (co==string::npos)?slist.substr(p):slist.substr(p,co-p);
		kv += f;
		kv += ':';
		f.insert(0,"openid.");
		kv += pin.get_param(f);
		kv += '\n';
		if(ext) ps[f.substr(sizeof("openid.")-1)] = pin.get_param(f);
		if(co==string::npos)
		    break;
		p = co+1;
	    }
	    secret_t secret = assoc->secret();
	    unsigned int md_len = 0;
	    unsigned char *md = HMAC(
		    EVP_sha1(),
		    &(secret.front()),secret.size(),
		    (const unsigned char *)kv.data(),kv.length(),
		    0,&md_len);
	    if(sig.size()!=md_len || memcmp(&(sig.front()),md,md_len))
		throw id_res_mismatch(OPKELE_CP_ "signature mismatch");
	}catch(failed_lookup& e) {
	    const string& slist = pin.get_param("openid.signed");
	    string::size_type pp = 0;
	    params_t p;
	    while(true) {
		string::size_type co = slist.find(',',pp);
		string f = "openid.";
		f += (co==string::npos)?slist.substr(pp):slist.substr(pp,co-pp);
		p[f] = pin.get_param(f);
		if(co==string::npos)
		    break;
		pp = co+1;
	    }
	    p["openid.assoc_handle"] = pin.get_param("openid.assoc_handle");
	    p["openid.sig"] = pin.get_param("openid.sig");
	    p["openid.signed"] = pin.get_param("openid.signed");
	    try {
		string ih = pin.get_param("openid.invalidate_handle");
		p["openid.invalidate_handle"] = ih;
	    }catch(failed_lookup& fl) { }
	    try {
		check_authentication(server,p);
	    }catch(failed_check_authentication& fca) {
		throw id_res_failed(OPKELE_CP_ "failed to check_authentication()");
	    }
	}
	if(ext) ext->id_res_hook(pin,ps);
    }

    void consumer_t::check_authentication(const string& server,const params_t& p) {
	string request = "openid.mode=check_authentication";
	for(params_t::const_iterator i=p.begin();i!=p.end();++i) {
	    if(i->first!="openid.mode") {
		request += '&';
		request += i->first;
		request += '=';
		request += util::url_encode(i->second);
	    }
	}
	curl_pick_t curl = curl_pick_t::easy_init();
	if(!curl)
	    throw exception_curl(OPKELE_CP_ "failed to initialize curl");
	CURLcode r;
	(r=curl.misc_sets())
	|| (r=curl.easy_setopt(CURLOPT_URL,server.c_str()))
	|| (r=curl.easy_setopt(CURLOPT_POST,1))
	|| (r=curl.easy_setopt(CURLOPT_POSTFIELDS,request.data()))
	|| (r=curl.easy_setopt(CURLOPT_POSTFIELDSIZE,request.length()))
	|| (r=curl.set_write())
	;
	if(r)
	    throw exception_curl(OPKELE_CP_ "failed to set curly options",r);
	if( (r=curl.easy_perform()) )
	    throw exception_curl(OPKELE_CP_ "failed to perform curly request",r);
	params_t pp; pp.parse_keyvalues(curl.response);
	if(pp.has_param("invalidate_handle"))
	    invalidate_assoc(server,pp.get_param("invalidate_handle"));
	if(pp.has_param("is_valid")) {
	    if(pp.get_param("is_valid")=="true")
		return;
	}else if(pp.has_param("lifetime")) {
	    if(util::string_to_long(pp.get_param("lifetime")))
		return;
	}
	throw failed_check_authentication(OPKELE_CP_ "failed to verify response");
    }

    void consumer_t::retrieve_links(const string& url,string& server,string& delegate) {
	server.erase();
	delegate.erase();
	curl_pick_t curl = curl_pick_t::easy_init();
	if(!curl)
	    throw exception_curl(OPKELE_CP_ "failed to initialize curl");
	string& html = curl.response;
	CURLcode r;
	(r=curl.misc_sets())
	|| (r=curl.easy_setopt(CURLOPT_URL,url.c_str()))
	|| (r=curl.set_write());
	;
	if(r)
	    throw exception_curl(OPKELE_CP_ "failed to set curly options",r);
	r = curl.easy_perform();
	if(r && r!=CURLE_WRITE_ERROR)
	    throw exception_curl(OPKELE_CP_ "failed to perform curly request",r);
	static const char *re_bre = "<\\s*body\\b", *re_hdre = "<\\s*head[^>]*>",
		     *re_lre = "<\\s*link\\b([^>]+)>",
		     *re_rre = "\\brel\\s*=\\s*['\"]([^'\"]+)['\"]",
		     *re_hre = "\\bhref\\s*=\\s*['\"]\\s*([^'\"\\s]+)\\s*['\"]";
	pcre_matches_t m1(3), m2(3);
	pcre_t bre(re_bre,PCRE_CASELESS);
	if(bre.exec(html,m1)>0)
	    html.erase(m1.begin(0));
	pcre_t hdre(re_hdre,PCRE_CASELESS);
	if(hdre.exec(html,m1)<=0)
	    throw bad_input(OPKELE_CP_ "failed to find <head>");
	html.erase(0,m1.end(0)+1);
	pcre_t lre(re_lre,PCRE_CASELESS), rre(re_rre,PCRE_CASELESS), hre(re_hre,PCRE_CASELESS);
	bool gotit = false;
	while( (!gotit) && lre.exec(html,m1)>=2 ) {
	    static const char *whitespace = " \t";
	    string attrs(html,m1.begin(1),m1.length(1));
	    html.erase(0,m1.end(0)+1);
	    if(!( rre.exec(attrs,m1)>=2 && hre.exec(attrs,m2)>=2 ))
		continue;
	    string rels(attrs,m1.begin(1),m1.length(1));
	    for(string::size_type ns = rels.find_first_not_of(whitespace);
		    ns!=string::npos;
		    ns=rels.find_first_not_of(whitespace,ns)) {
		string::size_type s = rels.find_first_of(whitespace,ns);
		string rel;
		if(s==string::npos) {
		    rel.assign(rels,ns,string::npos);
		    ns=string::npos;
		}else{
		    rel.assign(rels,ns,s-ns);
		    ns=s;
		}
		if(rel=="openid.server") {
		    server.assign(attrs,m2.begin(1),m2.length(1));
		    if(!delegate.empty()) {
			gotit = true;
			break;
		    }
		}else if(rel=="openid.delegate") {
		    delegate.assign(attrs,m2.begin(1),m2.length(1));
		    if(!server.empty()) {
			gotit = true;
			break;
		    }
		}
	    }
	}
	if(server.empty())
	    throw failed_assertion(OPKELE_CP_ "The location has no openid.server declaration");
    }

    assoc_t consumer_t::find_assoc(const string& /* server */) {
	throw failed_lookup(OPKELE_CP_ "no find_assoc() provided");
    }

    string consumer_t::normalize(const string& url) {
	string rv = url;
	// strip leading and trailing spaces
	string::size_type i = rv.find_first_not_of(" \t\r\n");
	if(i==string::npos)
	    throw bad_input(OPKELE_CP_ "empty URL");
	if(i)
	    rv.erase(0,i);
	i = rv.find_last_not_of(" \t\r\n");
	assert(i!=string::npos);
	if(i<(rv.length()-1))
	    rv.erase(i+1);
	// add missing http://
	i = rv.find("://");
	if(i==string::npos) { // primitive. but do we need more?
	    rv.insert(0,"http://");
	    i = sizeof("http://")-1;
	}else{
	    i += sizeof("://")-1;
	}
	string::size_type qm = rv.find('?',i);
	string::size_type sl = rv.find('/',i);
	if(qm!=string::npos) {
	    if(sl==string::npos || sl>qm)
		rv.insert(qm,1,'/');
	}else{
	    if(sl==string::npos)
		rv += '/';
	}
	return rv;
    }

    string consumer_t::canonicalize(const string& url) {
	string rv = normalize(url);
	curl_t curl = curl_t::easy_init();
	if(!curl)
	    throw exception_curl(OPKELE_CP_ "failed to initialize curl()");
	string html;
	CURLcode r;
	(r=curl.misc_sets())
	|| (r=curl.easy_setopt(CURLOPT_URL,rv.c_str()))
	|| (r=curl.easy_setopt(CURLOPT_NOBODY,1))
	;
	if(r)
	    throw exception_curl(OPKELE_CP_ "failed to set curly options",r);
	r = curl.easy_perform();
	if(r)
	    throw exception_curl(OPKELE_CP_ "failed to perform curly request",r);
	const char *eu = 0;
	r = curl.easy_getinfo(CURLINFO_EFFECTIVE_URL,&eu);
	if(r)
	    throw exception_curl(OPKELE_CP_ "failed to get CURLINFO_EFFECTIVE_URL",r);
	rv = eu;
	return normalize(rv);
    }

}
