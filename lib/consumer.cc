#include <algorithm>
#include <cassert>
#include <opkele/util.h>
#include <opkele/exception.h>
#include <opkele/data.h>
#include <opkele/consumer.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <curl/curl.h>
#include <pcre++.h>

#include <iostream>

#include "config.h"

namespace opkele {
    using namespace std;

    class curl_t {
	public:
	    CURL *_c;

	    curl_t() : _c(0) { }
	    curl_t(CURL *c) : _c(c) { }
	    ~curl_t() throw() { if(_c) curl_easy_cleanup(_c); }

	    curl_t& operator=(CURL *c) { if(_c) curl_easy_cleanup(_c); _c=c; return *this; }

	    operator const CURL*(void) const { return _c; }
	    operator CURL*(void) { return _c; }
    };

    static CURLcode curl_misc_sets(CURL* c) {
	CURLcode r;
	(r=curl_easy_setopt(c,CURLOPT_FOLLOWLOCATION,1))
	|| (r=curl_easy_setopt(c,CURLOPT_MAXREDIRS,5))
	|| (r=curl_easy_setopt(c,CURLOPT_DNS_CACHE_TIMEOUT,120))
	|| (r=curl_easy_setopt(c,CURLOPT_DNS_USE_GLOBAL_CACHE,1))
	|| (r=curl_easy_setopt(c,CURLOPT_USERAGENT,PACKAGE_NAME"/"PACKAGE_VERSION))
	|| (r=curl_easy_setopt(c,CURLOPT_TIMEOUT,20))
#ifdef	DISABLE_CURL_SSL_VERIFYHOST
	|| (r=curl_easy_setopt(c,CURLOPT_SSL_VERIFYHOST,0))
#endif
#ifdef	DISABLE_CURL_SSL_VERIFYPEER
	|| (r=curl_easy_setopt(c,CURLOPT_SSL_VERIFYPEER,0))
#endif
	;
	return r;
    }

    static size_t _curl_tostring(void *ptr,size_t size,size_t nmemb,void *stream) {
	string *str = (string*)stream;
	size_t bytes = size*nmemb;
	size_t get = min(16384-str->length(),bytes);
	str->append((const char*)ptr,get);
	return get;
    }

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
	curl_t curl = curl_easy_init();
	if(!curl)
	    throw exception_curl(OPKELE_CP_ "failed to curl_easy_init()");
	string response;
	CURLcode r;
	(r=curl_misc_sets(curl))
	|| (r=curl_easy_setopt(curl,CURLOPT_URL,server.c_str()))
	|| (r=curl_easy_setopt(curl,CURLOPT_POST,1))
	|| (r=curl_easy_setopt(curl,CURLOPT_POSTFIELDS,request.data()))
	|| (r=curl_easy_setopt(curl,CURLOPT_POSTFIELDSIZE,request.length()))
	|| (r=curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,_curl_tostring))
	|| (r=curl_easy_setopt(curl,CURLOPT_WRITEDATA,&response))
	;
	if(r)
	    throw exception_curl(OPKELE_CP_ "failed to curl_easy_setopt()",r);
	if(r=curl_easy_perform(curl))
	    throw exception_curl(OPKELE_CP_ "failed to curl_easy_perform()",r);
	params_t p; p.parse_keyvalues(response);
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
	    vector<unsigned char> ck(DH_size(dh));
	    int cklen = DH_compute_key(&(ck.front()),s_pub,dh);
	    if(cklen<0)
		throw exception_openssl(OPKELE_CP_ "failed to DH_compute_key()");
	    ck.resize(cklen);
	    // OpenID algorithm requires extra zero in case of set bit here
	    if(ck[0]&0x80) ck.insert(ck.begin(),1,0);
	    unsigned char key_sha1[SHA_DIGEST_LENGTH];
	    SHA1(&(ck.front()),ck.size(),key_sha1);
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
	if(ext) ext->checkid_hook(p,identity);
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
	}catch(failed_lookup& e) { /* XXX: more specific? */
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
	if(ext) ext->id_res_hook(pin,ps,identity);
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
	curl_t curl = curl_easy_init();
	if(!curl)
	    throw exception_curl(OPKELE_CP_ "failed to curl_easy_init()");
	string response;
	CURLcode r;
	(r=curl_misc_sets(curl))
	|| (r=curl_easy_setopt(curl,CURLOPT_URL,server.c_str()))
	|| (r=curl_easy_setopt(curl,CURLOPT_POST,1))
	|| (r=curl_easy_setopt(curl,CURLOPT_POSTFIELDS,request.data()))
	|| (r=curl_easy_setopt(curl,CURLOPT_POSTFIELDSIZE,request.length()))
	|| (r=curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,_curl_tostring))
	|| (r=curl_easy_setopt(curl,CURLOPT_WRITEDATA,&response))
	;
	if(r)
	    throw exception_curl(OPKELE_CP_ "failed to curl_easy_setopt()",r);
	if(r=curl_easy_perform(curl))
	    throw exception_curl(OPKELE_CP_ "failed to curl_easy_perform()",r);
	params_t pp; pp.parse_keyvalues(response);
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
	curl_t curl = curl_easy_init();
	if(!curl)
	    throw exception_curl(OPKELE_CP_ "failed to curl_easy_init()");
	string html;
	CURLcode r;
	(r=curl_misc_sets(curl))
	|| (r=curl_easy_setopt(curl,CURLOPT_URL,url.c_str()))
	|| (r=curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,_curl_tostring))
	|| (r=curl_easy_setopt(curl,CURLOPT_WRITEDATA,&html))
	;
	if(r)
	    throw exception_curl(OPKELE_CP_ "failed to curl_easy_setopt()",r);
	r = curl_easy_perform(curl);
	if(r && r!=CURLE_WRITE_ERROR)
	    throw exception_curl(OPKELE_CP_ "failed to curl_easy_perform()",r);
	pcrepp::Pcre bre("<body\\b",PCRE_CASELESS);
	// strip out everything past body
	if(bre.search(html))
	    html.erase(bre.get_match_start());
	pcrepp::Pcre hdre("<head[^>]*>",PCRE_CASELESS);
	if(!hdre.search(html))
	    throw bad_input(OPKELE_CP_ "failed to find head");
	html.erase(0,hdre.get_match_end()+1);
	pcrepp::Pcre lre("<link\\b([^>]+)>",PCRE_CASELESS),
	    rre("\\brel=['\"]([^'\"]+)['\"]",PCRE_CASELESS),
	    hre("\\bhref=['\"]([^'\"]+)['\"]",PCRE_CASELESS);
	while(lre.search(html)) {
	    string attrs = lre[0];
	    html.erase(0,lre.get_match_end()+1);
	    if(!(rre.search(attrs)&&hre.search(attrs)))
		continue;
	    if(rre[0]=="openid.server") {
		server = hre[0];
		if(!delegate.empty())
		    break;
	    }else if(rre[0]=="openid.delegate") {
		delegate = hre[0];
		if(!server.empty())
		    break;
	    }
	}
	if(server.empty())
	    throw failed_assertion(OPKELE_CP_ "The location has no openid.server declaration");
    }

    assoc_t consumer_t::find_assoc(const string& server) {
	throw failed_lookup(OPKELE_CP_ "no find_assoc() provided");
    }

    string consumer_t::canonicalize(const string& url) {
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

}
