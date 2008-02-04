#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <opkele/basic_rp.h>
#include <opkele/exception.h>
#include <opkele/uris.h>
#include <opkele/data.h>
#include <opkele/util.h>
#include <opkele/curl.h>

namespace opkele {

    static void dh_get_secret(
	    secret_t& secret, const basic_openid_message& om,
	    const char *exp_assoc, const char *exp_sess,
	    util::dh_t& dh,
	    size_t d_len, unsigned char *(*d_fun)(const unsigned char*,size_t,unsigned char*),
	    size_t exp_s_len) try {
	if(om.get_field("assoc_type")!=exp_assoc || om.get_field("session_type")!=exp_sess)
	    throw bad_input(OPKELE_CP_ "Unexpected associate response");
	util::bignum_t s_pub = util::base64_to_bignum(om.get_field("dh_server_public"));
	vector<unsigned char> ck(DH_size(dh)+1);
	unsigned char *ckptr = &(ck.front())+1;
	int cklen = DH_compute_key(ckptr,s_pub,dh);
	if(cklen<0)
	    throw exception_openssl(OPKELE_CP_ "failed to DH_compute_key()");
	if(cklen && (*ckptr)&0x80) {
	    (*(--ckptr))=0; ++cklen; }
	unsigned char key_digest[d_len];
	secret.enxor_from_base64((*d_fun)(ckptr,cklen,key_digest),om.get_field("enc_mac_key"));
	if(secret.size()!=exp_s_len)
	    throw bad_input(OPKELE_CP_ "Secret length isn't consistent with association type");
    }catch(opkele::failed_lookup& ofl) {
	throw bad_input(OPKELE_CP_ "Incoherent response from OP");
    } OPKELE_RETHROW

    static void direct_request(basic_openid_message& oum,const basic_openid_message& inm,const string& OP) {
	util::curl_pick_t curl = util::curl_pick_t::easy_init();
	if(!curl)
	    throw exception_curl(OPKELE_CP_ "failed to initialize curl");
	string request = inm.query_string();
	CURLcode r;
	(r=curl.misc_sets())
	    || (r=curl.easy_setopt(CURLOPT_URL,OP.c_str()))
	    || (r=curl.easy_setopt(CURLOPT_POST,1))
	    || (r=curl.easy_setopt(CURLOPT_POSTFIELDS,request.data()))
	    || (r=curl.easy_setopt(CURLOPT_POSTFIELDSIZE,request.length()))
	    || (r=curl.set_write());
	if(r)
	    throw exception_curl(OPKELE_CP_ "failed to set curly options",r);
	if( (r=curl.easy_perform()) )
	    throw exception_curl(OPKELE_CP_ "failed to perform curly request",r);
	oum.from_keyvalues(curl.response);
    }


    assoc_t basic_RP::associate(const string& OP) {
	util::dh_t dh = DH_new();
	if(!dh)
	    throw exception_openssl(OPKELE_CP_ "failed to DH_new()");
	dh->p = util::dec_to_bignum(data::_default_p);
	dh->g = util::dec_to_bignum(data::_default_g);
	if(!DH_generate_key(dh))
	    throw exception_openssl(OPKELE_CP_ "failed to DH_generate_key()");
	openid_message_t req;
	req.set_field("ns",OIURI_OPENID20);
	req.set_field("mode","associate");
	req.set_field("dh_modulus",util::bignum_to_base64(dh->p));
	req.set_field("dh_gen",util::bignum_to_base64(dh->g));
	req.set_field("dh_consumer_public",util::bignum_to_base64(dh->pub_key));
	openid_message_t res;
	req.set_field("assoc_type","HMAC-SHA256");
	req.set_field("session_type","DH-SHA256");
	secret_t secret;
	int expires_in;
	try {
	    direct_request(res,req,OP);
	    dh_get_secret( secret, res,
		    "HMAC-SHA256", "DH-SHA256",
		    dh, SHA256_DIGEST_LENGTH, SHA256, SHA256_DIGEST_LENGTH );
	    expires_in = util::string_to_long(res.get_field("expires_in"));
	}catch(exception& e) {
	    try {
		req.set_field("assoc_type","HMAC-SHA1");
		req.set_field("session_type","DH-SHA1");
		direct_request(res,req,OP);
		dh_get_secret( secret, res,
			"HMAC-SHA1", "DH-SHA1",
			dh, SHA_DIGEST_LENGTH, SHA1, SHA_DIGEST_LENGTH );
		expires_in = util::string_to_long(res.get_field("expires_in"));
	    }catch(bad_input& e) {
		throw dumb_RP(OPKELE_CP_ "OP failed to supply an association");
	    }
	}
	return store_assoc(
		OP, res.get_field("assoc_handle"),
		res.get_field("assoc_type"), secret,
		expires_in );
    }

    basic_openid_message& basic_RP::checkid_(
	    basic_openid_message& rv,
	    mode_t mode,
	    const string& return_to,const string& realm,
	    extension_t *ext) {
	rv.reset_fields();
	rv.set_field("ns",OIURI_OPENID20);
	if(mode==mode_checkid_immediate)
	    rv.set_field("mode","checkid_immediate");
	else if(mode==mode_checkid_setup)
	    rv.set_field("mode","checkid_setup");
	else
	    throw bad_input(OPKELE_CP_ "unknown checkid_* mode");
	if(realm.empty() && return_to.empty())
	    throw bad_input(OPKELE_CP_ "At least one of realm and return_to must be non-empty");
	if(!realm.empty()) {
	    rv.set_field("realm",realm);
	    rv.set_field("trust_root",realm);
	}
	if(!return_to.empty())
	    rv.set_field("return_to",return_to);
	const openid_endpoint_t& ep = get_endpoint();
	rv.set_field("claimed_id",ep.claimed_id);
	rv.set_field("identity",ep.local_id);
	try {
	    rv.set_field("assoc_handle",find_assoc(ep.uri)->handle());
	}catch(dumb_RP& drp) {
	}catch(failed_lookup& fl) {
	    try {
		rv.set_field("assoc_handle",associate(ep.uri)->handle());
	    }catch(dumb_RP& drp) { }
	} OPKELE_RETHROW
	if(ext) ext->rp_checkid_hook(rv);
	return rv;
    }

    class signed_part_message_proxy : public basic_openid_message {
	public:
	    const basic_openid_message& x;
	    set<string> signeds;

	    signed_part_message_proxy(const basic_openid_message& xx) : x(xx) {
		const string& slist = x.get_field("signed");
		string::size_type p = 0;
		while(true) {
		    string::size_type co = slist.find(',',p);
		    string f = (co==string::npos)
			?slist.substr(p):slist.substr(p,co-p);
		    signeds.insert(f);
		    if(co==string::npos) break;
		    p = co+1;
		}
	    }

	    bool has_field(const string& n) const {
		return signeds.find(n)!=signeds.end() && x.has_field(n); }
	    const string& get_field(const string& n) const {
		if(signeds.find(n)==signeds.end())
		    throw failed_lookup(OPKELE_CP_ "The field isn't known to be signed");
		return x.get_field(n); }

	    fields_iterator fields_begin() const {
		return signeds.begin(); }
	    fields_iterator fields_end() const {
		return signeds.end(); }
    };

    static void parse_query(const string& u,string::size_type q,
	    map<string,string>& p) {
	if(q==string::npos)
	    return;
	assert(u[q]=='?');
	++q;
	string::size_type l = u.size();
	while(q<l) {
	    string::size_type eq = u.find('=',q);
	    string::size_type am = u.find('&',q);
	    if(am==string::npos) {
		if(eq==string::npos) {
		    p[""] = u.substr(q);
		}else{
		    p[u.substr(q,eq-q)] = u.substr(eq+1);
		}
		break;
	    }else{
		if(eq==string::npos || eq>am) {
		    p[""] = u.substr(q,eq-q);
		}else{
		    p[u.substr(q,eq-q)] = u.substr(eq+1,am-eq-1);
		}
		q = ++am;
	    }
	}
    }

    void basic_RP::id_res(const basic_openid_message& om,extension_t *ext) {
	bool o2 = om.has_field("ns")
	    && om.get_field("ns")==OIURI_OPENID20;
	if( (!o2) && om.has_field("user_setup_url"))
	    throw id_res_setup(OPKELE_CP_ "assertion failed, setup url provided",
		    om.get_field("user_setup_url"));
	string m = om.get_field("mode");
	if(o2 && m=="setup_needed")
	    throw id_res_setup(OPKELE_CP_ "setup needed, no setup url provided");
	if(m=="cancel")
	    throw id_res_cancel(OPKELE_CP_ "authentication cancelled");
	bool go_dumb=false;
	try {
	    string OP = o2
		?om.get_field("op_endpoint")
		:get_endpoint().uri;
	    assoc_t assoc = retrieve_assoc(
		    OP,om.get_field("assoc_handle"));
	    if(om.get_field("sig")!=util::base64_signature(assoc,om))
		throw id_res_mismatch(OPKELE_CP_ "signature mismatch");
	}catch(dumb_RP& drp) {
	    go_dumb=true;
	}catch(failed_lookup& e) {
	    go_dumb=true;
	} OPKELE_RETHROW
	if(go_dumb) {
	    try {
		string OP = o2
		    ?om.get_field("op_endpoint")
		    :get_endpoint().uri;
		check_authentication(OP,om);
	    }catch(failed_check_authentication& fca) {
		throw id_res_failed(OPKELE_CP_ "failed to check_authentication()");
	    } OPKELE_RETHROW
	}
	signed_part_message_proxy signeds(om);
	if(o2) {
	    check_nonce(om.get_field("op_endpoint"),
		    om.get_field("response_nonce"));
	    static const char *mustsign[] = {
		"op_endpoint", "return_to", "response_nonce", "assoc_handle",
		"claimed_id", "identity" };
	    for(int ms=0;ms<(sizeof(mustsign)/sizeof(*mustsign));++ms) {
		if(om.has_field(mustsign[ms]) && !signeds.has_field(mustsign[ms]))
		    throw bad_input(OPKELE_CP_ string("Field '")+mustsign[ms]+"' is not signed against the specs");
	    }
	    if( (
		    (om.has_field("claimed_id")?1:0)
		    ^
		    (om.has_field("identity")?1:0)
		)&1 )
		throw bad_input(OPKELE_CP_ "claimed_id and identity must be either both present or both absent");

	    string turl = util::rfc_3986_normalize_uri(get_this_url());
	    util::strip_uri_fragment_part(turl);
	    string rurl = util::rfc_3986_normalize_uri(om.get_field("return_to"));
	    util::strip_uri_fragment_part(rurl);
	    string::size_type
		tq = turl.find('?'), rq = rurl.find('?');
	    if(
		    ((tq==string::npos)?turl:turl.substr(0,tq))
		    !=
		    ((rq==string::npos)?rurl:rurl.substr(0,rq))
	      )
		throw id_res_bad_return_to(OPKELE_CP_ "return_to url doesn't match request url");
	    map<string,string> tp; parse_query(turl,tq,tp);
	    map<string,string> rp; parse_query(rurl,rq,rp);
	    for(map<string,string>::const_iterator rpi=rp.begin();rpi!=rp.end();++rpi) {
		map<string,string>::const_iterator tpi = tp.find(rpi->first);
		if(tpi==tp.end())
		    throw id_res_bad_return_to(OPKELE_CP_ string("Parameter '")+rpi->first+"' from return_to is missing from the request");
		if(tpi->second!=rpi->second)
		    throw id_res_bad_return_to(OPKELE_CP_ string("Parameter '")+rpi->first+"' from return_to doesn't matche the request");
	    }

	    if(om.has_field("claimed_id")) {
		verify_OP(
			om.get_field("op_endpoint"),
			om.get_field("claimed_id"),
			om.get_field("identity") );
	    }

	}
	if(ext) ext->rp_id_res_hook(om,signeds);
    }

    void basic_RP::check_authentication(const string& OP,
	    const basic_openid_message& om){
	openid_message_t res;
	static const string checkauthmode = "check_authentication";
	direct_request(res,util::change_mode_message_proxy(om,checkauthmode),OP);
	if(res.has_field("is_valid")) {
	    if(res.get_field("is_valid")=="true") {
		if(res.has_field("invalidate_handle"))
		    invalidate_assoc(OP,res.get_field("invalidate_handle"));
		return;
	    }
	}
	throw failed_check_authentication(
		OPKELE_CP_ "failed to verify response");
    }

}
