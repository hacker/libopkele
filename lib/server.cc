#include <cstring>
#include <vector>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <opkele/util.h>
#include <opkele/exception.h>
#include <opkele/server.h>
#include <opkele/data.h>

namespace opkele {
    using namespace std;

    void server_t::associate(const params_t& pin,params_t& pout) {
	util::dh_t dh;
	util::bignum_t c_pub;
	unsigned char key_sha1[SHA_DIGEST_LENGTH];
	enum {
	    sess_cleartext,
	    sess_dh_sha1
	} st = sess_cleartext;
	if(
		pin.has_param("openid.session_type")
		&& pin.get_param("openid.session_type")=="DH-SHA1" ) {
	    /* TODO: fallback to cleartext in case of exceptions here? */
	    if(!(dh = DH_new()))
		throw exception_openssl(OPKELE_CP_ "failed to DH_new()");
	    c_pub = util::base64_to_bignum(pin.get_param("openid.dh_consumer_public"));
	    if(pin.has_param("openid.dh_modulus"))
		dh->p = util::base64_to_bignum(pin.get_param("openid.dh_modulus"));
	    else
		dh->p = util::dec_to_bignum(data::_default_p);
	    if(pin.has_param("openid.dh_gen"))
		dh->g = util::base64_to_bignum(pin.get_param("openid.dh_gen"));
	    else
		dh->g = util::dec_to_bignum(data::_default_g);
	    if(!DH_generate_key(dh))
		throw exception_openssl(OPKELE_CP_ "failed to DH_generate_key()");
	    vector<unsigned char> ck(DH_size(dh)+1);
	    unsigned char *ckptr = &(ck.front())+1;
	    int cklen = DH_compute_key(ckptr,c_pub,dh);
	    if(cklen<0)
		throw exception_openssl(OPKELE_CP_ "failed to DH_compute_key()");
	    if(cklen && (*ckptr)&0x80) {
		(*(--ckptr)) = 0; ++cklen;
	    }
	    SHA1(ckptr,cklen,key_sha1);
	    st = sess_dh_sha1;
	}
	assoc_t assoc = alloc_assoc(mode_associate);
	time_t now = time(0);
	pout.clear();
	pout["assoc_type"] = assoc->assoc_type();
	pout["assoc_handle"] = assoc->handle();
	/* TODO: eventually remove deprecated stuff */
	pout["issued"] = util::time_to_w3c(now);
	pout["expiry"] = util::time_to_w3c(now+assoc->expires_in());
	pout["expires_in"] = util::long_to_string(assoc->expires_in());
	secret_t secret = assoc->secret();
	switch(st) {
	    case sess_dh_sha1:
		pout["session_type"] = "DH-SHA1";
		pout["dh_server_public"] = util::bignum_to_base64(dh->pub_key);
		secret.enxor_to_base64(key_sha1,pout["enc_mac_key"]);
		break;
	    default:
		secret.to_base64(pout["mac_key"]);
		break;
	}
    }

    void server_t::checkid_immediate(const params_t& pin,string& return_to,params_t& pout,extension_t *ext) {
	checkid_(mode_checkid_immediate,pin,return_to,pout,ext);
    }

    void server_t::checkid_setup(const params_t& pin,string& return_to,params_t& pout,extension_t *ext) {
	checkid_(mode_checkid_setup,pin,return_to,pout,ext);
    }

    void server_t::checkid_(mode_t mode,const params_t& pin,string& return_to,params_t& pout,extension_t *ext) {
	if(mode!=mode_checkid_immediate && mode!=mode_checkid_setup)
	    throw bad_input(OPKELE_CP_ "invalid checkid_* mode");
	pout.clear();
	assoc_t assoc;
	try {
	    assoc = retrieve_assoc(pin.get_param("openid.assoc_handle"));
	}catch(failed_lookup& fl) {
	    // no handle specified or no valid handle found, going dumb
	    assoc = alloc_assoc(mode_checkid_setup);
	    if(pin.has_param("openid.assoc_handle"))
		pout["invalidate_handle"]=pin.get_param("openid.assoc_handle");
	}
	string trust_root;
	try {
	    trust_root = pin.get_param("openid.trust_root");
	}catch(failed_lookup& fl) { }
	string identity = pin.get_param("openid.identity");
	return_to = pin.get_param("openid.return_to");
	validate(*assoc,pin,identity,trust_root);
	pout["mode"] = "id_res";
	pout["assoc_handle"] = assoc->handle();
	if(pin.has_param("openid.assoc_handle") && assoc->stateless())
	    pout["invalidate_handle"] = pin.get_param("openid.assoc_handle");
	pout["identity"] = identity;
	pout["return_to"] = return_to;
	/* TODO: eventually remove deprecated stuff */
	time_t now = time(0);
	pout["issued"] = util::time_to_w3c(now);
	pout["valid_to"] = util::time_to_w3c(now+120);
	pout["exipres_in"] = "120";
	pout["signed"]="mode,identity,return_to";
	if(ext) ext->checkid_hook(pin,pout);
	pout.sign(assoc->secret(),pout["sig"],pout["signed"]);
    }

    void server_t::check_authentication(const params_t& pin,params_t& pout) {
	vector<unsigned char>  sig;
	const string& sigenc = pin.get_param("openid.sig");
	util::decode_base64(sigenc,sig);
	assoc_t assoc;
	try {
	    assoc = retrieve_assoc(pin.get_param("openid.assoc_handle"));
	}catch(failed_lookup& fl) {
	    throw failed_assertion(OPKELE_CP_ "invalid handle or handle not specified");
	}
	if(!assoc->stateless())
	    throw stateful_handle(OPKELE_CP_ "will not do check_authentication on a stateful handle");
	const string& slist = pin.get_param("openid.signed");
	string kv;
	string::size_type p =0;
	while(true) {
	    string::size_type co = slist.find(',',p);
	    string f = (co==string::npos)?slist.substr(p):slist.substr(p,co-p);
	    kv += f;
	    kv += ':';
	    if(f=="mode")
		kv += "id_res";
	    else {
		f.insert(0,"openid.");
		kv += pin.get_param(f);
	    }
	    kv += '\n';
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
	pout.clear();
	if(sig.size()==md_len && !memcmp(&(sig.front()),md,md_len)) {
	    pout["is_valid"]="true";
	    pout["lifetime"]="60"; /* TODO: eventually remove deprecated stuff */
	}else{
	    pout["is_valid"]="false";
	    pout["lifetime"]="0"; /* TODO: eventually remove deprecated stuff */
	}
	if(pin.has_param("openid.invalidate_handle")) {
	    string h = pin.get_param("openid.invalidate_handle");
	    try {
		assoc_t tmp = retrieve_assoc(h);
	    }catch(invalid_handle& ih) {
		pout["invalidate_handle"] = h;
	    }catch(failed_lookup& fl) { }
	}
    }

}
