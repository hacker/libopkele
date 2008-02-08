#include <time.h>
#include <cassert>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <opkele/data.h>
#include <opkele/basic_op.h>
#include <opkele/exception.h>
#include <opkele/util.h>
#include <opkele/uris.h>

namespace opkele {

    void basic_op::reset_vars() {
	assoc.reset();
	return_to.clear(); realm.clear();
	claimed_id.clear(); identity.clear();
	invalidate_handle.clear();
    }

    bool basic_op::has_return_to() const {
	return !return_to.empty();
    }
    const string& basic_op::get_return_to() const {
	if(return_to.empty())
	    throw no_return_to(OPKELE_CP_ "No return_to URL provided with request");
	return return_to;
    }

    const string& basic_op::get_realm() const {
	assert(!realm.empty());
	return realm;
    }

    bool basic_op::has_identity() const {
	return !identity.empty();
    }
    const string& basic_op::get_claimed_id() const {
	if(claimed_id.empty())
	    throw non_identity(OPKELE_CP_ "attempting to retrieve claimed_id of non-identity related request");
	assert(!identity.empty());
	return claimed_id;
    }
    const string& basic_op::get_identity() const {
	if(identity.empty())
	    throw non_identity(OPKELE_CP_ "attempting to retrieve identity of non-identity related request");
	assert(!claimed_id.empty());
	return identity;
    }

    bool basic_op::is_id_select() const {
	return identity==IDURI_SELECT20;
    }

    void basic_op::select_identity(const string& c,const string& i) {
	claimed_id = c; identity = i;
    }
    void basic_op::set_claimed_id(const string& c) {
	claimed_id = c;
    }

    basic_openid_message& basic_op::associate(
	    basic_openid_message& oum,
	    const basic_openid_message& inm) try {
	assert(inm.get_field("mode")=="associate");
	util::dh_t dh;
	util::bignum_t c_pub;
	unsigned char key_digest[SHA256_DIGEST_LENGTH];
	size_t d_len = 0;
	enum {
	    sess_cleartext, sess_dh_sha1, sess_dh_sha256
	} st = sess_cleartext;
	string sts = inm.get_field("session_type");
	string ats = inm.get_field("assoc_type");
	if(sts=="DH-SHA1" || sts=="DH-SHA256") {
	    if(!(dh = DH_new()))
		throw exception_openssl(OPKELE_CP_ "failed to DH_new()");
	    c_pub = util::base64_to_bignum(inm.get_field("dh_consumer_public"));
	    try { dh->p = util::base64_to_bignum(inm.get_field("dh_modulus"));
	    }catch(failed_lookup&) {
		dh->p = util::dec_to_bignum(data::_default_p); }
	    try { dh->g = util::base64_to_bignum(inm.get_field("dh_gen"));
	    }catch(failed_lookup&) {
		dh->g = util::dec_to_bignum(data::_default_g); }
	    if(!DH_generate_key(dh))
		throw exception_openssl(OPKELE_CP_ "failed to DH_generate_key()");
	    vector<unsigned char> ck(DH_size(dh)+1);
	    unsigned char *ckptr = &(ck.front())+1;
	    int cklen = DH_compute_key(ckptr,c_pub,dh);
	    if(cklen<0)
		throw exception_openssl(OPKELE_CP_ "failed to DH_compute_key()");
	    if(cklen && (*ckptr)&0x80) {
		(*(--ckptr)) = 0; ++cklen; }
	    if(sts=="DH-SHA1") {
		SHA1(ckptr,cklen,key_digest); d_len = SHA_DIGEST_LENGTH;
	    }else if(sts=="DH-SHA256") {
		SHA256(ckptr,cklen,key_digest); d_len = SHA256_DIGEST_LENGTH;
	    }else
		throw internal_error(OPKELE_CP_ "I thought I knew the session type");
	}else
	    throw unsupported(OPKELE_CP_ "Unsupported session_type");
	assoc_t assoc;
	if(ats=="HMAC-SHA1")
	    assoc = alloc_assoc(ats,SHA_DIGEST_LENGTH,true);
	else if(ats=="HMAC-SHA256")
	    assoc = alloc_assoc(ats,SHA256_DIGEST_LENGTH,true);
	else
	    throw unsupported(OPKELE_CP_ "Unsupported assoc_type");
	oum.reset_fields();
	oum.set_field("ns",OIURI_OPENID20);
	oum.set_field("assoc_type",assoc->assoc_type());
	oum.set_field("assoc_handle",assoc->handle());
	oum.set_field("expires_in",util::long_to_string(assoc->expires_in()));
	secret_t secret = assoc->secret();
	if(sts=="DH-SHA1" || sts=="DH-SHA256") {
	    if(d_len != secret.size())
		throw bad_input(OPKELE_CP_ "Association secret and session MAC are not of the same size");
	    oum.set_field("session_type",sts);
	    oum.set_field("dh_server_public",util::bignum_to_base64(dh->pub_key));
	    string b64; secret.enxor_to_base64(key_digest,b64);
	    oum.set_field("enc_mac_key",b64);
	}else /* TODO: support cleartext over encrypted connection */
	    throw unsupported(OPKELE_CP_ "Unsupported session type");
	return oum;
    } catch(unsupported& u) {
	oum.reset_fields();
	oum.set_field("ns",OIURI_OPENID20);
	oum.set_field("error",u.what());
	oum.set_field("error_code","unsupported-type");
	oum.set_field("session_type","DH-SHA256");
	oum.set_field("assoc_type","HMAC-SHA256");
	return oum;
    }

    void basic_op::checkid_(const basic_openid_message& inm,
	    extension_t *ext) {
	reset_vars();
	string mode = inm.get_field("mode");
	if(mode=="checkid_setup")
	    mode = mode_checkid_setup;
	else if(mode=="checkid_immediate")
	    mode = mode_checkid_immediate;
	else
	    throw bad_input(OPKELE_CP_ "Invalid checkid_* mode");
	try {
	    assoc = retrieve_assoc(invalidate_handle=inm.get_field("assoc_handle"));
	    invalidate_handle.clear();
	}catch(failed_lookup&) { }
	try {
	    openid2 = (inm.get_field("ns")==OIURI_OPENID20);
	}catch(failed_lookup&) { openid2 = false; }
	try {
	    return_to = inm.get_field("return_to");
	}catch(failed_lookup&) { }
	if(openid2) {
	    try {
		realm = inm.get_field("realm");
	    }catch(failed_lookup&) {
		try {
		    realm = inm.get_field("trust_root");
		}catch(failed_lookup&) {
		    if(return_to.empty())
			throw bad_input(OPKELE_CP_
				"Both realm and return_to are unset");
		    realm = return_to;
		}
	    }
	}else{
	    try {
		realm = inm.get_field("trust_root");
	    }catch(failed_lookup&) {
		if(return_to.empty())
		    throw bad_input(OPKELE_CP_
			    "Both realm and return_to are unset");
		realm = return_to;
	    }
	}
	try {
	    identity = inm.get_field("identity");
	    try {
		claimed_id = inm.get_field("claimed_id");
	    }catch(failed_lookup&) {
		if(openid2)
		    throw bad_input(OPKELE_CP_
			    "claimed_id and identity must be either both present or both absent");
		claimed_id = identity;
	    }
	}catch(failed_lookup&) {
	    if(openid2 && inm.has_field("claimed_id"))
		throw bad_input(OPKELE_CP_
		    "claimed_id and identity must be either both present or both absent");
	}
	verify_return_to();
	if(ext) ext->op_checkid_hook(inm);
    }

    basic_openid_message& basic_op::id_res(basic_openid_message& om,
	    extension_t *ext) {
	assert(!return_to.empty());
	assert(!is_id_select());
	if(!assoc) {
	    assoc = alloc_assoc("HMAC-SHA256",SHA256_DIGEST_LENGTH,true);
	}
	time_t now = time(0);
	struct tm gmt; gmtime_r(&now,&gmt);
	char w3timestr[24];
	if(!strftime(w3timestr,sizeof(w3timestr),"%Y-%m-%dT%H:%M:%SZ",&gmt))
	    throw failed_conversion(OPKELE_CP_
		    "Failed to build time string for nonce" );
	om.set_field("ns",OIURI_OPENID20);
	om.set_field("mode","id_res");
	om.set_field("op_endpoint",get_op_endpoint());
	string ats = "ns,mode,op_endpoint,return_to,response_nonce,"
	    "assoc_handle,signed";
	if(!identity.empty()) {
	    om.set_field("identity",identity);
	    om.set_field("claimed_id",claimed_id);
	    ats += ",identity,claimed_id";
	}
	om.set_field("return_to",return_to);
	string nonce = w3timestr;
	om.set_field("response_nonce",alloc_nonce(nonce,assoc->stateless()));
	if(!invalidate_handle.empty()) {
	    om.set_field("invalidate_handle",invalidate_handle);
	    ats += ",invalidate_handle";
	}
	om.set_field("assoc_handle",assoc->handle());
	om.add_to_signed(ats);
	if(ext) ext->op_id_res_hook(om);
	om.set_field("sig",util::base64_signature(assoc,om));
	return om;
    }

    basic_openid_message& basic_op::cancel(basic_openid_message& om) {
	assert(!return_to.empty());
	om.set_field("ns",OIURI_OPENID20);
	om.set_field("mode","cancel");
	return om;
    }

    basic_openid_message& basic_op::error(basic_openid_message& om,
	    const string& error,const string& contact,
	    const string& reference ) {
	assert(!return_to.empty());
	om.set_field("ns",OIURI_OPENID20);
	om.set_field("mode","error");
	om.set_field("error",error);
	om.set_field("contact",contact);
	om.set_field("reference",reference);
	return om;
    }

    basic_openid_message& basic_op::setup_needed(
	    basic_openid_message& oum,const basic_openid_message& inm) {
	assert(mode==mode_checkid_immediate);
	assert(!return_to.empty());
	if(openid2) {
	    oum.set_field("ns",OIURI_OPENID20);
	    oum.set_field("mode","setup_needed");
	}else{
	    oum.set_field("mode","id_res");
	    static const string setupmode = "checkid_setup";
	    oum.set_field("user_setup_url",
		    util::change_mode_message_proxy(inm,setupmode)
		    .append_query(get_op_endpoint()));
	}
	return oum;
    }

    basic_openid_message& basic_op::check_authentication(
	    basic_openid_message& oum,
	    const basic_openid_message& inm) try {
	assert(inm.get_field("mode")=="check_authentication");
	oum.reset_fields();
	oum.set_field("ns",OIURI_OPENID20);
	bool o2;
	try {
	    o2 = (inm.get_field("ns")==OIURI_OPENID20);
	}catch(failed_lookup&) { o2 = false; }
	string nonce;
	if(o2) {
	    try {
		if(!check_nonce(nonce = inm.get_field("response_nonce")))
		    throw failed_check_authentication(OPKELE_CP_ "Invalid nonce");
	    }catch(failed_lookup&) {
		throw failed_check_authentication(OPKELE_CP_ "No nonce provided with check_authentication request");
	    }
	}
	try {
	    assoc = retrieve_assoc(inm.get_field("assoc_handle"));
	    if(!assoc->stateless())
		throw failed_check_authentication(OPKELE_CP_ "Will not do check_authentication on a stateful handle");
	}catch(failed_lookup&) {
	    throw failed_check_authentication(OPKELE_CP_ "No assoc_handle or invalid assoc_handle specified with check_authentication request");
	}
	static const string idresmode = "id_res";
	try {
	    if(util::base64_signature(assoc,util::change_mode_message_proxy(inm,idresmode))!=inm.get_field("sig"))
		throw failed_check_authentication(OPKELE_CP_ "Signature mismatch");
	}catch(failed_lookup&) {
	    throw failed_check_authentication(OPKELE_CP_ "failed to calculate signature");
	}
	oum.set_field("is_valid","true");
	try {
	    string h = inm.get_field("invalidate_handle");
	    try {
		assoc_t ih = retrieve_assoc(h);
	    }catch(invalid_handle& ih) {
		oum.set_field("invalidate_handle",h);
	    }catch(failed_lookup& ih) {
		oum.set_field("invalidate_handle",h);
	    }
	}catch(failed_lookup&) { }
	if(o2) {
	    assert(!nonce.empty());
	    invalidate_nonce(nonce);
	}
	return oum;
    }catch(failed_check_authentication& ) {
	oum.set_field("is_valid","false");
	return oum;
    }

    void basic_op::verify_return_to() {
	if(realm.find('#')!=string::npos)
	    throw opkele::bad_realm(OPKELE_CP_ "authentication realm contains URI fragment");
	if(!util::uri_matches_realm(return_to,realm))
	    throw bad_return_to(OPKELE_CP_ "return_to URL doesn't match realm");
    }

}
