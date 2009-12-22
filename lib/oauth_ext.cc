#include <opkele/exception.h>
#include <opkele/oauth_ext.h>
#include <opkele/uris.h>
#include <algorithm>

namespace opkele {
    using std::find;

    void oauth_ext_t::rp_checkid_hook(basic_openid_message& om) {

	string pfx = om.allocate_ns(OIURI_OAUTH10,"oauth");
	//required: openid.oauth.consumer=www.plaxo.com
	//optional: openid.oauth.scope=http://www.google.com/m8/feeds/
	if (m_consumer.empty()) throw bad_input(OPKELE_CP_ "Required consumer key is missing from OAuth extension");
	om.set_field(pfx+".consumer", m_consumer);
	if (!m_scope.empty())  om.set_field(pfx+".scope", m_scope);
    }

    void oauth_ext_t::checkid_hook(basic_openid_message& om) {
	rp_checkid_hook(om); }

    void oauth_ext_t::rp_id_res_hook(const basic_openid_message& om,
	    const basic_openid_message& sp) {
	string pfx;
	try {
	    pfx = om.get_ns(OIURI_OAUTH10);
	}catch(failed_lookup&) {
		return;
	}
	pfx += '.';
	//required: openid.oauth.request_token=abcdefg
	//optional: openid.oauth.consumer=www.plaxo.com
	//optional: openid.oauth.scope=http://www.google.com/m8/feeds/
	string fn;

	fn = pfx + "request_token";
	if (sp.has_field(fn)) {
		m_request_token = sp.get_field(fn);
	} else throw bad_input(OPKELE_CP_ "Missing required response field: "+fn);

	fn = pfx + "consumer";
	if (sp.has_field(fn)) {
		m_consumer = sp.get_field(fn);
	}

	fn = pfx + "scope";
	if (sp.has_field(fn)) {
		m_scope = sp.get_field(fn);
	} 
    }

    void oauth_ext_t::id_res_hook(const basic_openid_message& om,
	    const basic_openid_message& sp) {
	rp_id_res_hook(om,sp); }

    void oauth_ext_t::op_checkid_hook(const basic_openid_message& inm) {
    }

    void oauth_ext_t::op_id_res_hook(basic_openid_message& oum) {
    }

    void oauth_ext_t::checkid_hook(const basic_openid_message& inm,
	    basic_openid_message& oum) {
	op_checkid_hook(inm);
        setup_response(inm,oum);
	op_id_res_hook(oum);
    }

    void oauth_ext_t::setup_response(const basic_openid_message& /* inm */,basic_openid_message& /* oum */) {
	setup_response();
    }
    void oauth_ext_t::setup_response() {
    }
}

