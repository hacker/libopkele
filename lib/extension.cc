#include <opkele/exception.h>
#include <opkele/extension.h>

namespace opkele {

    void extension_t::rp_checkid_hook(basic_openid_message&) {
	throw not_implemented(OPKELE_CP_ "RP checkid_* hook not implemented"); }
    void extension_t::rp_id_res_hook(const basic_openid_message&,
	    const basic_openid_message&) {
	throw not_implemented(OPKELE_CP_ "RP id_res hook not implemented"); }

    void extension_t::op_checkid_hook(const basic_openid_message&) {
	throw not_implemented(OPKELE_CP_ "OP checkid_* hook not implemented"); }
    void extension_t::op_id_res_hook(basic_openid_message& om) {
	throw not_implemented(OPKELE_CP_ "OP id_res hook not implemented"); }


    void extension_t::checkid_hook(basic_openid_message&) {
	throw not_implemented(OPKELE_CP_ "deprecated consumer checkid_* hook not implemented"); }
    void extension_t::id_res_hook(const basic_openid_message&,
	    const basic_openid_message&) {
	throw not_implemented(OPKELE_CP_ "deprecated consumer id_res hook not implemented"); }

    void extension_t::checkid_hook(const basic_openid_message&,basic_openid_message&) {
	throw not_implemented(OPKELE_CP_ "deprecated server checkid hook not implemented"); }
}
