#include <cstdarg>
#include <opkele/extension_chain.h>

namespace opkele {

    void extension_chain_t::rp_checkid_hook(basic_openid_message& om) {
	for(iterator i=begin();i!=end();++i) (*i)->rp_checkid_hook(om); }
    void extension_chain_t::rp_id_res_hook(const basic_openid_message& om,
	    const basic_openid_message& sp) {
	for(iterator i=begin();i!=end();++i) (*i)->rp_id_res_hook(om,sp); }

    void extension_chain_t::op_checkid_hook(const basic_openid_message& inm) {
	for(iterator i=begin();i!=end();++i) (*i)->op_checkid_hook(inm); }
    void extension_chain_t::op_id_res_hook(basic_openid_message& oum) {
	for(iterator i=begin();i!=end();++i) (*i)->op_id_res_hook(oum); }


    void extension_chain_t::checkid_hook(basic_openid_message& om){ 
	for(iterator i=begin();i!=end();++i) (*i)->checkid_hook(om); }
    void extension_chain_t::id_res_hook(const basic_openid_message& om,
	    const basic_openid_message& sp) {
	for(iterator i=begin();i!=end();++i) (*i)->id_res_hook(om,sp); }
    void extension_chain_t::checkid_hook(const basic_openid_message& inm,
	    basic_openid_message& oum) {
	for(iterator i=begin();i!=end();++i) (*i)->checkid_hook(inm,oum); }

}
