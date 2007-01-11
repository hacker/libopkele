#include <cstdarg>
#include <opkele/extension_chain.h>

namespace opkele {

    void extension_chain_t::checkid_hook(params_t& p,const string& identity) {
	for(iterator i=begin();i!=end();++i) (*i)->checkid_hook(p,identity);
    }
    void extension_chain_t::id_res_hook(const params_t& p,const params_t& sp,const string& identity) {
	for(iterator i=begin();i!=end();++i) (*i)->id_res_hook(p,sp,identity);
    }
    void extension_chain_t::checkid_hook(const params_t& pin,params_t& pout) {
	for(iterator i=begin();i!=end();++i) (*i)->checkid_hook(pin,pout);
    }

}
