#include <opkele/exception.h>
#include <opkele/extension.h>

namespace opkele {

    void extension_t::checkid_hook(params_t& /* p */,const string& /* identity */ ) {
	throw not_implemented(OPKELE_CP_ "Consumer checkid_hook not implemented");
    }
    void extension_t::id_res_hook(const params_t& /* p */,const params_t& /* sp */,const string& /* identity */) {
	throw not_implemented(OPKELE_CP_ "Consumer id_res_hook not implemented");
    }
    void extension_t::checkid_hook(const params_t& /* pin */,params_t& /* pout */) {
	throw not_implemented(OPKELE_CP_ "Server checkid_hook not implemented");
    }
}
