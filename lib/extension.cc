#include <opkele/exception.h>
#include <opkele/extension.h>

namespace opkele {

    void extension_t::checkid_hook(basic_openid_message&) {
	throw not_implemented(OPKELE_CP_ "Consumer checkid_hook not implemented");
    }
    void extension_t::id_res_hook(const basic_openid_message&,const basic_openid_message&) {
	throw not_implemented(OPKELE_CP_ "Consumer id_res_hook not implemented");
    }
    void extension_t::checkid_hook(const basic_openid_message&,basic_openid_message&) {
	throw not_implemented(OPKELE_CP_ "Server checkid_hook not implemented");
    }
}
