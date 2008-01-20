#include <opkele/types.h>
#include <opkele/exception.h>
#include <opkele/util.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "config.h"

namespace opkele {
    using namespace std;

    string params_t::append_query(const string& url,const char *prefix) const {
	string rv = url;
	bool p = true;
	if(rv.find('?')==string::npos) {
	    rv += '?'; p = false; }
	for(fields_iterator i=fields_begin();i!=fields_end();++i) {
	    if(p)
		rv += '&';
	    else
		p = true;
	    if(prefix) rv += prefix;
	    rv += *i;
	    rv += '=';
	    rv += util::url_encode(get_field(*i));
	}
	return rv;
    }

}
