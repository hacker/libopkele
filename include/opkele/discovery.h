#ifndef __OPKELE_DISCOVERY_H
#define __OPKELE_DISCOVERY_H

#include <string>
#include <opkele/types.h>

namespace opkele {
    using std::string;

    struct idiscovery_t;

    void idiscover(idiscovery_t& result,const string& identity);

    struct idiscovery_t {
	bool xri_identity;
	string normalized_id;
	string canonicalized_id;
	xrd::XRD_t xrd;

	idiscovery_t() { }
	idiscovery_t(const string& i) {
	    idiscover(*this,i);
	}
	idiscovery_t(const char *i) {
	    idiscover(*this,i);
	}

	void clear() {
	    normalized_id.clear(); canonicalized_id.clear();
	    xrd.clear();
	}

	idiscovery_t& operator=(const string& i) {
	    idiscover(*this,i); return *this; }
	idiscovery_t& operator=(const char *i) {
	    idiscover(*this,i); return *this; }
    };
}

#endif /* __OPKELE_DISCOVERY_H */
