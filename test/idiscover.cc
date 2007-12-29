#include <iostream>
#include <stdexcept>
#include <iterator>
#include <algorithm>
using namespace std;
#include <opkele/exception.h>
#include <opkele/discovery.h>

template<typename _PDT>
    ostream& operator<<(ostream& o,const opkele::xrd::priority_map<_PDT>& pm) {
	for(typename opkele::xrd::priority_map<_PDT>::const_iterator i=pm.begin();
		i!=pm.end();++i)
	    o << ' ' << i->second << '[' << i->first << ']';
	return o;
    }

ostream& operator<<(ostream& o,const opkele::xrd::service_t s) {
    o << "{" << endl
	<< " Type: ";
    copy(s.types.begin(),s.types.end(),
	    ostream_iterator<string>(o," "));
    o << endl
	<< " URI: " << s.uris << endl
	<< " LocalID: " << s.local_ids << endl;
    o << "}";
}

int main(int argc,char **argv) {
    try {
	if(argc<2)
	    throw opkele::exception(OPKELE_CP_ "Please, give me something to resolve");
	for(int a=1;a<argc;++a) {
	    opkele::idiscovery_t discovery(argv[a]);
	    clog
		<< "===============================================================" << endl
		<< "User-supplied ID: " << argv[a] << endl
		<< "Normalized ID: " << discovery.normalized_id << endl
		<< "Canonicalized ID: " << discovery.canonicalized_id << endl
		<< "The identity is " << (discovery.xri_identity?"":"not ") << "an i-name" << endl;
	    if(discovery.xrd.expires)
		clog << "Information expires in " << discovery.xrd.expires-time(0) << " seconds" << endl;
	    clog << endl
		<< "CanonicalID: " << discovery.xrd.canonical_ids << endl
		<< "LocalID: " << discovery.xrd.local_ids << endl
		<< "Services: " << discovery.xrd.services << endl;
	}
    }catch(exception& e) {
	cerr << "oops: " << e.what() << endl;
	_exit(1);
    }
    _exit(0);
}
