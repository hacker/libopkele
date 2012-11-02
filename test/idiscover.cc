#include <iostream>
#include <stdexcept>
#include <iterator>
#include <algorithm>
#include <unistd.h>
using namespace std;
#include <opkele/exception.h>
#include <opkele/discovery.h>
#include <opkele/util.h>
#include <opkele/util-internal.h>

namespace opkele {
    ostream& operator<<(ostream& o,const opkele::openid_endpoint_t& oep) {
	o
	    << " URI:        " << oep.uri << endl
	    << " Claimed ID: " << oep.claimed_id << endl
	    << " Local ID:   " << oep.local_id << endl;
	return o;
    }
}

int main(int argc,char **argv) {
    try {
	if(argc<2)
	    throw opkele::exception(OPKELE_CP_ "Please, give me something to resolve");
	for(int a=1;a<argc;++a) {
	    cout << "==============================================================" << endl
		<< "User-supplied ID: " << argv[a] << endl
		<< "Endpoints:" << endl
		<< " --" << endl;
	    string normalized = opkele::idiscover(
			ostream_iterator<opkele::openid_endpoint_t>(cout," --\n")
		     ,argv[a]);
	    cout << "Normalized ID:   " << normalized << endl;
	}
    }catch(exception& e) {
	cerr << "oops, caught " << opkele::util::abi_demangle(typeid(e).name()) << endl
	    << " .what(): " << e.what() << endl;
	_exit(1);
    }
    _exit(0);
}
