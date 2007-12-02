#include <iostream>
#include <stdexcept>
#include <iterator>
#include <algorithm>
using namespace std;
#include <opkele/exception.h>
#include <opkele/openid_service_resolver.h>

int main(int argc,char **argv) {
    try {
	if(argc<2)
	    throw opkele::exception(OPKELE_CP_ "Please, give me something to resolve");
	opkele::openid_service_resolver_t resolver;
	for(int a=1;a<argc;++a) {
	    const opkele::openid_auth_info_t& iai = resolver.resolve(argv[a]);
	    clog
		<< "====================" << endl
		<< "canonical id is " << iai.canonical_id << endl
		<< endl
		<< "service priority is " << iai.auth_SEP.priority << endl
		<< "service types are " ;
	    copy(
		    iai.auth_SEP.xrd_Type.begin(), iai.auth_SEP.xrd_Type.end(),
		    ostream_iterator<string>(clog," ") );
	    clog << endl
		<< "service URI is " << iai.auth_SEP.xrd_URI  << endl;
	    if(!iai.auth_SEP.openid_Delegate.empty())
		clog << "openid:Delegate is " << iai.auth_SEP.openid_Delegate << endl;
	    clog << endl;
	}
    }catch(exception& e) {
	cerr << "oops: " << e.what() << endl;
	_exit(1);
    }
    _exit(0);
}
