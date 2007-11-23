#include <iostream>
#include <stdexcept>
using namespace std;
#include <opkele/exception.h>
#include <opkele/consumer.h>
#include <opkele/util.h>

#include "config.h"

class failed_test : public opkele::exception {
    public:
	failed_test(OPKELE_E_PARS)
	    : exception(OPKELE_E_CONS) { }
};

class dummy_consumer_t : public opkele::consumer_t {
    public:
	virtual opkele::assoc_t store_assoc(const string& /* server */,const string& /* handle */,const opkele::secret_t& /* secret */,int /* expires_in */) {
	    throw opkele::not_implemented(OPKELE_CP_ "Not implemented");
	}
	virtual opkele::assoc_t retrieve_assoc(const string& /* server */ ,const string& /* handle */) {
	    throw opkele::not_implemented(OPKELE_CP_ "Not implemented");
	}
	virtual void invalidate_assoc(const string& /* server */,const string& /* handle */) {
	    throw opkele::not_implemented(OPKELE_CP_ "Not implemented");
	}
};


void test_retrieve_links(const string& f,bool success,const string& s="",const string& d="") {
    dummy_consumer_t dc;
    string server, delegate;
    try {
	dc.retrieve_links("file://" OPKELE_SRC_DIR "/test/html/"+f,server,delegate);
	if(!success)
	    throw failed_test(OPKELE_CP_ "Retrieved links when it shouldn't");
	if(server!=s)
	    throw failed_test(OPKELE_CP_ "retrieve_links test failed, expected server '"+s+"', got '"+server+"'");
	if(delegate!=d)
	    throw failed_test(OPKELE_CP_ "retrieve_links test failed, expected delegate '"+d+"', got '"+delegate+"'");
    }catch(opkele::bad_input& obi) {
	if(success)
	    throw failed_test(OPKELE_CP_ "Test '"+f+"' failed due to 'bad_input'["+obi.what()+"]");
    }catch(opkele::failed_assertion& ofa) {
	if(success)
	    throw failed_test(OPKELE_CP_ "Test '"+f+"' failed due to 'failed_assertion'["+ofa.what()+"]");
    }
}

void test_retrieve_links() {
    test_retrieve_links("empty.html",false);
    test_retrieve_links("in-body.html",false);
    test_retrieve_links("head-in-body.html",false);
    test_retrieve_links("hkn.html",true,"http://www.klever.net/openid.server","http://hacker.klever.net/");
    test_retrieve_links("hkn-server.html",true,"http://www.klever.net/openid.server");
    test_retrieve_links("hkn-delegate.html",false);
    test_retrieve_links("unclosed-head.html",true,"http://www.klever.net/openid.server","http://hacker.klever.net/");
    test_retrieve_links("spaced-links.html",true,"http://www.klever.net/openid.server","http://hacker.klever.net/");
    test_retrieve_links("spaced-link-attrs.html",true,"http://www.klever.net/openid.server","http://hacker.klever.net/");
    test_retrieve_links("2rels.html",true,"http://www.klever.net/openid.server","http://www.klever.net/openid.server");
}

void test_rfc_3986_normalize_uri(const string &ouri,bool success,const string& nuri="") {
    try {
	string n = opkele::util::rfc_3986_normalize_uri(ouri);
	if(!success)
	    throw failed_test(OPKELE_CP_ "Normalized URI when it shouldn't");
	if(n!=nuri)
	    throw failed_test(OPKELE_CP_ "rfc_3986_test_failed for '"+ouri+"' failed, expected '"+nuri+"', got '"+n+"'");
    }catch(opkele::bad_input& obi) {
	if(success)
	    throw failed_test(OPKELE_CP_ "Test '"+ouri+"' failed due to 'bad_input'["+obi.what()+"]");
    }catch(opkele::not_implemented& oni) {
	if(success)
	    throw failed_test(OPKELE_CP_ "Test '"+ouri+"' failed due to 'not_implemented'["+oni.what()+"]");
    }
}

void test_rfc_3986_normalize_uri() {
    test_rfc_3986_normalize_uri(
	    "invalid", false );
    test_rfc_3986_normalize_uri(
	    "ftp://hacker.klever.net/", false );
    test_rfc_3986_normalize_uri(
	    "http://", false );
    test_rfc_3986_normalize_uri(
	    "http:/hacker.klever.net/", false );
    test_rfc_3986_normalize_uri(
	    "hTTp://hacker.klever.net#uh?oh", true, "http://hacker.klever.net/#uh?oh" );
    test_rfc_3986_normalize_uri(
	    "http://hacker.klever.net?uh#oh", true, "http://hacker.klever.net/?uh#oh" );
    test_rfc_3986_normalize_uri(
	    "http://hacker.klever.net:80/", true, "http://hacker.klever.net/" );
    test_rfc_3986_normalize_uri(
	    "http://hacker.klever.net:80?uh", true, "http://hacker.klever.net/?uh" );
    test_rfc_3986_normalize_uri(
	    "http://hacker.klever.net:80#uh", true, "http://hacker.klever.net/#uh" );
    test_rfc_3986_normalize_uri(
	    "https://hacker.klever.net:443", true, "https://hacker.klever.net/" );
    test_rfc_3986_normalize_uri(
	    "http://hacker.klever.net:?oh", true, "http://hacker.klever.net/?oh" );
    test_rfc_3986_normalize_uri(
	    "http://hacker.klever.net/ah%2E", true, "http://hacker.klever.net/ah." );
    test_rfc_3986_normalize_uri(
	    "http://hacker.klever.net/ah/%2E/", true, "http://hacker.klever.net/ah/" );
    test_rfc_3986_normalize_uri(
	    "http://hacker.klever.net/ah/%2b/", true, "http://hacker.klever.net/ah/%2B/" );
    test_rfc_3986_normalize_uri(
	    "http://hacker.klever.net/ah/./oh?eh", true, "http://hacker.klever.net/ah/oh?eh" );
    test_rfc_3986_normalize_uri(
	    "http://hacker.klever.net/ah/../oh?", true, "http://hacker.klever.net/oh?" );
    test_rfc_3986_normalize_uri(
	    "http://hacker.klever.net/ah//oh?", true, "http://hacker.klever.net/ah/oh?" );
    test_rfc_3986_normalize_uri(
	    "http://hacker.klever.net/ah/?", true, "http://hacker.klever.net/ah/?" );
    test_rfc_3986_normalize_uri(
	    "http://hacker.klever.net/ah/%", false );
    test_rfc_3986_normalize_uri(
	    "http://hacker.klever.net/ah/%a", false );
    test_rfc_3986_normalize_uri(
	    "http://hacker.klever.net/ah/%zx", false );
    test_rfc_3986_normalize_uri(
	    "http://hacker.klever.net/ah/%5x", false );
    test_rfc_3986_normalize_uri(
	    "Http://Hacker.Klever.Net:", true, "http://hacker.klever.net/" );
}

int main() {
    try {
	test_rfc_3986_normalize_uri();
	test_retrieve_links();
    }catch(failed_test& ft) {
	cerr << "Test failed: " << ft.what() << endl;
    }catch(exception& e) {
	cerr << "oops: " << e.what() << endl;
	_exit(1);
    }
    _exit(0);
}
