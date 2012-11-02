#include <iostream>
#include <stdexcept>
#include <unistd.h>
using namespace std;
#include <opkele/exception.h>
#include <opkele/util.h>

#include "config.h"

class failed_test : public opkele::exception {
    public:
	failed_test(OPKELE_E_PARS)
	    : exception(OPKELE_E_CONS) { }
};

void test_rfc_3986_normalize_uri(const string &ouri,bool success,const string& nuri="") {
    try {
	string n = opkele::util::rfc_3986_normalize_uri(ouri);
	if(!success)
	    throw failed_test(OPKELE_CP_ "Normalized URI when it shouldn't ('"+ouri+"' normalization resulted in '"+n+"')");
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
    test_rfc_3986_normalize_uri(
	    "http://www.xxx.com/openid/1", true, "http://www.xxx.com/openid/1" );
}

void test_w3c_to_time(const char *w3c,time_t expected) {
    time_t t = opkele::util::w3c_to_time(w3c);
    if(t!=expected) {
	char tmp[512]; snprintf(tmp,sizeof(tmp)-1,
		"test failed for %s, expected %lu, got %lu (expected-got == %lu)",
		w3c, (unsigned long)expected, (unsigned long)t,
		(unsigned long)(expected-t) );
	throw failed_test(OPKELE_CP_ tmp);
    }
}

void test_w3c_to_time() {
    test_w3c_to_time("2008-06-29T12:33:44",1214742824);
}

int main() {
    try {
	test_w3c_to_time();
	test_rfc_3986_normalize_uri();
    }catch(failed_test& ft) {
	cerr << "Test failed: " << ft.what() << endl;
    }catch(exception& e) {
	cerr << "oops: " << e.what() << endl;
	_exit(1);
    }
    _exit(0);
}
