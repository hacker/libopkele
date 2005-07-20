#include <errno.h>
#include <cassert>
#include <vector>
#include <string>
#include <mimetic/mimetic.h>
#include <curl/curl.h>
#include "opkele/util.h"
#include "opkele/exception.h"

namespace opkele {
    using namespace std;

    namespace util {

	/*
	 * big numerics
	 */

	BIGNUM *base64_to_bignum(const string& b64) {
	    vector<unsigned char> bin;
	    mimetic::Base64::Decoder b;
	    mimetic::decode(
		    b64.begin(),b64.end(), b,
		    back_insert_iterator<vector<unsigned char> >(bin) );
	    BIGNUM *rv = BN_bin2bn(&(bin.front()),bin.size(),0);
	    if(!rv)
		throw failed_conversion(OPKELE_CP_ "failed to BN_bin2bn()");
	    return rv;
	}

	BIGNUM *dec_to_bignum(const string& dec) {
	    BIGNUM *rv = 0;
	    if(!BN_dec2bn(&rv,dec.c_str()))
		throw failed_conversion(OPKELE_CP_ "failed to BN_dec2bn()");
	    return rv;
	}

	string bignum_to_base64(const BIGNUM *bn) {
	    vector<unsigned char> bin(BN_num_bytes(bn));
	    int l = BN_bn2bin(bn,&(bin.front()));
	    string rv;
	    mimetic::Base64::Encoder b(0);
	    mimetic::encode(
		    bin.begin(),bin.begin()+l, b,
		    back_insert_iterator<string>(rv) );
	    return rv;
	}

	/*
	 * w3c times
	 */

	string time_to_w3c(time_t t) {
	    struct tm tm_t;
	    if(!gmtime_r(&t,&tm_t))
		throw failed_conversion(OPKELE_CP_ "failed to BN_dec2bn()");
	    char rv[25];
	    if(!strftime(rv,sizeof(rv)-1,"%Y-%m-%dT%H:%M:%SZ",&tm_t))
		throw failed_conversion(OPKELE_CP_ "failed to strftime()");
	    return rv;
	}

	time_t w3c_to_time(const string& w) {
	    struct tm tm_t;
	    memset(&tm_t,0,sizeof(tm_t));
	    if(
		    sscanf(
			w.c_str(),
			"%04d-%02d-%02dT%02d:%02d:%02dZ",
			&tm_t.tm_year,&tm_t.tm_mon,&tm_t.tm_mday,
			&tm_t.tm_hour,&tm_t.tm_min,&tm_t.tm_sec
		    ) != 6 )
		throw failed_conversion(OPKELE_CP_ "failed to sscanf()");
	    tm_t.tm_mon--;
	    tm_t.tm_year-=1900;
	    time_t rv = mktime(&tm_t);
	    if(rv==(time_t)-1)
		throw failed_conversion(OPKELE_CP_ "failed to mktime()");
	    return rv;
	}

	/*
	 *
	 */

	string url_encode(const string& str) {
	    char * t = curl_escape(str.c_str(),str.length());
	    if(!t)
		throw failed_conversion(OPKELE_CP_ "failed to curl_escape()");
	    string rv(t);
	    curl_free(t);
	    return rv;
	}

	string long_to_string(long l) {
	    char rv[32];
	    int r=snprintf(rv,sizeof(rv),"%ld",l);
	    if(r<0 || r>=sizeof(rv))
		throw failed_conversion(OPKELE_CP_ "failed to snprintf()");
	    return rv;
	}

	long string_to_long(const string& s) {
	    char *endptr = 0;
	    long rv = strtol(s.c_str(),&endptr,10);
	    if((!endptr) || endptr==s.c_str())
		throw failed_conversion(OPKELE_CP_ "failed to strtol()");
	    return rv;
	}

    }

}
