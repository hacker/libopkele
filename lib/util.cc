#include <errno.h>
#include <cassert>
#include <vector>
#include <string>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <curl/curl.h>
#include "opkele/util.h"
#include "opkele/exception.h"

namespace opkele {
    using namespace std;

    namespace util {

	/*
	 * base64
	 */
	string encode_base64(const void *data,size_t length) {
	    BIO *b64 = 0, *bmem = 0;
	    try {
		b64 = BIO_new(BIO_f_base64());
		if(!b64)
		    throw exception_openssl(OPKELE_CP_ "failed to BIO_new() base64 encoder");
		BIO_set_flags(b64,BIO_FLAGS_BASE64_NO_NL);
		bmem = BIO_new(BIO_s_mem());
		BIO_set_flags(b64,BIO_CLOSE);
		if(!bmem)
		    throw exception_openssl(OPKELE_CP_ "failed to BIO_new() memory buffer");
		BIO_push(b64,bmem);
		if(((size_t)BIO_write(b64,data,length))!=length)
		    throw exception_openssl(OPKELE_CP_ "failed to BIO_write()");
		if(BIO_flush(b64)!=1)
		    throw exception_openssl(OPKELE_CP_ "failed to BIO_flush()");
		char *rvd;
		long rvl = BIO_get_mem_data(bmem,&rvd);
		string rv(rvd,rvl);
		BIO_free_all(b64);
		return rv;
	    }catch(...) {
		if(b64) BIO_free_all(b64);
		throw;
	    }
	}

	void decode_base64(const string& data,vector<unsigned char>& rv) {
	    BIO *b64 = 0, *bmem = 0;
	    rv.clear();
	    try {
		bmem = BIO_new_mem_buf((void*)data.data(),data.size());
		if(!bmem)
		    throw exception_openssl(OPKELE_CP_ "failed to BIO_new_mem_buf()");
		b64 = BIO_new(BIO_f_base64());
		if(!b64)
		    throw exception_openssl(OPKELE_CP_ "failed to BIO_new() base64 decoder");
		BIO_set_flags(b64,BIO_FLAGS_BASE64_NO_NL);
		BIO_push(b64,bmem);
		unsigned char tmp[512];
		size_t rb = 0;
		while((rb=BIO_read(b64,tmp,sizeof(tmp)))>0)
		    rv.insert(rv.end(),tmp,&tmp[rb]);
		BIO_free_all(b64);
	    }catch(...) {
		if(b64) BIO_free_all(b64);
		throw;
	    }
	}

	/*
	 * big numerics
	 */

	BIGNUM *base64_to_bignum(const string& b64) {
	    vector<unsigned char> bin;
	    decode_base64(b64,bin);
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
	    vector<unsigned char> bin(BN_num_bytes(bn)+1);
	    unsigned char *binptr = &(bin.front())+1;
	    int l = BN_bn2bin(bn,binptr);
	    if(l && (*binptr)&0x80){
		(*(--binptr)) = 0; ++l;
	    }
	    return encode_base64(binptr,l);
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
	    if(r<0 || r>=(int)sizeof(rv))
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
