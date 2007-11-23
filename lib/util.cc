#include <errno.h>
#include <cassert>
#include <cctype>
#include <cstring>
#include <vector>
#include <string>
#include <stack>
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

	/*
	 * Normalize URL according to the rules, described in rfc 3986, section 6
	 *
	 * - uppercase hext triplets (e.g. %ab -> %AB)
	 * - lowercase scheme and host
	 * - decode %-encoded characters, specified as unreserved in rfc 3986, section 2.3,
	 *   that is - [:alpha:][:digit:]._~-
	 * - remove dot segments
	 * - remove empty and default ports
	 * - if there's no path component, add '/'
	 */
	 string rfc_3986_normalize_uri(const string& uri) {
	     string rv;
	     string::size_type colon = uri.find(':');
	     if(colon==string::npos)
		 throw bad_input(OPKELE_CP_ "No scheme specified in URI");
	     transform(
		     uri.begin(), uri.begin()+colon+1,
		     back_inserter(rv), ::tolower );
	     bool s;
	     if(rv=="http:")
		 s = false;
	     else if(rv=="https:")
		 s = true;
	     else
		 throw not_implemented(OPKELE_CP_ "Only http(s) URIs can be normalized here");
	     string::size_type ul = uri.length();
	     if(ul <= (colon+3))
		 throw bad_input(OPKELE_CP_ "Unexpected end of URI being normalized encountered");
	     if(uri[colon+1]!='/' || uri[colon+2]!='/')
		 throw bad_input(OPKELE_CP_ "Unexpected input in URI being normalized after scheme component");
	     rv += "//";
	     string::size_type interesting = uri.find_first_of(":/#?",colon+3);
	     if(interesting==string::npos) {
		 transform(
			 uri.begin()+colon+3,uri.end(),
			 back_inserter(rv), ::tolower );
		 rv += '/'; return rv;
	     }
	     transform(
		     uri.begin()+colon+3,uri.begin()+interesting,
		     back_inserter(rv), ::tolower );
	     bool qf = false;
	     char ic = uri[interesting];
	     if(ic==':') {
		 string::size_type ni = uri.find_first_of("/#?%",interesting+1);
		 const char *nptr = uri.data()+interesting+1;
		 char *eptr = 0;
		 long port = strtol(nptr,&eptr,10);
		 if( (port>0) && (port<65535) && port!=(s?443:80) ) {
		     char tmp[6];
		     snprintf(tmp,sizeof(tmp),"%d",port);
		     rv += ':'; rv += tmp;
		 }
		 if(ni==string::npos) {
		     rv += '/'; return rv;
		 }
		 interesting = ni;
	     }else if(ic!='/') {
		 rv += '/'; rv += ic;
		 qf = true;
		 ++interesting;
	     }
	     string::size_type n = interesting;
	     char tmp[3] = { 0,0,0 };
	     stack<string::size_type> psegs; psegs.push(rv.length());
	     string pseg;
	     for(;n<ul;) {
		 string::size_type unsafe = uri.find_first_of(qf?"%":"%/?#",n);
		 if(unsafe==string::npos) {
		     pseg.append(uri,n,ul-n-1); n = ul-1;
		 }else{
		     pseg.append(uri,n,unsafe-n);
		     n = unsafe;
		 }
		 char c = uri[n++];
		 if(c=='%') {
		     if((n+1)>=ul)
			 throw bad_input(OPKELE_CP_ "Unexpected end of URI encountered while parsing percent-encoded character");
		     tmp[0] = uri[n++];
		     tmp[1] = uri[n++];
		     if(!( isxdigit(tmp[0]) && isxdigit(tmp[1]) ))
			 throw bad_input(OPKELE_CP_ "Invalid percent-encoded character in URI being normalized");
		     int cc = strtol(tmp,0,16);
		     if( isalpha(cc) || isdigit(cc) || strchr("._~-",cc) )
			 pseg += cc;
		     else{
			 pseg += '%';
			 pseg += toupper(tmp[0]); pseg += toupper(tmp[1]);
		     }
		 }else if(qf) {
		     rv += pseg; rv += c;
		     pseg.clear();
		 }else if(n>=ul || strchr("?/#",c)) {
		     if(pseg.empty() || pseg==".") {
		     }else if(pseg=="..") {
			 if(psegs.size()>1) {
			     rv.resize(psegs.top()); psegs.pop();
			 }
		     }else{
			 psegs.push(rv.length());
			 if(c!='/') {
			     pseg += c;
			     qf = true;
			 }
			 rv += '/'; rv += pseg;
		     }
		     if(c=='/' && (n>=ul || strchr("?#",uri[n])) ) {
			 rv += '/';
			 if(n<ul)
			     qf = true;
		     }else if(strchr("?#",c)) {
			 if(psegs.size()==1 && psegs.top()==rv.length())
			     rv += '/';
			 if(pseg.empty())
			     rv += c;
			 qf = true;
		     }
		     pseg.clear();
		 }else{
		     pseg += c;
		 }
	     }
	     if(!pseg.empty()) {
		 rv += '/'; rv += pseg;
	     }
	     return rv;
	 }

    }

}
