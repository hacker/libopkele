#include <errno.h>
#include <cassert>
#include <cctype>
#include <cstring>
#include <vector>
#include <string>
#include <stack>
#include <algorithm>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <opkele/util.h>
#include <opkele/exception.h>
#include <opkele/data.h>
#include <opkele/debug.h>

#include <config.h>
#ifdef HAVE_DEMANGLE
# include <cxxabi.h>
#endif

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

#ifndef HAVE_TIMEGM
	static time_t timegm(struct tm *t) {
	    char *tz = getenv("TZ");
	    setenv("TZ","",1); tzset();
	    time_t rv = mktime(t);
	    if(tz)
		setenv("TZ",tz,1);
	    else
		unsetenv("TZ");
	    tzset();
	    return rv;
	}
#	define timegm opkele::util::timegm
#endif /* HAVE_TIMEGM */

	time_t w3c_to_time(const string& w) {
	    int fraction;
	    struct tm tm_t;
	    memset(&tm_t,0,sizeof(tm_t));
	    if( (
			sscanf(
			    w.c_str(),
			    "%04d-%02d-%02dT%02d:%02d:%02dZ",
			    &tm_t.tm_year,&tm_t.tm_mon,&tm_t.tm_mday,
			    &tm_t.tm_hour,&tm_t.tm_min,&tm_t.tm_sec
			    ) != 6
		) && (
		    sscanf(
			w.c_str(),
			"%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
			&tm_t.tm_year,&tm_t.tm_mon,&tm_t.tm_mday,
			&tm_t.tm_hour,&tm_t.tm_min,&tm_t.tm_sec,
			&fraction
			) != 7
		    ) )
		throw failed_conversion(OPKELE_CP_ "failed to sscanf()");
	    tm_t.tm_mon--;
	    tm_t.tm_year-=1900;
	    time_t rv = timegm(&tm_t);
	    if(rv==(time_t)-1)
		throw failed_conversion(OPKELE_CP_ "failed to gmtime()");
	    return rv;
	}

	/*
	 *
	 */

	static inline bool isrfc3986unreserved(int c) {
	    if(c<'-') return false;
	    if(c<='.') return true;
	    if(c<'0') return false; if(c<='9') return true;
	    if(c<'A') return false; if(c<='Z') return true;
	    if(c<'_') return false;
	    if(c=='_') return true;
	    if(c<'a') return false; if(c<='z') return true;
	    if(c=='~') return true;
	    return false;
	}

	struct __url_encoder : public unary_function<char,void> {
	    public:
		string& rv;

		__url_encoder(string& r) : rv(r) { }

		result_type operator()(argument_type c) {
		    if(isrfc3986unreserved(c))
			rv += c;
		    else{
			char tmp[4];
			snprintf(tmp,sizeof(tmp),"%%%02X",
				(c&0xff));
			rv += tmp;
		    }
		}
	};

	string url_encode(const string& str) {
	    string rv;
	    for_each(str.begin(),str.end(),
		    __url_encoder(rv));
	    return rv;
	}

	string url_decode(const string& str) {
	    string rv;
	    back_insert_iterator<string> ii(rv);
	    char tmp[3]; tmp[2] = 0;
	    for(string::const_iterator i=str.begin(),ie=str.end();
		    i!=ie;++i) {
		switch(*i) {
		    case '+':
			*(ii++) = ' '; break;
		    case '%':
			++i;
			if(i==ie)
			    throw failed_conversion(OPKELE_CP_ "trailing percent in the url-encoded string");
			tmp[0] = *(i++);
			if(i==ie)
			    throw failed_conversion(OPKELE_CP_ "not enough hexadecimals after the percent sign in url-encoded string");
			tmp[1] = *i;
			if(!(isxdigit(tmp[0]) && isxdigit(tmp[1])))
			    throw failed_conversion(OPKELE_CP_ "non-hex follows percent in url-encoded string");
			*(ii++) = (char)strtol(tmp,0,16);
			break;
		    default:
			*(ii++) = *i; break;
		}
	    }
	    return rv;
	}

	string attr_escape(const string& str) {
	    static const char *unsafechars = "<>&\n\"'";
	    string rv;
	    string::size_type p=0;
	    while(true) {
		string::size_type us = str.find_first_of(unsafechars,p);
		if(us==string::npos) {
		    if(p!=str.length())
			rv.append(str,p,str.length()-p);
		    return rv;
		}
		rv.append(str,p,us-p);
		rv += "&#";
		rv += long_to_string((long)str[us]);
		rv += ';';
		p = us+1;
	    }
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
	 * - uppercase hex triplets (e.g. %ab -> %AB)
	 * - lowercase scheme and host
	 * - decode %-encoded characters, specified as unreserved in rfc 3986, section 2.3,
	 *   that is - [:alpha:][:digit:]._~-
	 * - remove dot segments
	 * - remove empty and default ports
	 * - if there's no path component, add '/'
	 */
	 string rfc_3986_normalize_uri(const string& uri) {
	     string rv;
	     string::size_type ns = uri.find_first_not_of(data::_whitespace_chars);
	     if(ns==string::npos)
		 throw bad_input(OPKELE_CP_ "Can't normalize empty URI");
	     string::size_type colon = uri.find(':',ns);
	     if(colon==string::npos)
		 throw bad_input(OPKELE_CP_ "No scheme specified in URI");
	     transform(
		     uri.begin()+ns, uri.begin()+colon+1,
		     back_inserter(rv), ::tolower );
	     bool s;
	     string::size_type ul = uri.find_last_not_of(data::_whitespace_chars)+1;
	     if(ul <= (colon+3))
		 throw bad_input(OPKELE_CP_ "Unexpected end of URI being normalized encountered");
	     if(uri[colon+1]!='/' || uri[colon+2]!='/')
		 throw bad_input(OPKELE_CP_ "Unexpected input in URI being normalized after scheme component");
	     if(rv=="http:")
		 s = false;
	     else if(rv=="https:")
		 s = true;
	     else{
		 /* TODO: support more schemes.  e.g. xri. How do we normalize
		  * xri?
		  */
		 rv.append(uri,colon+1,ul-colon-1);
		 return rv;
	     }
	     rv += "//";
	     string::size_type interesting = uri.find_first_of(":/#?",colon+3);
	     if(interesting==string::npos) {
		 transform(
			 uri.begin()+colon+3,uri.begin()+ul,
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
		     char tmp[8];
		     snprintf(tmp,sizeof(tmp),":%ld",port);
		     rv += tmp;
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
			 pseg += (char)cc;
		     else{
			 pseg += '%';
			 pseg += (char)toupper(tmp[0]); pseg += (char)toupper(tmp[1]);
		     }
		 }else if(qf) {
		     rv += pseg; rv += c;
		     pseg.clear();
		 }else if(n>=ul || strchr("?/#",c)) {
		     if( (unsafe!=string::npos && pseg.empty()) || pseg==".") {
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
		 if(!qf) rv += '/';
		 rv += pseg;
	     }
	     return rv;
	 }

	string& strip_uri_fragment_part(string& u) {
	    string::size_type q = u.find('?'), f = u.find('#');
	    if(q==string::npos) {
		if(f!=string::npos)
		    u.erase(f);
	    }else{
		if(f!=string::npos) {
		    if(f<q)
			u.erase(f,q-f);
		    else
			u.erase(f);
		}
	    }
	    return u;
	}

	bool uri_matches_realm(const string& uri,const string& realm) {
	    string nrealm = opkele::util::rfc_3986_normalize_uri(realm);
	    string nu = opkele::util::rfc_3986_normalize_uri(uri);
	    string::size_type pr = nrealm.find("://");
	    string::size_type pu = nu.find("://");
	    assert(!(pr==string::npos || pu==string::npos));
	    pr += sizeof("://")-1;
	    pu += sizeof("://")-1;
	    if(!strncmp(nrealm.c_str()+pr,"*.",2)) {
		pr = nrealm.find('.',pr);
		pu = nu.find('.',pu);
		assert(pr!=string::npos);
		if(pu==string::npos)
		    return false;
		// TODO: check for overgeneralized realm
	    }
	    string::size_type lr = nrealm.length();
	    string::size_type lu = nu.length();
	    if( (lu-pu) < (lr-pr) )
		return false;
	    pair<const char*,const char*> mp = mismatch(
		    nrealm.c_str()+pr,nrealm.c_str()+lr,
		    nu.c_str()+pu);
	    if( (*(mp.first-1))!='/'
		    && !strchr("/?#",*mp.second) )
		return false;
	    return true;
	}

	string abi_demangle(const char *mn) {
#ifndef HAVE_DEMANGLE
	    return mn;
#else /* !HAVE_DEMANGLE */
	    int dstat;
	    char *demangled = abi::__cxa_demangle(mn,0,0,&dstat);
	    if(dstat)
		return mn;
	    string rv = demangled;
	    free(demangled);
	    return rv;
#endif /* !HAVE_DEMANGLE */
	}

	string base64_signature(const assoc_t& assoc,const basic_openid_message& om) {
	    const string& slist = om.get_field("signed");
	    string kv;
	    string::size_type p=0;
	    while(true) {
		string::size_type co = slist.find(',',p);
		string f = (co==string::npos)
		    ?slist.substr(p):slist.substr(p,co-p);
		kv += f;
		kv += ':';
		kv += om.get_field(f);
		kv += '\n';
		if(co==string::npos) break;
		p = co+1;
	    }
	    const secret_t& secret = assoc->secret();
	    const EVP_MD *evpmd;
	    const string& at = assoc->assoc_type();
	    if(at=="HMAC-SHA256")
		evpmd = EVP_sha256();
	    else if(at=="HMAC-SHA1")
		evpmd = EVP_sha1();
	    else
		throw unsupported(OPKELE_CP_ "unknown association type");
	    unsigned int md_len = 0;
	    unsigned char md[SHA256_DIGEST_LENGTH];
	    HMAC(evpmd,
		    &(secret.front()),secret.size(),
		    (const unsigned char*)kv.data(),kv.length(),
		    md,&md_len);
	    return encode_base64(md,md_len);
	}

	string normalize_identifier(const string& usi,bool strip_fragment) {
	    if(usi.empty())
		return usi;
	    string rv;
	    string::size_type fsc = usi.find_first_not_of(data::_whitespace_chars);
	    if(fsc==string::npos)
		return rv;
	    string::size_type lsc = usi.find_last_not_of(data::_whitespace_chars);
	    assert(lsc!=string::npos);
	    if(!strncasecmp(usi.c_str()+fsc,"xri://",sizeof("xri://")-1))
		fsc += sizeof("xri://")-1;
	    if( (fsc+1) >= lsc )
		return rv;
	    rv.assign(usi,fsc,lsc-fsc+1);
	    if(strchr(data::_iname_leaders,rv[0])) {
		/* TODO: further normalize xri identity, fold case or
		 * whatever... */
	    }else{
		if(rv.find("://")==string::npos)
		    rv.insert(0,"http://");
		if(strip_fragment) {
		    string::size_type fp = rv.find('#');
		    if(fp!=string::npos) {
			string::size_type qp = rv.find('?');
			if(qp==string::npos || qp<fp)
			    rv.erase(fp);
			else if(qp>fp)
			    rv.erase(fp,qp-fp);
		    }
		}
		rv = rfc_3986_normalize_uri(rv);
	    }
	    return rv;
	}

    }

}
