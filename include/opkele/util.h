#ifndef __OPKELE_UTIL_H
#define __OPKELE_UTIL_H

#include <time.h>
#include <string>
#include <vector>
#include <openssl/bn.h>
#include <openssl/dh.h>

namespace opkele {
    using std::string;
    using std::vector;

    namespace util {

	class bignum_t {
	    public:
		BIGNUM *_bn;

		bignum_t() : _bn(0) { }
		bignum_t(BIGNUM *bn) : _bn(bn) { }
		~bignum_t() throw() { if(_bn) BN_free(_bn); }
		
		bignum_t& operator=(BIGNUM *bn) { if(_bn) BN_free(_bn); _bn = bn; return *this; }

		operator const BIGNUM*(void) const { return _bn; }
		operator BIGNUM*(void) { return _bn; }
	};
	class dh_t {
	    public:
		DH *_dh;
		
		dh_t() : _dh(0) { }
		dh_t(DH *dh) : _dh(dh) { }
		~dh_t() throw() { if(_dh) DH_free(_dh); }

		dh_t& operator=(DH *dh) { if(_dh) DH_free(_dh); _dh = dh; return *this; }

		operator const DH*(void) const { return _dh; }
		operator DH*(void) { return _dh; }

		DH* operator->() { return _dh; }
		const DH* operator->() const { return _dh; }
	};

	BIGNUM *base64_to_bignum(const string& b64);
	BIGNUM *dec_to_bignum(const string& dec);
	string bignum_to_base64(const BIGNUM *bn);

	string time_to_w3c(time_t t);
	time_t w3c_to_time(const string& w);

	string url_encode(const string& str);

	string long_to_string(long l);
	long string_to_long(const string& s);

	string encode_base64(const void *data,size_t length);
	void decode_base64(const string& data,vector<unsigned char>& rv);
    }

}

#endif /* __OPKELE_UTIL_H */
