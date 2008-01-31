#ifndef __OPKELE_UTIL_H
#define __OPKELE_UTIL_H

#include <time.h>
#include <string>
#include <vector>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <opkele/types.h>

namespace opkele {
    using std::string;
    using std::vector;

    /**
     * @brief opkele utils namespace
     */
    namespace util {

	/**
	 * Convenience class encapsulating SSL BIGNUM object for the purpose of
	 * automatical freeing.
	 */
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
	/**
	 * Convenience clas encapsulating SSL DH object for the purpose of
	 * automatic freeing.
	 */
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

	/**
	 * Convert base64-encoded SSL BIGNUM to internal representation.
	 * @param b64 base64-encoded number
	 * @return SSL BIGNUM
	 * @throw failed_conversion in case of error
	 */
	BIGNUM *base64_to_bignum(const string& b64);
	/**
	 * Convert decimal representation to SSL BIGNUM.
	 * @param dec decimal representation
	 * @return resulting BIGNUM
	 * @throw failed_conversion in case of error
	 */
	BIGNUM *dec_to_bignum(const string& dec);
	/**
	 * Convert SSL BIGNUM data to base64 encoded string.
	 * @param bn BIGNUM
	 * @return base64encoded string
	 */
	string bignum_to_base64(const BIGNUM *bn);

	/**
	 * Convert internal time representation to w3c format
	 * @param t internal representation
	 * @return w3c time
	 * @throw failed_conversion in case of error
	 */
	string time_to_w3c(time_t t);
	/**
	 * Convert W3C time representation to  internal time_t
	 * @param w w3c representation
	 * @return converted time
	 * @throw failed_conversion in case of error
	 */
	time_t w3c_to_time(const string& w);

	/**
	 * Encode string to the representation suitable for using in URL.
	 * @param str string to encode
	 * @return encoded string
	 * @throw failed_conversion in case of failure
	 */
	string url_encode(const string& str);

	/**
	 * Convert number to string
	 * @param l number
	 * @return string representation
	 * @throw failed_conversion in case of failure
	 */
	string long_to_string(long l);
	/**
	 * Convert string to number
	 * @param s string, containing the number
	 * @return the number
	 * @throw failed_conversion in case of failure
	 */
	long string_to_long(const string& s);

	/**
	 * Encode binary data using base64.
	 * @param data pointer to binary data
	 * @param length length of data
	 * @return encoded data
	 */
	string encode_base64(const void *data,size_t length);
	/**
	 * Decode binary data from base64 representation.
	 * @param data base64-encoded data
	 * @param rv container for decoded binary
	 */
	void decode_base64(const string& data,vector<unsigned char>& rv);

	/**
	 * Normalize http(s) URI according to RFC3986, section 6. URI is
	 * expected to have scheme: in front of it.
	 * @param uri URI
	 * @return normalized URI
	 * @throw not_implemented in case of non-httpi(s) URI
	 * @throw bad_input in case of malformed URI
	 */
	string rfc_3986_normalize_uri(const string& uri);

	string& strip_uri_fragment_part(string& uri);

	string abi_demangle(const char* mn);

	string base64_signature(const assoc_t& assoc,const basic_openid_message& om);

	class change_mode_message_proxy : public basic_openid_message {
	    public:
		const basic_openid_message& x;
		const string& mode;

		change_mode_message_proxy(const basic_openid_message& xx,const string& m) : x(xx), mode(m) { }

		bool has_field(const string& n) const { return x.has_field(n); }
		const string& get_field(const string& n) const {
		    return (n=="mode")?mode:x.get_field(n); }
		bool has_ns(const string& uri) const {return x.has_ns(uri); }
		string get_ns(const string& uri) const { return x.get_ns(uri); }
		fields_iterator fields_begin() const {
		    return x.fields_begin(); }
		fields_iterator fields_end() const {
		    return x.fields_end(); }
	};

    }

}

#endif /* __OPKELE_UTIL_H */
