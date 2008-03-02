#ifndef __OPKELE_UTIL_H
#define __OPKELE_UTIL_H

#include <time.h>
#include <string>
#include <vector>
#include <opkele/types.h>

namespace opkele {
    using std::string;
    using std::vector;

    /**
     * @brief opkele utils namespace
     */
    namespace util {

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
	 * Encode string to the representation suitable for using in URL
	 * @param str string to encode
	 * @return encoded string
	 * @throw failed_conversion in case of failure
	 */
	string url_encode(const string& str);

	/**
	 * Decode url-encoded string back to normal
	 * @param str url-encoded string
	 * @return decoded string
	 * @throw failed_conversion in case of failure
	 */
	string url_decode(const string& str);

	/**
	 * Make string suitable for using as x(ht)ml attribute.
	 * @param str string to escape
	 * @return escaped string
	 */
	string attr_escape(const string& str);

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

	string normalize_identifier(const string& usi,bool strip_fragment);

	/**
	 * Match URI against realm
	 * @param uri URI to match
	 * @param realm realm to match against
	 * @return true if URI matches realm
	 */
	bool uri_matches_realm(const string& uri,const string& realm);

	/**
	 * Strip fragment part from URI
	 * @param uri input/output parameter containing the URI
	 * @return reference to uri
	 */
	string& strip_uri_fragment_part(string& uri);

	/**
	 * Calculate signature and encode it using base64
	 * @param assoc association being used for signing
	 * @param om openid message
	 * @return base64 representation of the signature
	 */
	string base64_signature(const assoc_t& assoc,const basic_openid_message& om);

    }

}

#endif /* __OPKELE_UTIL_H */
