#include <algorithm>
#include <functional>
#include <opkele/types.h>
#include <opkele/exception.h>
#include <mimetic/mimetic.h>

namespace opkele {
    using namespace std;

    template<class __a1,class __a2,class __r>
	struct bitwise_xor : public binary_function<__a1,__a2,__r> {
	    __r operator() (const __a1& a1,const __a2& a2) const {
		return a1^a2;
	    }
	};

    void secret_t::enxor_to_base64(const unsigned char *key_sha1,string& rv) const {
	if(size()!=20)
	    throw bad_input(OPKELE_CP_ "wrong secret size");
	vector<unsigned char> tmp;
	transform(
		begin(), end(),
		key_sha1,
		back_insert_iterator<vector<unsigned char> >(tmp),
		bitwise_xor<unsigned char,unsigned char,unsigned char>() );
	mimetic::Base64::Encoder b(0);
	mimetic::encode(
		tmp.begin(),tmp.end(), b,
		back_insert_iterator<string>(rv) );
    }

    void secret_t::enxor_from_base64(const unsigned char *key_sha1,const string& b64) {
	mimetic::Base64::Decoder b;
	clear();
	mimetic::decode(
		b64.begin(),b64.end(), b,
		back_insert_iterator<secret_t>(*this) );
	transform(
		begin(), end(),
		key_sha1,
		begin(),
		bitwise_xor<unsigned char,unsigned char,unsigned char>() );
    }

    void secret_t::to_base64(string& rv) const {
	if(size()!=20)
	    throw bad_input(OPKELE_CP_ "wrong secret size");
	mimetic::Base64::Encoder b(0);
	mimetic::encode(
		begin(),end(), b,
		back_insert_iterator<string>(rv) );
    }

    void secret_t::from_base64(const string& b64) {
	mimetic::Base64::Decoder b;
	mimetic::decode(
		b64.begin(),b64.end(), b,
		back_insert_iterator<secret_t>(*this) );
    }

}
