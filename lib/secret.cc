#include <algorithm>
#include <functional>
#include <opkele/types.h>
#include <opkele/exception.h>
#include <opkele/util.h>

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
	rv = util::encode_base64(&(tmp.front()),tmp.size());
    }

    void secret_t::enxor_from_base64(const unsigned char *key_sha1,const string& b64) {
	clear();
	util::decode_base64(b64,*this);
	transform(
		begin(), end(),
		key_sha1,
		begin(),
		bitwise_xor<unsigned char,unsigned char,unsigned char>() );
    }

    void secret_t::to_base64(string& rv) const {
	if(size()!=20)
	    throw bad_input(OPKELE_CP_ "wrong secret size");
	rv = util::encode_base64(&(front()),size());
    }

    void secret_t::from_base64(const string& b64) {
	util::decode_base64(b64,*this);
    }

}
