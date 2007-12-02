#ifndef __OPKELE_OPENID_SERVICE_RESOLVER_H
#define __OPKELE_OPENID_SERVICE_RESOLVER_H

#include <climits>
#include <string>
#include <list>
#include <set>
#include <map>
#include <opkele/curl.h>
#include <opkele/expat.h>

namespace opkele {
    using std::list;
    using std::string;
    using std::set;
    using std::map;

    struct openid_auth_SEP_t {
	    long priority;
	    set<string> xrd_Type;
	    string xrd_URI;
	    string openid_Delegate;

	    openid_auth_SEP_t() : priority(LONG_MAX) { }
    };

    struct openid_auth_info_t {
	string canonical_id;
	openid_auth_SEP_t auth_SEP;
    };


    class openid_service_resolver_t : public util::curl_t, public util::expat_t {
	public:
	    string xri_proxy;

	    openid_service_resolver_t(const string& xp="");
	    ~openid_service_resolver_t() throw() { }

	    const openid_auth_info_t& resolve(const string& id);

	    enum state_t {
		state_parse = 0,
		state_stopping_head, state_stopping_body,
		state_stopping_size
	    };
	    state_t state;

	    struct parser_node_t {
		string element;
		string content;
		typedef map<string,string> attrs_t;
		attrs_t attrs;
		bool skip_text, skip_tags;
		openid_auth_info_t auth_info;

		parser_node_t(const XML_Char *n,const XML_Char **a)
		    : skip_text(true), skip_tags(true)
		{
		    element = n;
		    for(;*a;a+=2)
			attrs[a[0]] = a[1];
		}

	    };

	    class parser_tree_t : public list<parser_node_t> {
		public:
		    const_reference top() const { return back(); }
		    reference top()  { return back(); }

		    const_reference parent() const {
			const_reverse_iterator rv = rbegin();
			return *(++rv); }
		    reference parent() {
			reverse_iterator rv = rbegin();
			return *(++rv); }

		    inline void pop() { pop_back(); }
		    inline void push(const_reference e) { push_back(e); }

		    void push(const XML_Char *n,const XML_Char **a) {
			parser_node_t nn(n,a);
			if(empty())
			    nn.skip_text = nn.skip_tags = true;
			else{
			    const_reference t = top();
			    nn.skip_text = t.skip_text; nn.skip_tags = t.skip_tags;
			}
			push(nn);
		    }
	    };
	    parser_tree_t tree;

	    void start_element(const XML_Char *n,const XML_Char **a);
	    void end_element(const XML_Char *n);
	    void character_data(const XML_Char *s,int l);

	    string xrds_location;
	    openid_auth_SEP_t html_SEP;
	    openid_auth_info_t auth_info;

	    void pop_tag();

	    size_t write(void *p,size_t s,size_t nm);

	    string http_content_type;

	    size_t header(void *p,size_t s,size_t nm);
	    
	    bool xri_mode;

	    void discover_service(const string& url,bool xri=false);
    };

}

#endif /* __OPKELE_OPENID_SERVICE_RESOLVER_H */
