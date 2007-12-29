#include <list>
#include <opkele/curl.h>
#include <opkele/expat.h>
#include <opkele/uris.h>
#include <opkele/discovery.h>
#include <opkele/exception.h>
#include <opkele/util.h>

#include "config.h"

#define XRDS_HEADER "X-XRDS-Location"
#define CT_HEADER "Content-Type"

namespace opkele {
    using std::list;
    using xrd::XRD_t;
    using xrd::service_t;

    static const char *whitespace = " \t\r\n";
    static const char *i_leaders = "=@+$!(";

    static inline bool is_qelement(const XML_Char *n,const char *qen) {
	return !strcasecmp(n,qen);
    }
    static inline bool is_element(const XML_Char *n,const char *en) {
	if(!strcasecmp(n,en)) return true;
	int nl = strlen(n), enl = strlen(en);
	if( (nl>=(enl+1)) && n[nl-enl-1]=='\t'
		&& !strcasecmp(&n[nl-enl],en) )
	    return true;
	return false;
    }

    static long element_priority(const XML_Char **a) {
	for(;*a;++a)
	    if(!strcasecmp(*(a++),"priority")) {
		long rv;
		return (sscanf(*a,"%ld",&rv)==1)?rv:-1;
	    }
	return -1;
    }

    class idigger_t : public util::curl_t, public util::expat_t {
	public:
	    string xri_proxy;

	    enum {
		xmode_html = 1, xmode_xrd = 2
	    };
	    int xmode;

	    string xrds_location;
	    string http_content_type;
	    service_t html_openid1;
	    service_t html_openid2;
	    string cdata_buf;
	    long status_code;
	    string status_string;

	    typedef list<string> pt_stack_t;
	    pt_stack_t pt_stack;
	    int skipping;

	    XRD_t *xrd;
	    service_t *xrd_service;
	    string* cdata;

	    idigger_t()
		: util::curl_t(easy_init()),
		util::expat_t(0),
		xri_proxy(XRI_PROXY_URL) {
		    CURLcode r;
		    (r=misc_sets())
			|| (r=set_write())
			|| (r=set_header())
			;
		    if(r)
			throw exception_curl(OPKELE_CP_ "failed to set curly options",r);
		}
	    ~idigger_t() throw() { }

	    void discover(idiscovery_t& result,const string& identity) {
		result.clear();
		string::size_type fsc = identity.find_first_not_of(whitespace);
		if(fsc==string::npos)
		    throw bad_input(OPKELE_CP_ "whtiespace-only identity");
		string::size_type lsc = identity.find_last_not_of(whitespace);
		assert(lsc!=string::npos);
		if(!strncasecmp(identity.c_str()+fsc,"xri://",sizeof("xri://")-1))
		    fsc += sizeof("xri://")-1;
		if((fsc+1)>=lsc)
		    throw bad_input(OPKELE_CP_ "not a character of importance in identity");
		string id(identity,fsc,lsc-fsc+1);
		if(strchr(i_leaders,id[0])) {
		    result.normalized_id = id;
		    result.xri_identity = true;
		    /* TODO: further canonicalize xri identity? Like folding case  or whatever... */
		    discover_at(
			    result,
			    xri_proxy + util::url_encode(id)+
			    "?_xrd_r=application/xrd+xml;sep=false", xmode_xrd);
		    if(status_code!=100)
			throw failed_xri_resolution(OPKELE_CP_
				"XRI resolution failed with '"+status_string+"' message",status_code);
		    if(result.xrd.canonical_ids.empty())
			throw opkele::failed_discovery(OPKELE_CP_ "No CanonicalID for XRI identity found");
		}else{
		    result.xri_identity = false;
		    if(id.find("://")==string::npos)
			id.insert(0,"http://");
		    string::size_type fp = id.find('#');
		    if(fp!=string::npos) {
			string::size_type qp = id.find('?');
			if(qp==string::npos || qp<fp)
			    id.erase(fp);
			else if(qp>fp)
			    id.erase(fp,qp-fp);
		    }
		    result.normalized_id = util::rfc_3986_normalize_uri(id);
		    discover_at(result,id,xmode_html|xmode_xrd);
		    const char * eu = 0;
		    CURLcode r = easy_getinfo(CURLINFO_EFFECTIVE_URL,&eu);
		    if(r)
			throw exception_curl(OPKELE_CP_ "failed to get CURLINFO_EFFECTIVE_URL",r);
		    result.canonicalized_id = util::rfc_3986_normalize_uri(eu); /* XXX: strip fragment part? */
		    if(xrds_location.empty()) {
			html2xrd(result.xrd);
		    }else{
			discover_at(result,xrds_location,xmode_xrd);
			if(result.xrd.empty())
			    html2xrd(result.xrd);
		    }
		}
	    }

	    void discover_at(idiscovery_t& result,const string& url,int xm) {
		CURLcode r = easy_setopt(CURLOPT_URL,url.c_str());
		if(r)
		    throw exception_curl(OPKELE_CP_ "failed to set culry urlie",r);

		(*(expat_t*)this) = parser_create_ns();
		set_user_data(); set_element_handler();
		set_character_data_handler();

		http_content_type.clear();
		xmode = xm;
		if(xmode&xmode_html) {
		    xrds_location.clear();
		    html_openid1.clear(); html_openid2.clear();
		}
		xrd = &result.xrd;
		cdata = 0; xrd_service = 0; skipping = 0;
		status_code = 100; status_string.clear();

		r = easy_perform();
		if(r && r!=CURLE_WRITE_ERROR)
		    throw exception_curl(OPKELE_CP_ "failed to perform curly request",r);

		parse(0,0,true);
	    }

	    void html2xrd(XRD_t& x) {
		if(!html_openid1.uris.empty()) {
		    html_openid1.types.insert(STURI_OPENID11);
		    x.services.add(-1,html_openid1);
		}
		if(!html_openid2.uris.empty()) {
		    html_openid2.types.insert(STURI_OPENID20);
		    x.services.add(-1,html_openid2);
		}
	    }

	    size_t write(void *p,size_t s,size_t nm) {
		if(skipping<0) return 0;
		/* TODO: limit total size */
		size_t bytes = s*nm;
		parse((const char *)p,bytes,false);
		return bytes;
	    }
	    size_t header(void *p,size_t s,size_t nm) {
		size_t bytes = s*nm;
		const char *h = (const char*)p;
		const char *colon = (const char*)memchr(p,':',bytes);
		const char *space = (const char*)memchr(p,' ',bytes);
		if(space && ( (!colon) || space<colon ) ) {
		    xrds_location.clear(); http_content_type.clear();
		}else if(colon) {
		    const char *hv = ++colon;
		    int hnl = colon-h;
		    int rb;
		    for(rb = bytes-hnl-1;rb>0 && isspace(*hv);++hv,--rb);
		    while(rb>0 && isspace(hv[rb-1])) --rb;
		    if(rb) {
			if( (hnl>=sizeof(XRDS_HEADER))
				&& !strncasecmp(h,XRDS_HEADER":",
				    sizeof(XRDS_HEADER)) ) {
			    xrds_location.assign(hv,rb);
			}else if( (hnl>=sizeof(CT_HEADER))
				&& !strncasecmp(h,CT_HEADER":",
				    sizeof(CT_HEADER)) ) {
			    const char *sc = (const char*)memchr(
				    hv,';',rb);
			    http_content_type.assign(hv,sc?(sc-hv):rb);
			}
		    }
		}
		return curl_t::header(p,s,nm);
	    }

	    void start_element(const XML_Char *n,const XML_Char **a) {
		if(skipping<0) return;
		if(skipping) {
		    if(xmode&xmode_html)
			html_start_element(n,a);
		    ++skipping; return;
		}
		if(pt_stack.empty()) {
		    if(is_qelement(n,NSURI_XRDS "\tXRDS"))
			return;
		    if(is_qelement(n,NSURI_XRD "\tXRD")) {
			assert(xrd);
			xrd->clear();
			pt_stack.push_back(n);
		    }else if(xmode&xmode_html) {
			html_start_element(n,a);
		    }else{
			skipping = -1;
		    }
		}else{
		    int pt_s = pt_stack.size();
		    if(pt_s==1) {
			if(is_qelement(n,NSURI_XRD "\tCanonicalID")) {
			    assert(xrd);
			    cdata = &(xrd->canonical_ids.add(element_priority(a),string()));
			}else if(is_qelement(n,NSURI_XRD "\tLocalID")) {
			    assert(xrd);
			    cdata = &(xrd->local_ids.add(element_priority(a),string()));
			}else if(is_qelement(n,NSURI_XRD "\tService")) {
			    assert(xrd);
			    xrd_service = &(xrd->services.add(element_priority(a),
					service_t()));
			    pt_stack.push_back(n);
			}else if(is_qelement(n,NSURI_XRD "\tStatus")) {
			    for(;*a;) {
				if(!strcasecmp(*(a++),"code")) {
				    if(sscanf(*(a++),"%ld",&status_code)==1 && status_code!=100) {
					cdata = &status_string;
					pt_stack.push_back(n);
					break;
				    }
				}
			    }
			}else if(is_qelement(n,NSURI_XRD "\tExpires")) {
			    assert(xrd);
			    cdata_buf.clear();
			    cdata = &cdata_buf;
			}else if(xmode&xmode_html) {
			    html_start_element(n,a);
			}else{
			    skipping = 1;
			}
		    }else if(pt_s==2) {
			if(is_qelement(pt_stack.back().c_str(), NSURI_XRD "\tService")) {
			    if(is_qelement(n,NSURI_XRD "\tType")) {
				assert(xrd); assert(xrd_service);
				cdata_buf.clear();
				cdata = &cdata_buf;
			    }else if(is_qelement(n,NSURI_XRD "\tURI")) {
				assert(xrd); assert(xrd_service);
				cdata = &(xrd_service->uris.add(element_priority(a),string()));
			    }else if(is_qelement(n,NSURI_XRD "\tLocalID")
				    || is_qelement(n,NSURI_OPENID10 "\tDelegate") ) {
				assert(xrd); assert(xrd_service);
				cdata = &(xrd_service->local_ids.add(element_priority(a),string()));
			    }else{
				skipping = 1;
			    }
			}else
			    skipping = 1;
		    }else if(xmode&xmode_html) {
			html_start_element(n,a);
		    }else{
			skipping = 1;
		    }
		}
	    }
	    void end_element(const XML_Char *n) {
		if(skipping<0) return;
		if(skipping) {
		    --skipping; return;
		}
		if(is_qelement(n,NSURI_XRD "\tType")) {
		    assert(xrd); assert(xrd_service); assert(cdata==&cdata_buf);
		    xrd_service->types.insert(cdata_buf);
		}else if(is_qelement(n,NSURI_XRD "\tService")) {
		    assert(xrd); assert(xrd_service);
		    assert(!pt_stack.empty());
		    assert(pt_stack.back()==(NSURI_XRD "\tService"));
		    pt_stack.pop_back();
		    xrd_service = 0;
		}else if(is_qelement(n,NSURI_XRD "\tStatus")) {
		    assert(xrd);
		    if(is_qelement(pt_stack.back().c_str(),n)) {
			assert(cdata==&status_string);
			pt_stack.pop_back();
			if(status_code!=100)
			    skipping = -1;
		    }
		}else if(is_qelement(n,NSURI_XRD "\tExpires")) {
		    assert(xrd);
		    xrd->expires = util::w3c_to_time(cdata_buf);
		}else if((xmode&xmode_html) && is_element(n,"head")) {
		    skipping = -1;
		}
		cdata = 0;
	    }
	    void character_data(const XML_Char *s,int l) {
		if(skipping) return;
		if(cdata) cdata->append(s,l);
	    }

	    void html_start_element(const XML_Char *n,const XML_Char **a) {
		if(is_element(n,"meta")) {
		    bool heq = false;
		    string l;
		    for(;*a;a+=2) {
			if(!( strcasecmp(a[0],"http-equiv")
				|| strcasecmp(a[1],XRDS_HEADER) ))
			    heq = true;
			else if(!strcasecmp(a[0],"content"))
			    l.assign(a[1]);
		    }
		    if(heq)
			xrds_location = l;
		}else if(is_element(n,"link")) {
		    string rels;
		    string href;
		    for(;*a;a+=2) {
			if( !strcasecmp(a[0],"rel") ) {
			    rels.assign(a[1]);
			}else if( !strcasecmp(a[0],"href") ) {
			    const char *ns = a[1];
			    for(;*ns && isspace(*ns);++ns);
			    href.assign(ns);
			    string::size_type lns=href.find_last_not_of(whitespace);
			    href.erase(lns+1);
			}
		    }
		    for(string::size_type ns=rels.find_first_not_of(whitespace);
			    ns!=string::npos; ns=rels.find_first_not_of(whitespace,ns)) {
			string::size_type s = rels.find_first_of(whitespace,ns);
			string rel;
			if(s==string::npos) {
			    rel.assign(rels,ns,string::npos);
			    ns = string::npos;
			}else{
			    rel.assign(rels,ns,s-ns);
			    ns = s;
			}
			if(rel=="openid.server")
			    html_openid1.uris.add(-1,href);
			else if(rel=="openid.delegate")
			    html_openid1.local_ids.add(-1,href);
			else if(rel=="openid2.provider")
			    html_openid2.uris.add(-1,href);
			else if(rel=="openid2.local_id")
			    html_openid2.local_ids.add(-1,href);
		    }
		}else if(is_element(n,"body")) {
		    skipping = -1;
		}
	    }

    };

    void idiscover(idiscovery_t& result,const string& identity) {
	idigger_t idigger;
	idigger.discover(result,identity);
    }

}
