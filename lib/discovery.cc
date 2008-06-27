#include <list>
#include <opkele/curl.h>
#include <opkele/expat.h>
#include <opkele/uris.h>
#include <opkele/discovery.h>
#include <opkele/exception.h>
#include <opkele/util.h>
#include <opkele/data.h>
#include <opkele/debug.h>

#include "config.h"

#include <opkele/tidy.h>

#define XRDS_HEADER "X-XRDS-Location"
#define CT_HEADER "Content-Type"

namespace opkele {
    using std::list;
    using xrd::XRD_t;
    using xrd::service_t;

    /* TODO: the whole discovery thing needs cleanup and optimization due to
     * many changes of concept. */

    static const size_t max_html = 16384;

    static const struct service_type_t {
	const char *uri;
	const char *forceid;
    } op_service_types[] = {
	{ STURI_OPENID20_OP, IDURI_SELECT20 },
	{ STURI_OPENID20, 0 },
	{ STURI_OPENID11, 0 },
	{ STURI_OPENID10, 0 }
    };
    enum {
	st_index_1 = 2, st_index_2 = 1
    };


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
    /* TODO: ideally all attributes should be
     * retrieved in one run */
    static const char *element_attr(const XML_Char **a, const char *at) {
	for(;*a;++a)
	    if(!strcasecmp(*(a++),at)) {
		return *a;
	    }
	return 0;
    }

    class idigger_t : public util::curl_t, public util::expat_t {
	public:
	    string xri_proxy;

	    enum {
		xmode_html = 1, xmode_xrd = 2, xmode_cid = 4,
		xmode_noredirs = 8
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
	    bool parser_choked;
	    string save_html;

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

	    void yadiscover(endpoint_discovery_iterator oi,const string& yurl,const char **types,bool redirs) {
		idiscovery_t idis;
		idis.xri_identity = false;
		discover_at(idis,yurl,xmode_html|xmode_xrd|(redirs?0:xmode_noredirs));
		if(!xrds_location.empty()) {
		    idis.clear();
		    discover_at(idis,xrds_location,xmode_xrd);
		}
		idis.normalized_id = idis.canonicalized_id = yurl;
		service_type_t st;
		for(st.uri=*types;*types;st.uri=*(++types))
		    queue_endpoints(oi,idis,&st);
	    }

	    string discover(endpoint_discovery_iterator& oi,const string& identity) {
		string rv;
		idiscovery_t idis;
		string::size_type fsc = identity.find_first_not_of(data::_whitespace_chars);
		if(fsc==string::npos)
		    throw bad_input(OPKELE_CP_ "whitespace-only identity");
		string::size_type lsc = identity.find_last_not_of(data::_whitespace_chars);
		assert(lsc!=string::npos);
		if(!strncasecmp(identity.c_str()+fsc,"xri://",sizeof("xri://")-1))
		    fsc += sizeof("xri://")-1;
		if((fsc+1)>=lsc)
		    throw bad_input(OPKELE_CP_ "not a character of importance in identity");
		string id(identity,fsc,lsc-fsc+1);
		idis.clear();
		if(strchr(data::_iname_leaders,id[0])) {
		    /* TODO: further normalize xri identity? Like folding case
		     * or whatever... */
		    rv = id;
		    set<string> cids;
		    for(const struct service_type_t *st=op_service_types;
			    st<&op_service_types[sizeof(op_service_types)/sizeof(*op_service_types)];++st) {
			idis.clear();
			discover_at( idis,
				xri_proxy + util::url_encode(id)+
				"?_xrd_t="+util::url_encode(st->uri)+
				"&_xrd_r=application/xrd%2Bxml"
				";sep=true;refs=true",
				xmode_xrd );
			if(status_code==241) continue;
			if(status_code!=100)
			    throw failed_xri_resolution(OPKELE_CP_
				    "XRI resolution failed with '"+status_string+"' message"
				    ", while looking for SEP with type '"+st->uri+"'", status_code);
			if(idis.xrd.canonical_ids.empty())
			    throw opkele::failed_discovery(OPKELE_CP_ "No CanonicalID for XRI identity found");
			string cid = idis.xrd.canonical_ids.begin()->second;
			if(cids.find(cid)==cids.end()) {
			    cids.insert(cid);
			    idis.clear();
			    discover_at( idis,
				    xri_proxy + util::url_encode(id)+
				    "?_xrd_t="+util::url_encode(st->uri)+
				    "&_xrd_r=application/xrd%2Bxml"
				    ";sep=true;refs=true",
				    xmode_xrd );
			    if(status_code==241) continue;
			    if(status_code!=100)
				throw failed_xri_resolution(OPKELE_CP_
					"XRI resolution failed with '"+status_string+"' message"
					", while looking for SEP with type '"+st->uri+"'"
					" on canonical id", status_code);
			}
			idis.canonicalized_id = cid;
			idis.normalized_id = rv; idis.xri_identity = true;
			queue_endpoints(oi,idis,st);
		    }
		}else{
		    idis.xri_identity = false;
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
		    rv = idis.normalized_id = util::rfc_3986_normalize_uri(id);
		    discover_at(idis,id,xmode_html|xmode_xrd);
		    const char * eu = 0;
		    CURLcode r = easy_getinfo(CURLINFO_EFFECTIVE_URL,&eu);
		    if(r)
			throw exception_curl(OPKELE_CP_ "failed to get CURLINFO_EFFECTIVE_URL",r);
		    string cid = util::strip_uri_fragment_part( idis.canonicalized_id = util::rfc_3986_normalize_uri(eu) );
		    if(xrds_location.empty()) {
			if(idis.xrd.empty())
			    html2xrd(oi,idis);
			else{
			    for(const service_type_t *st=op_service_types;
				    st<&op_service_types[sizeof(op_service_types)/sizeof(*op_service_types)];++st)
				queue_endpoints(oi,idis,st);
			}
		    }else{
			idis.clear();
			idis.canonicalized_id = cid;
			discover_at(idis,xrds_location,xmode_xrd);
			if(idis.xrd.empty())
			    html2xrd(oi,idis);
			else{
			    for(const service_type_t *st=op_service_types;
				    st<&op_service_types[sizeof(op_service_types)/sizeof(*op_service_types)];++st)
				queue_endpoints(oi,idis,st);
			}
		    }
		}
		return rv;
	    }

	    void discover_at(idiscovery_t& idis,const string& url,int xm) {
		CURLcode r = easy_setopt(CURLOPT_MAXREDIRS, (xm&xmode_noredirs)?0:5);
		if(r)
		    throw exception_curl(OPKELE_CP_ "failed to set curly maxredirs option");
		if( (r=easy_setopt(CURLOPT_URL,url.c_str())) )
		    throw exception_curl(OPKELE_CP_ "failed to set curly urlie",r);

		http_content_type.clear();
		xmode = xm;
		prepare_to_parse();
		if(xmode&xmode_html) {
		    xrds_location.clear();
		    save_html.clear();
		    save_html.reserve(max_html);
		}
		xrd = &idis.xrd;

		r = easy_perform();
		if(r && r!=CURLE_WRITE_ERROR)
		    throw exception_curl(OPKELE_CP_ "failed to perform curly request",r);

		if(!parser_choked) {
		    parse(0,0,true);
		}else if(xmode&xmode_html){
		    /* TODO: do not bother if we've seen xml */
		    try {
			util::tidy_doc_t td = util::tidy_doc_t::create();
			if(!td)
			    throw exception_tidy(OPKELE_CP_ "failed to create htmltidy document");
#ifndef NDEBUG
			td.opt_set(TidyQuiet,false);
			td.opt_set(TidyShowWarnings,false);
#endif /* NDEBUG */
			td.opt_set(TidyForceOutput,true);
			td.opt_set(TidyXhtmlOut,true);
			td.opt_set(TidyDoctypeMode,TidyDoctypeOmit);
			td.opt_set(TidyMark,false);
			td.opt_set(TidyNumEntities,true);
			if(td.parse_string(save_html)<=0)
			    throw exception_tidy(OPKELE_CP_ "tidy failed to parse document");
			if(td.clean_and_repair()<=0)
			    throw exception_tidy(OPKELE_CP_ "tidy failed to clean and repair");
			util::tidy_buf_t tide;
			if(td.save_buffer(tide)<=0)
			    throw exception_tidy(OPKELE_CP_ "tidy failed to save buffer");
			prepare_to_parse();
			parse(tide.c_str(),tide.size(),true);
		    }catch(exception_tidy& et) { }
		}
		save_html.clear();
	    }

	    void prepare_to_parse() {
		(*(expat_t*)this) = parser_create_ns();
		set_user_data(); set_element_handler();
		set_character_data_handler();

		if(xmode&xmode_html) {
		    html_openid1.clear(); html_openid2.clear();
		    parser_choked = false;
		}

		cdata = 0; xrd_service = 0; skipping = 0;
		pt_stack.clear();
		status_code = 100; status_string.clear();
	    }

	    void html2xrd(endpoint_discovery_iterator& oi,idiscovery_t& id) {
		XRD_t& x = id.xrd;
		if(!html_openid2.uris.empty()) {
		    html_openid2.types.insert(STURI_OPENID20);
		    x.services.add(-1,html_openid2);
		    queue_endpoints(oi,id,&op_service_types[st_index_2]);
		}
		if(!html_openid1.uris.empty()) {
		    html_openid1.types.insert(STURI_OPENID11);
		    x.services.add(-1,html_openid1);
		    queue_endpoints(oi,id,&op_service_types[st_index_1]);
		}
	    }

	    size_t write(void *p,size_t s,size_t nm) {
		/* TODO: limit total size */
		size_t bytes = s*nm;
		const char *inbuf = (const char*)p;
		if(xmode&xmode_html) {
		    size_t mbts = save_html.capacity()-save_html.size();
		    size_t bts = 0;
		    if(mbts>0) {
			bts = (bytes>mbts)?mbts:bytes;
			save_html.append(inbuf,bts);
		    }
		    if(skipping<0) return bts;
		}
		if(skipping<0) return 0;
		bool rp = parse(inbuf,bytes,false);
		if(!rp) {
		    parser_choked = true;
		    skipping = -1;
		    if(!(xmode&xmode_html))
			bytes = 0;
		}
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
		    size_t hnl = colon-h;
		    int rb;
		    for(rb = bytes-hnl-1;rb>0 && isspace(*hv);++hv,--rb) ;
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
			}else if(is_qelement(n,NSURI_XRD "\tProviderID")) {
			    assert(xrd);
			    cdata = &(xrd->provider_id);
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
				}else
				    ++a;
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
				const char *append = element_attr(a,"append");
				xrd::uri_t& uri = xrd_service->uris.add(element_priority(a),xrd::uri_t("",append?append:""));
				cdata = &uri.uri;
			    }else if(is_qelement(n,NSURI_XRD "\tLocalID")
				    || is_qelement(n,NSURI_OPENID10 "\tDelegate") ) {
				assert(xrd); assert(xrd_service);
				cdata = &(xrd_service->local_ids.add(element_priority(a),string()));
			    }else if(is_qelement(n,NSURI_XRD "\tProviderID")) {
				    assert(xrd); assert(xrd_service);
				    cdata = &(xrd_service->provider_id);
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
			    for(;*ns && isspace(*ns);++ns) ;
			    href.assign(ns);
			    string::size_type lns=href.find_last_not_of(data::_whitespace_chars);
			    href.erase(lns+1);
			}
		    }
		    for(string::size_type ns=rels.find_first_not_of(data::_whitespace_chars);
			    ns!=string::npos; ns=rels.find_first_not_of(data::_whitespace_chars,ns)) {
			string::size_type s = rels.find_first_of(data::_whitespace_chars,ns);
			string rel;
			if(s==string::npos) {
			    rel.assign(rels,ns,string::npos);
			    ns = string::npos;
			}else{
			    rel.assign(rels,ns,s-ns);
			    ns = s;
			}
			if(rel=="openid.server")
			    html_openid1.uris.add(-1,xrd::uri_t(href));
			else if(rel=="openid.delegate")
			    html_openid1.local_ids.add(-1,href);
			else if(rel=="openid2.provider")
			    html_openid2.uris.add(-1,xrd::uri_t(href));
			else if(rel=="openid2.local_id")
			    html_openid2.local_ids.add(-1,href);
		    }
		}else if(is_element(n,"body")) {
		    skipping = -1;
		}
	    }

	    void queue_endpoints(endpoint_discovery_iterator& oi,
		    const idiscovery_t &id,
		    const service_type_t *st) {
		openid_endpoint_t ep;
		ep.claimed_id = id.canonicalized_id;
		for(xrd::services_t::const_iterator isvc=id.xrd.services.begin();
			isvc!=id.xrd.services.end(); ++isvc) {
		    const xrd::service_t svc = isvc->second;
		    if(svc.types.find(st->uri)==svc.types.end()) continue;
		    for(xrd::uris_t::const_iterator iu=svc.uris.begin();iu!=svc.uris.end();++iu) {
			ep.uri = iu->second.uri;
			if(id.xri_identity) {
			    if(iu->second.append=="qxri") {
				ep.uri += id.normalized_id;
			    } /* TODO: else handle other append attribute values */
			}
			if(st->forceid) {
			    ep.local_id = ep.claimed_id = st->forceid;
			    *(oi++) = ep;
			}else{
			    if(svc.local_ids.empty()) {
				ep.local_id = ep.claimed_id;
				*(oi++) = ep;
			    }else{
				for(xrd::local_ids_t::const_iterator ilid=svc.local_ids.begin();
					ilid!=svc.local_ids.end(); ++ilid) {
				    ep.local_id = ilid->second;
				    *(oi++) = ep;
				}
			    }
			}
		    }
		}
	    }

    };

    string idiscover(endpoint_discovery_iterator oi,const string& identity) {
	idigger_t idigger;
	return idigger.discover(oi,identity);
    }

    void yadiscover(endpoint_discovery_iterator oi,const string& yurl,const char **types,bool redirs) try {
	idigger_t idigger;
	idigger.yadiscover(oi,yurl,types,redirs);
    }catch(exception_curl& ec) {
	if(redirs || ec._error!=CURLE_TOO_MANY_REDIRECTS)
	    throw;
    }

}
