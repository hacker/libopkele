#include <cctype>
#include <opkele/exception.h>
#include <opkele/util.h>
#include <opkele/openid_service_resolver.h>
#include <opkele/uris.h>

#define LOCATION_HEADER "X-XRDS-Location"

namespace opkele {
    static const char *whitespace = " \t\r\n";

    openid_service_resolver_t::openid_service_resolver_t(const string& xp)
	: util::curl_t(easy_init()),
	util::expat_t(0),
	xri_proxy(xp.empty()?"http://beta.xri.net/":xp)
    {
	CURLcode r;
	(r=misc_sets())
	|| (r=set_write())
	|| (r==set_header())
	;
	if(r)
	    throw opkele::exception_curl(OPKELE_CP_ "failed to set curly options",r);
    }

    static bool is_element(const XML_Char *n,const char *en) {
	if(!strcasecmp(n,en)) return true;
	int nl = strlen(n), enl = strlen(en);
	if( (nl>=(enl+1)) && n[nl-enl-1]=='\t'
		&& !strcasecmp(&n[nl-enl],en) )
	    return true;
	return false;
    }
    static inline bool is_qelement(const XML_Char *n,const char *qen) {
	return !strcasecmp(n,qen);
    }
    static inline bool is_element(
	    const openid_service_resolver_t::parser_node_t& n,
	    const char *en) {
	return is_element(n.element.c_str(),en);
    }
    static inline bool is_qelement(
	    const openid_service_resolver_t::parser_node_t& n,
	    const char *qen) {
	return is_qelement(n.element.c_str(),qen);
    }

    void openid_service_resolver_t::start_element(const XML_Char *n,const XML_Char **a) {
	if(state!=state_parse) return;
	tree.push(n,a);
	parser_node_t& t = tree.top();
	if(is_element(n,"html") || is_element(n,"head")
		|| is_qelement(n,NSURI_XRDS "\tXRDS")
		|| is_qelement(n,NSURI_XRD "\tXRD") )
	    t.skip_tags = false;
	else if(is_qelement(n,NSURI_XRD "\tService")
		|| is_qelement(n,NSURI_XRD "\tType")
		|| is_qelement(n,NSURI_XRD "\tURI")
		|| is_qelement(n,NSURI_OPENID10 "\tDelegate")
		|| is_qelement(n,NSURI_XRD "\tCanonicalID") )
	    t.skip_tags = t.skip_text = false;
	else if(is_element(n,"body"))
	    state = state_stopping_body;
    }
    void openid_service_resolver_t::end_element(const XML_Char *n) {
	if(state!=state_parse) return;
	assert(tree.top().element == n);
	pop_tag();
    }
    void openid_service_resolver_t::character_data(const XML_Char *s,int l) {
	if(state!=state_parse) return;
	if( !( tree.empty() || tree.top().skip_text ) )
	    tree.top().content.append(s,l);
    }

    static void copy_trim_whitespace(string& to,const string& from) {
	string::size_type ns0 = from.find_first_not_of(whitespace);
	if(ns0==string::npos) {
	    to.clear(); return;
	}
	string::size_type ns1 = from.find_last_not_of(whitespace);
	assert(ns1!=string::npos);
	to.assign(from,ns0,ns1-ns0+1);
    }

    void openid_service_resolver_t::pop_tag() {
	assert(!tree.empty());
	parser_node_t& t = tree.top();
	if( is_element(t,"meta")
		&& !strcasecmp(t.attrs["http-equiv"].c_str(),LOCATION_HEADER) ) {
	    xrds_location = t.attrs["content"];
	}else if( is_element(t,"link") ) {
	    parser_node_t::attrs_t::const_iterator ir = t.attrs.find("rel");
	    if(ir!=t.attrs.end()) {
		const string& rels = ir->second;
		for(string::size_type ns = rels.find_first_not_of(whitespace);
			ns!=string::npos;
			ns=rels.find_first_not_of(whitespace,ns)) {
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
			copy_trim_whitespace(html_SEP.xrd_URI,t.attrs["href"]);
		    else if(rel=="openid.delegate")
			copy_trim_whitespace(html_SEP.openid_Delegate,t.attrs["href"]);
		}
	    }
	}else if( is_element(t,"head") )
	    state = state_stopping_head;
	else if( is_qelement(t,NSURI_XRD "\tXRD")) {
	    if( !(
			(
			 xri_mode
			 && t.auth_info.canonical_id.empty()
			) ||
			t.auth_info.auth_SEP.xrd_Type.empty()
		 ) )
		auth_info = t.auth_info;
	}else if( tree.size()>1 ) {
	    parser_node_t& p = tree.parent();
	    if( is_qelement(p,NSURI_XRD "\tService") ) {
		if( is_qelement(t,NSURI_XRD "\tType") ) {
		    if(t.content==STURI_OPENID10) {
			string tmp; copy_trim_whitespace(tmp,t.content);
			p.auth_info.auth_SEP.xrd_Type.insert(tmp);
		    }
		}else if( is_qelement(t,NSURI_XRD "\tURI") )
		    copy_trim_whitespace(p.auth_info.auth_SEP.xrd_URI,t.content);
		else if( is_qelement(t,NSURI_OPENID10 "\tDelegate") )
		    copy_trim_whitespace(p.auth_info.auth_SEP.openid_Delegate,t.content);
	    }else if( is_qelement(p,NSURI_XRD "\tXRD") ) {
		if(is_qelement(t,NSURI_XRD "\tService") ) {
		    if( !t.auth_info.auth_SEP.xrd_Type.empty() ) {
			parser_node_t::attrs_t::const_iterator ip
			    = t.attrs.find("priority");
			if(ip!=t.attrs.end()) {
			    const char *nptr = ip->second.c_str();
			    char *eptr = 0;
			    t.auth_info.auth_SEP.priority = strtol(nptr,&eptr,10);
			    if(nptr==eptr)
				t.auth_info.auth_SEP.priority = LONG_MAX;
			}
			if( (t.auth_info.auth_SEP.priority < p.auth_info.auth_SEP.priority)
				|| p.auth_info.auth_SEP.xrd_Type.empty() )
			    p.auth_info.auth_SEP = t.auth_info.auth_SEP;
		    }
		}else if( is_qelement(t,NSURI_XRD "\tCanonicalID") )
		    copy_trim_whitespace(p.auth_info.canonical_id,t.content);
	    }
	}
	
	tree.pop();
    }

    size_t openid_service_resolver_t::write(void *p,size_t s,size_t nm) {
	if(state != state_parse)
	    return 0;
	/* TODO: limit total size */
	size_t bytes = s*nm;
	parse((const char *)p,bytes,false);
	return bytes;
    }

    size_t openid_service_resolver_t::header(void *p,size_t s,size_t nm) {
	size_t bytes = s*nm;
	const char *h = (const char *)p;
	const char *colon = (const char*)memchr(p,':',bytes);
	const char *space = (const char*)memchr(p,' ',bytes);
	if(space && ( (!colon) || space<colon ) ) {
	    xrds_location.clear(); http_content_type.clear();
	}else if(colon) {
	    const char *hv = ++colon;
	    int hnl = colon-h;
	    int rb;
	    for(rb = bytes-hnl-1;
		    rb>0 && isspace(*hv);
		    ++hv,--rb );
	    while(rb>0 && isspace(hv[rb-1]))
		--rb;
	    if(rb) {
		if( (hnl >= sizeof(LOCATION_HEADER))
			&& !strncasecmp(h,LOCATION_HEADER ":",
			    sizeof(LOCATION_HEADER)) ) {
		    xrds_location.assign(hv,rb);
		}else if( (hnl >= sizeof("Content-Type"))
			&& !strncasecmp(h,"Content-Type:",
			    sizeof("Content-Type")) ) {
		    const char *sc = (const char*)memchr(
			    hv,';',rb);
		    http_content_type.assign(
			    hv,sc?(sc-hv):rb );
		}
	    }
	}
	return curl_t::header(p,s,nm);
    }

    void openid_service_resolver_t::discover_service(const string& url,bool xri) {
	CURLcode r = easy_setopt(CURLOPT_URL,url.c_str());
	if(r)
	    throw opkele::exception_curl(OPKELE_CP_ "failed to set curly urlie",r);

	(*(expat_t*)this) = parser_create_ns();
	set_user_data(); set_element_handler();
	set_character_data_handler();
	tree.clear();
	state = state_parse;

	r = easy_perform();
	if(r && r!=CURLE_WRITE_ERROR)
	    throw exception_curl(OPKELE_CP_ "failed to perform curly request",r);

	parse(0,0,true);
	while(!tree.empty()) pop_tag();
    }

    const openid_auth_info_t& openid_service_resolver_t::resolve(const string& id) {
	auth_info = openid_auth_info_t();
	html_SEP = openid_auth_SEP_t();

	string::size_type fns = id.find_first_not_of(whitespace);
	if(fns==string::npos)
	    throw opkele::bad_input(OPKELE_CP_ "whitespace-only identity");
	string::size_type lns = id.find_last_not_of(whitespace);
	assert(lns!=string::npos);
	if(!strncasecmp(
		    id.c_str()+fns,"xri://",
		    sizeof("xri://")-1))
	    fns+=sizeof("xri://")-1;
	string nid(id,fns,lns-fns+1);
	if(nid.empty())
	    throw opkele::bad_input(OPKELE_CP_ "nothing significant in identity");
	if(strchr("=@+$!(",*nid.c_str())) {
	    discover_service(
		    xri_proxy + util::url_encode(nid) +
		    "?_xrd_t=" STURI_OPENID10 "&_xrd_r=application/xrd+xml;sep=true",
		    true );
	    if(auth_info.canonical_id.empty()
		    || auth_info.auth_SEP.xrd_Type.empty() )
		throw opkele::failed_lookup(OPKELE_CP_ "no OpenID service for XRI found");
	    return auth_info;
	}else{
	    const char *np = nid.c_str();
	    if( (strncasecmp(np,"http",4) || strncmp(
			    tolower(*(np+4))=='s'? np+5 : np+4, "://", 3))
#ifndef NDEBUG
		    && strncasecmp(np,"file:///",sizeof("file:///")-1)
#endif		/* XXX: or how do I let tests work? */
		    )
		nid.insert(0,"http://");
	    string::size_type fp = nid.find('#');
	    if(fp!=string::npos) {
		string::size_type qp = nid.find('?');
		if(qp==string::npos || qp<fp) {
		    nid.erase(fp);
		}else if(qp>fp)
		    nid.erase(fp,qp-fp);
	    }
	    discover_service(nid);
	    const char *eu = 0;
	    CURLcode r = easy_getinfo(CURLINFO_EFFECTIVE_URL,&eu);
	    if(r)
		throw exception_curl(OPKELE_CP_ "failed to get CURLINFO_EFFECTIVE_URL",r);
	    string canonicalized_id = util::rfc_3986_normalize_uri(eu);
	    if(xrds_location.empty()) {
		if(auth_info.auth_SEP.xrd_Type.empty()) {
		    if(html_SEP.xrd_URI.empty())
			throw opkele::failed_lookup(OPKELE_CP_ "no OpenID service discovered");
		    auth_info.auth_SEP = html_SEP;
		    auth_info.auth_SEP.xrd_Type.clear(); auth_info.auth_SEP.xrd_Type.insert( STURI_OPENID10 );
		    auth_info.canonical_id = canonicalized_id;
		}else{
		    if(auth_info.canonical_id.empty())
			auth_info.canonical_id = canonicalized_id;
		}
		return auth_info;
	    }else{
		discover_service(xrds_location);
		if(auth_info.auth_SEP.xrd_Type.empty())
		    throw opkele::failed_lookup(OPKELE_CP_ "no OpenID service found in Yadis document");
		if(auth_info.canonical_id.empty())
		    auth_info.canonical_id = canonicalized_id;
		return auth_info;
	    }
	}
    }

}
