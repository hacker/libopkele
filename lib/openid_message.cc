#include <cassert>
#include <opkele/types.h>
#include <opkele/exception.h>
#include <opkele/util.h>
#include <opkele/debug.h>

#include "config.h"

namespace opkele {
    using std::input_iterator_tag;
    using std::unary_function;

    struct __om_copier : public unary_function<const string&,void> {
	public:
	    const basic_openid_message& from;
	    basic_openid_message& to;

	    __om_copier(basic_openid_message& t,const basic_openid_message& f)
		: from(f), to(t) {
		    to.reset_fields();
		}

	    result_type operator()(argument_type f) {
		to.set_field(f,from.get_field(f)); }
    };

    basic_openid_message::basic_openid_message(const basic_openid_message& x) {
	x.copy_to(*this);
    }
    void basic_openid_message::copy_to(basic_openid_message& x) const {
	for_each(fields_begin(),fields_end(),
		__om_copier(x,*this) );
    }

    struct __om_ns_finder : public unary_function<const string&,bool> {
	public:
	    const basic_openid_message& om;
	    const string& uri;

	    __om_ns_finder(const basic_openid_message& m,
		    const string& u) : om(m), uri(u) { }

	    result_type operator()(argument_type f) {
		return
		    (!strncmp(f.c_str(),"ns.",sizeof("ns.")-1))
			&& om.get_field(f)==uri ;
	    }
    };

    bool basic_openid_message::has_ns(const string& uri) const {
	fields_iterator ei = fields_end();
	fields_iterator i = find_if(fields_begin(),fields_end(),
		__om_ns_finder(*this,uri));
	return !(i==ei);
    }
    string basic_openid_message::get_ns(const string& uri) const {
	fields_iterator ei = fields_end();
	fields_iterator i = find_if(fields_begin(),fields_end(),
		__om_ns_finder(*this,uri));
	if(i==ei)
	    throw failed_lookup(OPKELE_CP_ string("failed to find namespace ")+uri);
	return i->substr(3);
    }

    struct __om_query_builder : public unary_function<const string&,void> {
	public:
	    const basic_openid_message& om;
	    bool first;
	    string& rv;
	    const char *pfx;

	    __om_query_builder(const char *p,string& r,const basic_openid_message& m)
		: om(m), first(true), rv(r), pfx(p) {
		    for_each(om.fields_begin(),om.fields_end(),*this);
		}
	    __om_query_builder(const char *p,string& r,const basic_openid_message& m,const string& u)
		: om(m), first(true), rv(r), pfx(p) {
		    rv = u;
		    if(rv.find('?')==string::npos)
			rv += '?';
		    else
			first = false;
		    for_each(om.fields_begin(),om.fields_end(),*this);
		}

	    result_type operator()(argument_type f) {
		if(first)
		    first = false;
		else
		    rv += '&';
		if(pfx) rv += pfx;
		rv+= f;
		rv += '=';
		rv += util::url_encode(om.get_field(f));
	    }
    };

    string basic_openid_message::append_query(const string& url,const char *pfx) const {
	string rv;
	return __om_query_builder(pfx,rv,*this,url).rv;
    }
    string basic_openid_message::query_string(const char *pfx) const {
	string rv;
	return __om_query_builder(pfx,rv,*this).rv;
    }

    void basic_openid_message::reset_fields() {
	throw not_implemented(OPKELE_CP_ "reset_fields() not implemented");
    }
    void basic_openid_message::set_field(const string&,const string&) {
	throw not_implemented(OPKELE_CP_ "set_field() not implemented");
    }
    void basic_openid_message::reset_field(const string&) {
	throw not_implemented(OPKELE_CP_ "reset_field() not implemented");
    }

    void basic_openid_message::from_keyvalues(const string& kv) {
	reset_fields();
	string::size_type p = 0;
	while(true) {
	    string::size_type co = kv.find(':',p);
	    if(co==string::npos)
		break;
#ifndef POSTELS_LAW
	    string::size_type nl = kv.find('\n',co+1);
	    if(nl==string::npos)
		throw bad_input(OPKELE_CP_ "malformed input");
	    if(nl>co)
		insert(value_type(kv.substr(p,co-p),kv.substr(co+1,nl-co-1)));
	    p = nl+1;
#else /* POSTELS_LAW */
	    string::size_type lb = kv.find_first_of("\r\n",co+1);
	    if(lb==string::npos) {
		set_field(kv.substr(p,co-p),kv.substr(co+1));
		break;
	    }
	    if(lb>co)
		set_field(kv.substr(p,co-p),kv.substr(co+1,lb-co-1));
	    string::size_type nolb = kv.find_first_not_of("\r\n",lb);
	    if(nolb==string::npos)
		break;
	    p = nolb;
#endif /* POSTELS_LAW */
	}
    }

    struct __om_kv_outputter : public unary_function<const string&,void> {
	public:
	    const basic_openid_message& om;
	    ostream& os;

	    __om_kv_outputter(const basic_openid_message& m,ostream& s)
		: om(m), os(s) { }

	    result_type operator()(argument_type f) {
		os << f << ':' << om.get_field(f) << '\n';
	    }
    };

    void basic_openid_message::to_keyvalues(ostream& o) const {
	for_each(fields_begin(),fields_end(),__om_kv_outputter(*this,o));
    }

    struct __om_html_outputter : public unary_function<const string&,void> {
	public:
	    const basic_openid_message& om;
	    ostream& os;
	    const char *pfx;

	    __om_html_outputter(const basic_openid_message& m,ostream& s,const char *p=0)
		: om(m), os(s), pfx(p) { }

	    result_type operator()(argument_type f) {
		os <<
		    "<input type=\"hidden\""
		    " name=\"";
		if(pfx)
		    os << util::attr_escape(pfx);
		os << util::attr_escape(f) << "\""
		    " value=\"" << util::attr_escape(om.get_field(f)) << "\" />";
	    }
    };

    void basic_openid_message::to_htmlhiddens(ostream& o,const char* pfx) const {
	for_each(fields_begin(),fields_end(),__om_html_outputter(*this,o,pfx));
    }

    void basic_openid_message::add_to_signed(const string& fields) {
	string::size_type fnc = fields.find_first_not_of(",");
	if(fnc==string::npos)
	    throw bad_input(OPKELE_CP_ "Trying to add nothing in particular to the list of signed fields");
	string signeds;
	try {
	    signeds = get_field("signed");
	    string::size_type lnc = signeds.find_last_not_of(",");
	    if(lnc==string::npos)
		signeds.assign(fields,fnc,fields.size()-fnc);
	    else{
		string::size_type ss = signeds.size();
		if(lnc==(ss-1)) {
		    signeds+= ',';
		    signeds.append(fields,fnc,fields.size()-fnc);
		}else{
		    if(lnc<(ss-2))
			signeds.replace(lnc+2,ss-lnc-2,
				fields,fnc,fields.size()-fnc);
		    else
			signeds.append(fields,fnc,fields.size()-fnc);
		}
	    }
	}catch(failed_lookup&) {
	    signeds.assign(fields,fnc,fields.size()-fnc);
	}
	set_field("signed",signeds);
    }

    string basic_openid_message::find_ns(const string& uri,const char *pfx) const {
	try {
	    return get_ns(uri);
	}catch(failed_lookup&) {
	    return pfx;
	}
    }
    string basic_openid_message::allocate_ns(const string& uri,const char *pfx) {
	if(!has_field("ns"))
	    return pfx;
	if(has_ns(uri))
	    throw bad_input(OPKELE_CP_ "OpenID message already contains namespace");
	string rv = pfx;
	if(has_field("ns."+rv)) {
	    string::reference c=rv[rv.length()];
	    for(c='a';c<='z' && has_field("ns."+rv);++c);
	    if(c=='z')
		throw exception(OPKELE_CP_ "Failed to allocate namespace");
	}
	set_field("ns."+rv,uri);
	return rv;
    }

    void openid_message_t::copy_to(basic_openid_message& x) const {
	x.reset_fields();
	for(const_iterator i=begin();i!=end();++i)
	    x.set_field(i->first,i->second);
    }

    bool openid_message_t::has_field(const string& n) const {
	return find(n)!=end();
    }
    const string& openid_message_t::get_field(const string& n) const {
	const_iterator i=find(n);
	if(i==end())
	    throw failed_lookup(OPKELE_CP_ n+": no such field");
	return i->second;
    }

    openid_message_t::fields_iterator openid_message_t::fields_begin() const {
	return util::map_keys_iterator<const_iterator,string,const string&,const string*>(begin(),end());
    }
    openid_message_t::fields_iterator openid_message_t::fields_end() const {
	return util::map_keys_iterator<const_iterator,string,const string&,const string*>(end(),end());
    }

    void openid_message_t::reset_fields() {
	clear();
    }
    void openid_message_t::set_field(const string& n,const string& v) {
	(*this)[n]=v;
    }
    void openid_message_t::reset_field(const string& n) {
	erase(n);
    }

}
