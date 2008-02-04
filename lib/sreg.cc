#include <opkele/exception.h>
#include <opkele/sreg.h>
#include <opkele/uris.h>
#include <algorithm>

namespace opkele {
    using std::find;

    static const struct _sreg_field {
	const char *fieldname;
	sreg_t::fieldbit_t fieldbit;
    }	fields[] = {
	{ "nickname", sreg_t::field_nickname },
	{ "email", sreg_t::field_email },
	{ "fullname", sreg_t::field_fullname },
	{ "dob", sreg_t::field_dob },
	{ "gender", sreg_t::field_gender },
	{ "postcode", sreg_t::field_postcode },
	{ "country", sreg_t::field_country },
	{ "language", sreg_t::field_language },
	{ "timezone", sreg_t::field_timezone }
    };
#   define fields_BEGIN	fields
#   define fields_END &fields[sizeof(fields)/sizeof(*fields)]
    typedef const struct _sreg_field *fields_iterator;

    bool operator==(const struct _sreg_field& fd,const string& fn) {
	return fd.fieldname==fn;
    }

    void sreg_t::rp_checkid_hook(basic_openid_message& om) {
	string fr, fo;
	for(fields_iterator f=fields_BEGIN;f<fields_END;++f) {
	    if(f->fieldbit&fields_required) {
		if(!fr.empty()) fr+=",";
		fr += f->fieldname;
	    }
	    if(f->fieldbit&fields_optional) {
		if(!fo.empty()) fo+=",";
		fo += f->fieldname;
	    }
	}
	string pfx = om.allocate_ns(OIURI_SREG11,"sreg");
	if(!fr.empty()) om.set_field(pfx+".required",fr);
	if(!fo.empty()) om.set_field(pfx+".optional",fo);
	if(!policy_url.empty()) om.set_field(pfx+".policy_url",policy_url);
    }

    void sreg_t::checkid_hook(basic_openid_message& om) {
	rp_checkid_hook(om); }

    void sreg_t::rp_id_res_hook(const basic_openid_message& om,
	    const basic_openid_message& sp) {
	clear();
	string pfx;
	try {
	    pfx = om.find_ns(OIURI_SREG11,"sreg");
	}catch(failed_lookup& fl) {
	    try {
		pfx = om.find_ns(OIURI_SREG10,"sreg");
	    }catch(failed_lookup& fl) {
		return;
	    }
	}
	pfx += '.';
	for(fields_iterator f=fields_BEGIN;f<fields_END;++f) {
	    string fn = pfx; fn+=f->fieldname;
	    if(!sp.has_field(fn)) continue;
	    has_fields |= f->fieldbit;
	    response[f->fieldbit]=sp.get_field(fn);
	}
    }

    void sreg_t::id_res_hook(const basic_openid_message& om,
	    const basic_openid_message& sp) {
	rp_id_res_hook(om,sp); }

    const string& sreg_t::get_field(fieldbit_t fb) const {
	response_t::const_iterator i = response.find(fb);
	if(i==response.end())
	    throw failed_lookup(OPKELE_CP_ "no field data available");
	return i->second;
    }

    void sreg_t::set_field(fieldbit_t fb,const string& fv) {
	response[fb] = fv;
	has_fields |= fb;
    }

    void sreg_t::reset_field(fieldbit_t fb) {
	has_fields &= ~fb;
	response.erase(fb);
    }

    void sreg_t::clear() {
	has_fields = 0; response.clear();
    }

    static long fields_list_to_bitmask(string& fl) {
	long rv = 0;
	while(!fl.empty()) {
	    string::size_type co = fl.find(',');
	    string fn;
	    if(co==string::npos) {
		fn = fl; fl.erase();
	    }else{
		fn = fl.substr(0,co); fl.erase(0,co+1);
	    }
	    fields_iterator f = find(fields_BEGIN,fields_END,fn);
	    if(f!=fields_END)
		rv |= f->fieldbit;
	}
	return rv;
    }

    void sreg_t::op_checkid_hook(const basic_openid_message& inm) {
	string ins = inm.find_ns(OIURI_SREG11,"sreg");
	fields_optional = 0; fields_required = 0; policy_url.erase();
	fields_response = 0;
	try {
	    string fl = inm.get_field(ins+".required");
	    fields_required = fields_list_to_bitmask(fl);
	}catch(failed_lookup&) { }
	try {
	    string fl = inm.get_field(ins+".optional");
	    fields_optional = fields_list_to_bitmask(fl);
	}catch(failed_lookup&) { }
	try {
	    policy_url = inm.get_field(ins+".policy_url");
	}catch(failed_lookup&) { }
    }

    void sreg_t::op_id_res_hook(basic_openid_message& oum) {
	string ons = oum.allocate_ns(OIURI_SREG11,"sreg");
	fields_response &= has_fields;
	string signeds = "ns."+ons;
	for(fields_iterator f=fields_BEGIN;f<fields_END;++f) {
	    if(!(f->fieldbit&fields_response)) continue;
	    signeds +=',';
	    string pn = ons; pn += '.'; pn += f->fieldname;
	    signeds += pn;
	    oum.set_field(pn,get_field(f->fieldbit));
	}
	oum.add_to_signed(signeds);
    }

    void sreg_t::checkid_hook(const basic_openid_message& inm,
	    basic_openid_message& oum) {
	op_checkid_hook(inm);
        setup_response(inm,oum);
	op_id_res_hook(oum);
    }

    void sreg_t::setup_response(const basic_openid_message& /* inm */,basic_openid_message& /* oum */) {
	setup_response();
    }
    void sreg_t::setup_response() {
	fields_response = (fields_required|fields_optional)&has_fields;
    }
}
