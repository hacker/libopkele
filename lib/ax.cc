#include <opkele/exception.h>
#include <opkele/ax.h>
#include <opkele/uris.h>
#include <opkele/util.h>

#include <map>
#include <string>
#include <vector>

using namespace std;

namespace opkele {

    void ax_t::add_attribute(const char *uri, bool required, const char *alias /* = NULL */, int count /* = 1 */) {
	assert(uri && *uri);
	assert(count != 0);

	ax_attr_t attr;
	attr.uri = uri;
	attr.required = required;
	attr.count = count;
	// if no alias is specified, generate one using an internal auto-incremented counter
	attr.alias = alias ? alias : string("attr") + opkele::util::long_to_string(++alias_count);
	
	attrs.push_back(attr);
    }

    void ax_t::rp_checkid_hook(basic_openid_message& om) {
	if (attrs.size() == 0) return; // not asking for any attributes

	string pfx = om.allocate_ns(OIURI_AX10,"ax");
	om.set_field(pfx+".mode", "fetch_request"); // only supports fetch_request for now

	string required_fields, optional_fields;
	for (size_t i = 0; i < attrs.size(); i++) {
            // build up list of required/optional aliases
	    if (attrs[i].required) required_fields += (required_fields.empty() ? "" : ",") + attrs[i].alias;
	    else optional_fields += (optional_fields.empty() ? "" : ",") + attrs[i].alias;

	    om.set_field(pfx+".type."+attrs[i].alias, attrs[i].uri);

            // only specify count if it's >1 or unlimited
	    if (attrs[i].count == UNLIMITED_COUNT) {
		om.set_field(pfx+".count."+attrs[i].alias, "unlimited");
	    } else if (attrs[i].count > 1) {
		om.set_field(pfx+".count."+attrs[i].alias, opkele::util::long_to_string(attrs[i].count));
	    }
	}

	if (!required_fields.empty()) om.set_field(pfx+".required", required_fields);
	if (!optional_fields.empty()) om.set_field(pfx+".if_available", optional_fields);

	if (!update_url.empty()) om.set_field(pfx+".update_url", update_url);
    }

    void ax_t::checkid_hook(basic_openid_message& om) {
	rp_checkid_hook(om); }

    void ax_t::rp_id_res_hook(const basic_openid_message& om,
	    const basic_openid_message& sp) {
	string pfx;
	try {
	    pfx = om.find_ns(OIURI_AX10,"ax");
	}catch(failed_lookup&) {
		return;
	}
	pfx += '.';

	// first look at all aliases and generate an internal uri->alias map
	string fn;
	map<string, string> aliases;
	for (basic_openid_message::fields_iterator it = sp.fields_begin(); it != sp.fields_end(); ++it) {
	    fn = *it;
	    string type_pfx = pfx; type_pfx += "type.";
	    size_t pos = fn.find(type_pfx);
	    if (pos == string::npos) continue;
            string alias = fn.substr(pos + type_pfx.size());
            aliases[sp.get_field(fn)] = alias;
	}

	// now for each alias, pull out the count and value(s) and store uri->[value1, ...]
	for (map<string, string>::iterator it = aliases.begin(); it != aliases.end(); ++it) {
	    vector<string> values;
	    fn = pfx; fn += "count." + it->second;
	    if (sp.has_field(fn)) {
	        int count = opkele::util::string_to_long(sp.get_field(fn));
		for (int i = 1; i <= count; i++) {
		    fn = pfx; fn += "value." + it->second + "." + opkele::util::long_to_string(i);
		    values.push_back(sp.get_field(fn));
		}
	    } else {
		fn = pfx; fn += "value." + it->second;
		values.push_back(sp.get_field(fn));
	    }
	    response_attrs[it->first] = values;
	}

	fn = pfx; fn += "update_url";
	if (sp.has_field(fn)) update_url = sp.get_field(fn);
    }

    string ax_t::get_attribute(const char *uri, int index /* = 0 */) {
	if (response_attrs.find(uri) == response_attrs.end()) return "";
	return response_attrs[uri][index];
    }

    size_t ax_t::get_attribute_count(const char *uri) {
	if (response_attrs.find(uri) == response_attrs.end()) return 0;
	return response_attrs[uri].size();
    }

    void ax_t::id_res_hook(const basic_openid_message& om,
	    const basic_openid_message& sp) {
	rp_id_res_hook(om,sp); }

    void ax_t::op_checkid_hook(const basic_openid_message& inm) {
    }

    void ax_t::op_id_res_hook(basic_openid_message& oum) {
    }

    void ax_t::checkid_hook(const basic_openid_message& inm,
	    basic_openid_message& oum) {
	op_checkid_hook(inm);
        setup_response(inm,oum);
	op_id_res_hook(oum);
    }

    void ax_t::setup_response(const basic_openid_message& /* inm */,basic_openid_message& /* oum */) {
	setup_response();
    }
    void ax_t::setup_response() {
    }
}

