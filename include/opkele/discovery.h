#ifndef __OPKELE_DISCOVERY_H
#define __OPKELE_DISCOVERY_H

#include <string>
#include <opkele/types.h>

namespace opkele {
    using std::string;

    namespace xrd {

	struct priority_compare {
	    inline bool operator()(long a,long b) const {
		return (a<0) ? false : (b<0) ? true : (a<b);
	    }
	};

	template <typename _DT>
	    class priority_map : public multimap<long,_DT,priority_compare> {
		typedef multimap<long,_DT,priority_compare> map_type;
		public:

		    inline _DT& add(long priority,const _DT& d) {
			return insert(typename map_type::value_type(priority,d))->second;
		    }

		    bool has_value(const _DT& d) const {
			for(typename map_type::const_iterator i=this->begin();i!=this->end();++i)
			    if(i->second==d) return true;
			return false;
		    }
	    };

	typedef priority_map<string> canonical_ids_t;
	typedef priority_map<string> local_ids_t;
	typedef set<string> types_t;
	struct uri_t {
	    string uri;
	    string append;

	    uri_t() { }
	    uri_t(const string& u) : uri(u) { }
	    uri_t(const string& u,const string& a) : uri(u), append(a) { }
	};
	typedef priority_map<uri_t> uris_t;

	class service_t {
	    public:
		types_t types;
		uris_t uris;
		local_ids_t local_ids;
		string provider_id;

		void clear() {
		    types.clear();
		    uris.clear(); local_ids.clear();
		    provider_id.clear();
		}
	};
	typedef priority_map<service_t> services_t;

	class XRD_t {
	    public:
		time_t expires;

		canonical_ids_t canonical_ids;
		local_ids_t local_ids;
		services_t services;
		string provider_id;

		void clear() {
		    expires = 0;
		    canonical_ids.clear(); local_ids.clear();
		    services.clear();
		    provider_id.clear();
		}
		bool empty() const {
		    return
			canonical_ids.empty()
			&& local_ids.empty()
			&& services.empty();
		}

	};

    }

    typedef openid_endpoint_output_iterator endpoint_discovery_iterator;

    string idiscover(
	    endpoint_discovery_iterator oi,
	    const string& identity);
    void yadiscover(
	    endpoint_discovery_iterator oi,
	    const string& yurl,
	    const char **types, bool redirs=false);

    struct idiscovery_t {
	bool xri_identity;
	string normalized_id;
	string canonicalized_id;
	xrd::XRD_t xrd;

	idiscovery_t() { }

	void clear() {
	    normalized_id.clear(); canonicalized_id.clear();
	    xrd.clear();
	}

    };
}

#endif /* __OPKELE_DISCOVERY_H */
