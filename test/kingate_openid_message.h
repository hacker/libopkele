template<typename IT>
class join_iterator : public iterator<
		      input_iterator_tag,typename IT::value_type,
		      void,typename IT::pointer,typename IT::reference> {
    public:
	typedef pair<IT,IT> range_t;
	typedef list<range_t> ranges_t;
	ranges_t ranges;

	join_iterator() { }

	bool cleanup() {
	    bool rv = false;
	    while(!(ranges.empty() || ranges.front().first!=ranges.front().second)) {
		ranges.pop_front(); rv = true;
	    }
	    return rv;
	}

	join_iterator<IT>& add_range(const IT& b,const IT& e) {
	    ranges.push_back(typename ranges_t::value_type(b,e));
	    cleanup();
	    return *this;
	}

	bool operator==(const join_iterator<IT>& x) const {
	    return ranges==x.ranges; }
	bool operator!=(const join_iterator<IT>& x) const {
	    return ranges!=x.ranges; }

	typename IT::reference operator*() const {
	    assert(!ranges.empty());
	    assert(ranges.front().first!=ranges.front().second);
	    return *ranges.front().first; }
	typename IT::pointer operator->() const {
	    assert(!ranges.empty());
	    assert(ranges.front().first!=ranges.front().second);
	    return ranges.front().first.operator->(); }

	join_iterator<IT>& operator++() {
	    cleanup();
	    if(ranges.empty()) return *this;
	    do {
		++ranges.front().first;
	    }while(cleanup() && !ranges.empty());
	    return *this;
	}
	join_iterator<IT> operator++(int) {
	    join_iterator<IT> rv(*this);
	    ++(*this); return rv; }
};

template<typename IT>
class cut_prefix_filterator : public opkele::util::basic_filterator<IT> {
    public:
	string pfx;
	mutable string tmp;

	cut_prefix_filterator() { }
	cut_prefix_filterator(const IT& bi,const IT&ei,const string& pfx)
	    : opkele::util::basic_filterator<IT>(bi,ei), pfx(pfx) {
		this->prepare();
	    }

	bool is_interesting() const {
	    return pfx.length()==0 || !strncmp(this->it->c_str(),pfx.c_str(),pfx.length());
	}

	typename IT::reference operator*() const {
	    assert(!this->empty);
	    tmp = *this->it; tmp.erase(0,pfx.length());
	    return tmp; }
	typename IT::pointer operator->() const {
	    assert(!this->empty);
	    return &this->operator*(); }
};

class kingate_openid_message_t : public opkele::basic_openid_message {
    	typedef join_iterator<kingate::cgi_gateway::params_t::const_iterator> jitterator;
	typedef opkele::util::map_keys_iterator<
	    jitterator,
	    fields_iterator::value_type,
	    fields_iterator::reference,
	    fields_iterator::pointer> keys_iterator;
	typedef cut_prefix_filterator<keys_iterator> pfilterator;
    public:
	const kingate::cgi_gateway& gw;

	kingate_openid_message_t(const kingate::cgi_gateway& g) : gw(g) { }

	bool has_field(const string& n) const {
	    return gw.has_param("openid."+n); }
	const string& get_field(const string& n) const try {
	    return gw.get_param("openid."+n); }catch(kingate::exception_notfound& nf) {
		throw opkele::failed_lookup(OPKELE_CP_ nf.what()); }

	fields_iterator fields_begin() const {
	    return
		pfilterator( keys_iterator(
			    jitterator()
			    .add_range( gw.get.begin(), gw.get.end() )
			    .add_range( gw.post.begin(), gw.post.end() ),
			    jitterator()
			    ), keys_iterator(), "openid." );
	}
	fields_iterator fields_end() const {
	    return pfilterator();
	}
};
