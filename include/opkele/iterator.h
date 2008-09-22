#ifndef __OPKELE_ITERATOR_H
#define __OPKELE_ITERATOR_H

#include <cassert>
#include <iterator>

namespace opkele {
    namespace util {
	using std::iterator;
	using std::forward_iterator_tag;
	using std::output_iterator_tag;

	template <typename T>
	class basic_output_iterator_proxy_impl : public iterator<output_iterator_tag,T,void,T*,T&> {
	    public:
		virtual ~basic_output_iterator_proxy_impl() { }

		virtual basic_output_iterator_proxy_impl<T>* dup() const = 0;
		basic_output_iterator_proxy_impl<T>& operator*() { return *this; };
		virtual basic_output_iterator_proxy_impl<T>& operator=(const T& x) = 0;

	};

	template<typename IT,typename T=typename IT::value_type>
	class output_iterator_proxy_impl : public basic_output_iterator_proxy_impl<T> {
	    public:
		IT i;

		output_iterator_proxy_impl(const IT& _i) : i(_i) { }
		basic_output_iterator_proxy_impl<T>* dup() const {
		    return new output_iterator_proxy_impl<IT,T>(i); }
		basic_output_iterator_proxy_impl<T>& operator=(const T& x) {
		    (*i) = x; return *this; }
	};

	template<typename T>
	class output_iterator_proxy : public iterator<output_iterator_tag,T,void,T*,T&> {
	    public:
		basic_output_iterator_proxy_impl<T> *I;

		template<typename IT>
		    output_iterator_proxy(const IT& i)
		    : I(new output_iterator_proxy_impl<IT,T>(i)) { }
		output_iterator_proxy(const output_iterator_proxy<T>& x)
		    : I(x.I->dup()) { }
		~output_iterator_proxy() { delete I; }

		output_iterator_proxy& operator=(const output_iterator_proxy<T>& x) {
		    delete I; I = x.I->dup(); }

		output_iterator_proxy& operator*() { return *this; }
		output_iterator_proxy& operator=(const T& x) {
		    (**I) = x; return *this; }

		output_iterator_proxy& operator++() { return *this; }
		output_iterator_proxy& operator++(int) { return *this; }
	};

	template <typename T,typename TR=T&,typename TP=T*>
	class basic_forward_iterator_proxy_impl : public iterator<forward_iterator_tag,T,void,TP,TR> {
	    public:
		virtual ~basic_forward_iterator_proxy_impl() { }

		virtual basic_forward_iterator_proxy_impl<T,TR,TP>* dup() const = 0;

		virtual bool operator==(const basic_forward_iterator_proxy_impl<T,TR,TP>& x) const = 0;
		virtual bool operator!=(const basic_forward_iterator_proxy_impl<T,TR,TP>& x) const {
		    return !((*this)==x); }
		virtual TR operator*() const = 0;
		virtual TP operator->() const = 0;
		virtual void advance() = 0;
	};

	template <typename IT>
	class forward_iterator_proxy_impl : public basic_forward_iterator_proxy_impl<typename IT::value_type,typename IT::reference,typename IT::pointer> {
	    public:
		IT i;

		forward_iterator_proxy_impl(const IT& _i) : i(_i) { }

		virtual basic_forward_iterator_proxy_impl<typename IT::value_type,typename IT::reference,typename IT::pointer>* dup() const {
		    return new forward_iterator_proxy_impl<IT>(i); }

		virtual bool operator==(const basic_forward_iterator_proxy_impl<typename IT::value_type,typename IT::reference,typename IT::pointer>& x) const {
		    return i==static_cast<const forward_iterator_proxy_impl<IT>*>(&x)->i; }
		virtual bool operator!=(const basic_forward_iterator_proxy_impl<typename IT::value_type,typename IT::reference,typename IT::pointer>& x) const {
		    return i!=static_cast<const forward_iterator_proxy_impl<IT>*>(&x)->i; }
		virtual typename IT::reference operator*() const { return *i; }
		virtual typename IT::pointer operator->() const { return i.operator->(); }
		virtual void advance() { ++i; }
	};

	template<typename T,typename TR=T&,typename TP=T*>
	class forward_iterator_proxy : public iterator<forward_iterator_tag,T,void,TP,TR> {
	    public:
		basic_forward_iterator_proxy_impl<T,TR,TP> *I;

		template<typename IT>
		    forward_iterator_proxy(const IT& i)
		    : I(new forward_iterator_proxy_impl<IT>(i)) { }
		forward_iterator_proxy(const forward_iterator_proxy<T,TR,TP>& x)
		    : I(x.I->dup()) { }
		~forward_iterator_proxy() { delete I; }

		forward_iterator_proxy& operator=(const forward_iterator_proxy<T,TR,TP>& x) {
		    delete I; I = x.I->dup(); return *this; }

		bool operator==(const forward_iterator_proxy<T,TR,TP>& x) const {
		    return (*I)==(*(x.I)); }
		bool operator!=(const forward_iterator_proxy<T,TR,TP>& x) const {
		    return (*I)!=(*(x.I)); }

		TR operator*() const {
		    return **I; }
		TP operator->() const {
		    return I->operator->(); }

		forward_iterator_proxy<T,TR,TP>& operator++() {
		    I->advance(); return *this; }
		forward_iterator_proxy<T,TR,TP>& operator++(int) {
		    forward_iterator_proxy<T,TR,TP> rv(*this);
		    I->advance(); return rv; }
	};

	template<typename IT>
	    class basic_filterator : public iterator<
					  typename IT::iterator_category,
					  typename IT::value_type,
					  typename IT::difference_type,
					  typename IT::pointer,
					  typename IT::reference> {
		public:
		    IT it;
		    IT ei;
		    bool empty;

		    basic_filterator() : empty(true) { }
		    basic_filterator(const IT& _bi,const IT& _ei)
			: it(_bi), ei(_ei) { empty = (it==ei); }
		    basic_filterator(const basic_filterator<IT>& x)
			: it(x.it), ei(x.ei), empty(x.empty) { }
		    virtual ~basic_filterator() { }

		    bool operator==(const basic_filterator<IT>& x) const {
			return empty?x.empty:(it==x.it); }
		    bool operator!=(const basic_filterator<IT>& x) const {
			return empty!=x.empty || it!=x.it; }

		    typename IT::reference operator*() const {
			assert(!empty);
			return *it; }
		    typename IT::pointer operator->() const {
			assert(!empty);
			return it.operator->(); }

		    basic_filterator<IT>& operator++() {
			bool found = false;
			for(++it;!(it==ei || (found=is_interesting()));++it) ;
			if(!found) empty=true;
			return *this;
		    }
		    basic_filterator<IT> operator++(int) {
			basic_filterator<IT> rv(*this);
			++(*this);
			return rv;
		    }

		    void prepare() {
			bool found = false;
			for(;!(it==ei || (found=is_interesting()));++it) ;
			if(!found) empty = true;
		    }
		    virtual bool is_interesting() const = 0;
	    };

	template<typename IT,typename T=typename IT::value_type::first_type,typename TR=T&,typename TP=T*>
	    class map_keys_iterator : public iterator<
				      typename IT::iterator_category,
				      T,void,TP,TR> {
		public:
		    typedef map_keys_iterator<IT,T,TR,TP> self_type;
		    IT it;
		    IT ei;
		    bool empty;

		    map_keys_iterator() : empty(true) { }
		    map_keys_iterator(const IT& _bi,
			    const IT& _ei)
			: it(_bi), ei(_ei) { empty = (it==ei); }
		    map_keys_iterator(const self_type& x)
			: it(x.it), ei(x.ei), empty(x.empty) { }

		    bool operator==(const self_type& x) const {
			return empty?x.empty:(it==x.it); }
		    bool operator!=(const self_type& x) const {
			return empty!=x.empty || it!=x.it; }

		    TR operator*() const {
			assert(!empty);
			return it->first; }
		    TP operator->() const {
			assert(!empty);
			return &(it->first); }

		    self_type& operator++() {
			assert(!empty);
			empty=((++it)==ei); return *this; }
		    self_type operator++(int) {
			self_type rv(*this);
			++(*this); return rv; }
	    };

    }
}

#endif /* __OPKELE_ITERATOR_H */
