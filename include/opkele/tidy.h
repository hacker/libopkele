#ifndef __OPKELE_TIDY_H
#define __OPKELE_TIDY_H

#include <cassert>
#include <tidy.h>
#include <buffio.h>

namespace opkele {
    namespace util {

	class tidy_buf_t {
	    public:
		TidyBuffer _x;

		tidy_buf_t() { tidyBufInit(&_x); }
		virtual ~tidy_buf_t() throw() {
		    tidyBufFree(&_x); }

		inline operator const TidyBuffer&(void) const { return _x; }
		inline operator TidyBuffer&(void) { return _x; }

		inline operator const char*(void) const { return (const char*)_x.bp; }
		inline operator char*(void) { return (char*)_x.bp; }

		inline const char *c_str() const {
		    return (const char*)_x.bp; }
		inline size_t size() const {
		    return _x.size; }
	};

	class tidy_doc_t {
	    public:
		TidyDoc _x;

		tidy_doc_t() : _x(0) { }
		tidy_doc_t(TidyDoc x) : _x(x) { }
		virtual ~tidy_doc_t() throw() {
		    if(_x) tidyRelease(_x); }

		tidy_doc_t& operator=(TidyDoc x) {
		    if(_x) tidyRelease(_x);
		    _x = x;
		    return *this;
		}

		operator const TidyDoc(void) const { return _x; }
		operator TidyDoc(void) { return _x; }

		inline bool opt_set(TidyOptionId o,bool v) {
		    assert(_x);
		    return tidyOptSetBool(_x,o,v?yes:no); }
		inline bool opt_set(TidyOptionId o,int v) {
		    assert(_x);
		    return tidyOptSetInt(_x,o,v); }

		inline int parse_string(const string& s) {
		    assert(_x);
		    return tidyParseString(_x,s.c_str()); }
		inline int clean_and_repair() {
		    assert(_x);
		    return tidyCleanAndRepair(_x); }
		inline int save_buffer(TidyBuffer& ob) {
		    assert(_x);
		    return tidySaveBuffer(_x,&ob); }

		static inline TidyDoc create() {
		    return tidyCreate(); }
	};

    }
}

#endif /* __OPKELE_TIDY_H */
