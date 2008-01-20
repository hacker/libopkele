#include <sqlite3.h>

class sqlite3_t {
    public:
	sqlite3 *_D;

	sqlite3_t(const char *f)
	    : _D(0) {
		int r = sqlite3_open(f,&_D);
		if(r!=SQLITE_OK) {
		    string msg = sqlite3_errmsg(_D); sqlite3_close(_D);
		    throw opkele::exception(OPKELE_CP_ "Failed to open SQLite database: "+msg);
		}
	    }
	~sqlite3_t() {
	    if(_D) sqlite3_close(_D);
	}

	operator const sqlite3*(void) const { return _D; }
	operator sqlite3*(void) { return _D; }

	void exec(const char *sql) {
	    assert(_D);
	    char *errm;
	    if(sqlite3_exec(_D,sql,NULL,NULL,&errm)!=SQLITE_OK)
		throw opkele::exception(OPKELE_CP_ string("Failed to sqlite3_exec():")+errm);
	}
	void get_table(const char *sql,char ***resp,int *nr,int *nc) {
	    assert(_D);
	    char *errm;
	    if(sqlite3_get_table(_D,sql,resp,nr,nc,&errm)!=SQLITE_OK)
		throw opkele::exception(OPKELE_CP_ string("Failed to sqlite3_get_table():")+errm);
	}
};

template<typename T>
class sqlite3_mem_t {
    public:
	T _M;

	sqlite3_mem_t(T M) :_M(M) { }
	~sqlite3_mem_t() { if(_M) sqlite3_free(_M); }

	operator const T&(void) const { return _M; }
	operator T&(void) { return _M; }

	sqlite3_mem_t operator=(T M) {
	    if(_M) sqlite3_free(_M);
	    _M = M;
	}
};

class sqlite3_table_t {
    public:
	char **_T;

	sqlite3_table_t() : _T(0) { }
	sqlite3_table_t(char **T) : _T(T) { }
	~sqlite3_table_t() { if(_T) sqlite3_free_table(_T); }

	operator char**&(void) { return _T; }

	operator char ***(void) {
	    if(_T) sqlite3_free_table(_T);
	    return &_T; }

	const char *get(int r,int c,int nc) {
	    assert(_T);
	    return _T[r*nc+c];
	}
};
