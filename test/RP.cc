#include <uuid/uuid.h>
#include <iostream>
#include <cassert>
#include <stdexcept>
#include <string>
#include <set>
#include <iterator>
using namespace std;
#include <kingate/exception.h>
#include <kingate/plaincgi.h>
#include <kingate/cgi_gateway.h>
#include <opkele/exception.h>
#include <opkele/types.h>
#include <opkele/util.h>
#include <opkele/uris.h>
#include <opkele/discovery.h>
#include <opkele/association.h>
#include <opkele/sreg.h>
using namespace opkele;
#include <opkele/prequeue_rp.h>
#include <opkele/debug.h>

#include "sqlite.h"
#include "kingate_openid_message.h"

#undef DUMB_RP

#ifdef DUMB_RP
# define DUMBTHROW throw opkele::dumb_RP(OPKELE_CP_ "This RP is dumb")
#else
# define DUMBTHROW (void)0
#endif

class rpdb_t : public sqlite3_t {
    public:
	rpdb_t()
	    : sqlite3_t("/tmp/RP.db") {
		assert(_D);
		char **resp; int nrow,ncol; char *errm;
		if(sqlite3_get_table(
			_D,"SELECT a_op FROM assoc LIMIT 0",
			&resp,&nrow,&ncol,&errm)!=SQLITE_OK) {
		    extern const char *__RP_db_bootstrap;
		    DOUT_("Bootstrapping DB");
		    if(sqlite3_exec(_D,__RP_db_bootstrap,NULL,NULL,&errm)!=SQLITE_OK)
			throw opkele::exception(OPKELE_CP_ string("Failed to bootstrap SQLite database: ")+errm);
		}else
		    sqlite3_free_table(resp);

	    }
};

class example_rp_t : public opkele::prequeue_RP {
    public:
	mutable rpdb_t db;
	kingate::cookie htc;
	long as_id;
	int ordinal;
	kingate::cgi_gateway& gw;

	example_rp_t(kingate::cgi_gateway& g)
	: as_id(-1), ordinal(0), gw(g), have_eqtop(false)  {
	    try {
		htc = gw.cookies.get_cookie("ht_session");
		as_id = opkele::util::string_to_long(gw.get_param("asid"));
	    }catch(kingate::exception_notfound& kenf) {
		uuid_t uuid; uuid_generate(uuid);
		htc = kingate::cookie("ht_session",util::encode_base64(uuid,sizeof(uuid)));
		sqlite3_mem_t<char*> S = sqlite3_mprintf(
			"INSERT INTO ht_sessions (hts_id) VALUES (%Q)",
			htc.get_value().c_str());
		db.exec(S);
	    }
	}

	/* Global persistent store */

	opkele::assoc_t store_assoc(
		const string& OP,const string& handle,
		const string& type,const secret_t& secret,
		int expires_in) {
	    DUMBTHROW;
	    DOUT_("Storing '" << handle << "' assoc with '" << OP << "'");
	    time_t exp = time(0)+expires_in;
	    sqlite3_mem_t<char*>
		S = sqlite3_mprintf(
			"INSERT INTO assoc"
			" (a_op,a_handle,a_type,a_ctime,a_etime,a_secret)"
			" VALUES ("
			"  %Q,%Q,%Q,"
			"  datetime('now'), datetime('now','+%d seconds'),"
			"  %Q"
			" );", OP.c_str(), handle.c_str(), type.c_str(),
			expires_in,
			util::encode_base64(&(secret.front()),secret.size()).c_str() );
	    db.exec(S);
	    return opkele::assoc_t(new opkele::association(
			OP, handle, type, secret, exp, false ));
	}

	opkele::assoc_t find_assoc(
		const string& OP) {
	    DUMBTHROW;
	    DOUT_("Looking for an assoc with '" << OP << '\'');
	    sqlite3_mem_t<char*>
		S = sqlite3_mprintf(
			"SELECT"
			"  a_op,a_handle,a_type,a_secret,"
			"  strftime('%%s',a_etime) AS a_etime"
			" FROM assoc"
			" WHERE a_op=%Q AND a_itime IS NULL AND NOT a_stateless"
			"  AND ( a_etime > datetime('now','-30 seconds') )"
			" LIMIT 1",
			OP.c_str());
	    sqlite3_table_t T;
	    int nr,nc;
	    db.get_table(S,T,&nr,&nc);
	    if(nr<1)
		throw opkele::failed_lookup(OPKELE_CP_ "Couldn't find unexpired handle");
	    assert(nr==1);
	    assert(nc==5);
	    secret_t secret;
	    util::decode_base64(T.get(1,3,nc),secret);
	    DOUT_(" found '" << T.get(1,1,nc) << '\'');
	    return opkele::assoc_t(new opkele::association(
			T.get(1,0,nc), T.get(1,1,nc), T.get(1,2,nc),
			secret, strtol(T.get(1,4,nc),0,0), false ));
	}

	opkele::assoc_t retrieve_assoc(
		const string& OP,const string& handle) {
	    DUMBTHROW;
	    DOUT_("Retrieving assoc '" << handle << "' with '" << OP << '\'');
	    sqlite3_mem_t<char*>
		S = sqlite3_mprintf(
			"SELECT"
			"  a_op,a_handle,a_type,a_secret,"
			"  strftime('%%s',a_etime) AS a_etime"
			" FROM assoc"
			" WHERE a_op=%Q AND a_handle=%Q"
			"  AND a_itime IS NULL AND NOT a_stateless"
			" LIMIT 1",
			OP.c_str(),handle.c_str());
	    sqlite3_table_t T;
	    int nr,nc;
	    db.get_table(S,T,&nr,&nc);
	    if(nr<1)
		throw opkele::failed_lookup(OPKELE_CP_ "couldn't retrieve valid association");
	    assert(nr==1); assert(nc==5);
	    secret_t secret; util::decode_base64(T.get(1,3,nc),secret);
	    DOUT_(" found. type=" << T.get(1,2,nc) << '\'');
	    return opkele::assoc_t(new opkele::association(
			T.get(1,0,nc), T.get(1,1,nc), T.get(1,2,nc),
			secret, strtol(T.get(1,4,nc),0,0), false ));
	}

	void invalidate_assoc(
		const string& OP,const string& handle) {
	    DUMBTHROW;
	    DOUT_("Invalidating assoc '" << handle << "' with '" << OP << '\'');
	    sqlite3_mem_t<char*>
		S = sqlite3_mprintf(
			"UPDATE assoc SET a_itime=datetime('now')"
			" WHERE a_op=%Q AND a_handle=%Q",
			OP.c_str(), handle.c_str() );
	    db.exec(S);
	}

	void check_nonce(const string& OP,const string& nonce) {
	    DOUT_("Checking nonce '" << nonce << "' from '" << OP << '\'');
	    sqlite3_mem_t<char*>
		S = sqlite3_mprintf(
			"SELECT 1 FROM nonces WHERE n_op=%Q AND n_once=%Q",
			OP.c_str(), nonce.c_str());
	    sqlite3_table_t T;
	    int nr,nc;
	    db.get_table(S,T,&nr,&nc);
	    if(nr)
		throw opkele::id_res_bad_nonce(OPKELE_CP_ "already seen that nonce");
	    sqlite3_mem_t<char*>
		SS = sqlite3_mprintf(
			"INSERT INTO nonces (n_op,n_once) VALUES (%Q,%Q)",
			OP.c_str(), nonce.c_str());
	    db.exec(SS);
	}

	/* Session perisistent store */

	void begin_queueing() {
	    assert(as_id>=0);
	    DOUT_("Resetting queue for session '" << htc.get_value() << "'/" << as_id);
	    sqlite3_mem_t<char*> S = sqlite3_mprintf(
		    "DELETE FROM endpoints_queue"
		    " WHERE as_id=%ld",
		    as_id);
	    db.exec(S);
	}

	void queue_endpoint(const opkele::openid_endpoint_t& ep) {
	    assert(as_id>=0);
	    DOUT_("Queueing endpoint " << ep.claimed_id << " : " << ep.local_id << " @ " << ep.uri);
	    sqlite3_mem_t<char*> S = sqlite3_mprintf(
		    "INSERT INTO endpoints_queue"
		    " (as_id,eq_ctime,eq_ordinal,eq_uri,eq_claimed_id,eq_local_id)"
		    " VALUES (%ld,strftime('%%s','now'),%d,%Q,%Q,%Q)",
		    as_id,ordinal++,
		    ep.uri.c_str(),ep.claimed_id.c_str(),ep.local_id.c_str());
	    db.exec(S);
	}

	mutable openid_endpoint_t eqtop;
	mutable bool have_eqtop;

	const openid_endpoint_t& get_endpoint() const {
	    assert(as_id>=0);
	    if(!have_eqtop) {
		sqlite3_mem_t<char*>
		    S = sqlite3_mprintf(
			    "SELECT"
			    "  eq_uri, eq_claimed_id, eq_local_id"
			    " FROM endpoints_queue"
			    "  JOIN auth_sessions USING(as_id)"
			    " WHERE hts_id=%Q AND as_id=%ld"
			    " ORDER BY eq_ctime,eq_ordinal"
			    " LIMIT 1",htc.get_value().c_str(),as_id);
		sqlite3_table_t T; int nr,nc;
		db.get_table(S,T,&nr,&nc);
		if(nr<1)
		    throw opkele::exception(OPKELE_CP_ "No more endpoints queued");
		assert(nr==1); assert(nc==3);
		eqtop.uri = T.get(1,0,nc);
		eqtop.claimed_id = T.get(1,1,nc);
		eqtop.local_id = T.get(1,2,nc);
		have_eqtop = true;
	    }
	    return eqtop;
	}

	void next_endpoint() {
	    assert(as_id>=0);
	    get_endpoint();
	    have_eqtop = false;
	    sqlite3_mem_t<char*> S = sqlite3_mprintf(
		    "DELETE FROM endpoints_queue"
		    " WHERE as_id=%ld AND eq_uri=%Q AND eq_local_id=%Q",
		    htc.get_value().c_str(),as_id,
		    eqtop.uri.c_str());
	    db.exec(S);
	}

	mutable string _nid;

	void set_normalized_id(const string& nid) {
	    assert(as_id>=0);
	    sqlite3_mem_t<char*> S = sqlite3_mprintf(
		    "UPDATE auth_sessions"
		    " SET as_normalized_id=%Q"
		    " WHERE hts_id=%Q and as_id=%ld",
		    nid.c_str(),
		    htc.get_value().c_str(),as_id);
	    db.exec(S);
	    _nid = nid;
	}
	const string get_normalized_id() const {
	    assert(as_id>=0);
	    if(_nid.empty()) {
		sqlite3_mem_t<char*> S = sqlite3_mprintf(
			"SELECT as_normalized_id"
			" FROM"
			"  auth_sessions"
			" WHERE"
			"  hts_id=%Q AND as_id=%ld",
			htc.get_value().c_str(),as_id);
		sqlite3_table_t T; int nr,nc;
		db.get_table(S,T,&nr,&nc);
		assert(nr==1); assert(nc==1);
		_nid = T.get(1,0,nc);
	    }
	    return _nid;
	}

	const string get_this_url() const {
	    bool s = gw.has_meta("SSL_PROTOCOL_VERSION");
	    string rv = s?"https://":"http://";
	    rv += gw.http_request_header("Host");
	    const string& port = gw.get_meta("SERVER_PORT");
	    if( port!=(s?"443":"80") ) {
		rv += ':'; rv += port;
	    }
	    rv += gw.get_meta("REQUEST_URI");
	    return rv;
	}

	void initiate(const string& usi) {
	    allocate_asid();
	    prequeue_RP::initiate(usi);
	}

	string get_self_url() const {
	    string rv = get_this_url();
	    string::size_type q = rv.find('?');
	    if(q!=string::npos)
		rv.erase(q);
	    return rv;
	}

	void allocate_asid() {
	    sqlite3_mem_t<char*> S = sqlite3_mprintf(
		    "INSERT INTO auth_sessions (hts_id)"
		    " VALUES (%Q)",
		    htc.get_value().c_str());
	    db.exec(S);
	    as_id = sqlite3_last_insert_rowid(db);
	    DOUT_("Allocated authentication session id "<<as_id);
	    assert(as_id>=0);
	}

#ifdef DUMB_RP
	virtual assoc_t associate(const string& OP) {
	    DUMBTHROW;
	}
#endif
};

int main(int,char **) {
    try {
	kingate::plaincgi_interface ci;
	kingate::cgi_gateway gw(ci);
	string op;
	try { op = gw.get_param("op"); }catch(kingate::exception_notfound&) { }
	if(op=="initiate") {
	    example_rp_t rp(gw);
	    string usi = gw.get_param("openid_identity");
	    rp.initiate(usi);
	    opkele::sreg_t sreg(opkele::sreg_t::fields_NONE,opkele::sreg_t::fields_ALL);
	    opkele::openid_message_t cm;
	    string loc;
	    cout <<
		"Set-Cookie: " << rp.htc.set_cookie_header() << "\n"
		"Status: 302 Going to OP\n"
		"Location: " << (
			loc = rp.checkid_(cm,opkele::mode_checkid_setup,
			rp.get_self_url()+
			"?op=confirm&asid="+opkele::util::long_to_string(rp.as_id),
			rp.get_self_url(),&sreg).append_query(rp.get_endpoint().uri)
			)
		<< "\n\n";
	    DOUT_("Going to " << loc);
	}else if(op=="confirm") {
	    kingate_openid_message_t om(gw);
	    example_rp_t rp(gw);
	    opkele::sreg_t sreg(opkele::sreg_t::fields_NONE,opkele::sreg_t::fields_ALL);
	    rp.id_res(om,&sreg);
	    cout <<
		"Content-Type: text/plain\n\n";
	    for(opkele::basic_openid_message::fields_iterator i=om.fields_begin();
		    i!=om.fields_end();++i) {
		cout << *i << '=' << om.get_field(*i) << endl;
	    }
	    cout << endl
		<< "SREG fields: " << sreg.has_fields << endl;
	}else{
	    cout <<
		"Content-type: text/html\n\n"

		"<html>"
		 "<head><title>test RP</title></head>"
		 "<body>"
		  "<form action='' method='post'>"
		   "<input type='hidden' name='op' value='initiate' />"
		   "<input type='text' name='openid_identity'/>"
		   "<input type='submit' name='submit' value='submit' />"
		  "</form>"
		  "<br/><br/>"
		  "<a href='?op=initiate&amp;openid_identity=www.myopenid.com&amp;dummy=" << time(0) << "'>login with myopenid.com account</a>"
		  "<br/>"
		 "</body"
		"</html>"
		;
	}
#ifdef OPKELE_HAVE_KONFORKA
    }catch(konforka::exception& e) {
#else
    }catch(std::exception& e){
#endif
	DOUT_("Oops: " << e.what());
	cout << "Content-Type: text/plain\n\n"
	    "Exception:\n"
	    " what: " << e.what() << endl;
#ifdef OPKELE_HAVE_KONFORKA
	cout << " where: " << e.where() << endl;
	if(!e._seen.empty()) {
	    cout << " seen:" << endl;
	    for(list<konforka::code_point>::const_iterator
		    i=e._seen.begin();i!=e._seen.end();++i) {
		cout << "  " << i->c_str() << endl;
	    }
	}
#endif
    }
}
