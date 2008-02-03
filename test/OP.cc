#include <uuid/uuid.h>
#include <iostream>
#include <cassert>
#include <string>
#include <ext/algorithm>
using namespace std;
#include <kingate/exception.h>
#include <kingate/plaincgi.h>
#include <kingate/cgi_gateway.h>
#include <opkele/exception.h>
#include <opkele/util.h>
#include <opkele/uris.h>
#include <opkele/extension.h>
#include <opkele/association.h>
#include <opkele/debug.h>
#include <opkele/verify_op.h>

#include "sqlite.h"
#include "kingate_openid_message.h"

static const string get_self_url(const kingate::cgi_gateway& gw) {
    bool s = gw.has_meta("SSL_PROTOCOL_VERSION");
    string rv = s?"https://":"http://";
    rv += gw.http_request_header("Host");
    const string& port = gw.get_meta("SERVER_PORT");
    if( port!=(s?"443":"80") ) {
	rv += ':'; rv += port;
    }
    rv += gw.get_meta("REQUEST_URI");
    string::size_type q = rv.find('?');
    if(q!=string::npos)
	rv.erase(q);
    return rv;
}

class opdb_t : public sqlite3_t {
    public:
	opdb_t()
	    : sqlite3_t("/tmp/OP.db") {
		assert(_D);
		char **resp; int nr,nc; char *errm;
		if(sqlite3_get_table(
			    _D, "SELECT a_op FROM assoc LIMIT 0",
			    &resp,&nr,&nc,&errm)!=SQLITE_OK) {
		    extern const char *__OP_db_bootstrap;
		    DOUT_("Bootstrapping DB");
		    if(sqlite3_exec(_D,__OP_db_bootstrap,NULL,NULL,&errm)!=SQLITE_OK)
			throw opkele::exception(OPKELE_CP_ string("Failed to boostrap SQLite database: ")+errm);
		}else
		    sqlite3_free_table(resp);
	    }
};

class example_op_t : public opkele::verify_op {
    public:
	kingate::cgi_gateway& gw;
	opdb_t db;
	kingate::cookie htc;


	example_op_t(kingate::cgi_gateway& gw)
	: gw(gw) {
	    try {
		htc = gw.cookies.get_cookie("htop_session");
		sqlite3_mem_t<char*> S = sqlite3_mprintf(
			"SELECT 1 FROM ht_sessions WHERE hts_id=%Q",
			htc.get_value().c_str());
		sqlite3_table_t T; int nr,nc;
		db.get_table(S,T,&nr,&nc);
		if(nr<1)
		    throw kingate::exception_notfound(CODEPOINT,"forcing cookie generation");
	    }catch(kingate::exception_notfound& kenf) {
		uuid_t uuid; uuid_generate(uuid);
		htc = kingate::cookie("htop_session",opkele::util::encode_base64(uuid,sizeof(uuid)));
		sqlite3_mem_t<char*> S = sqlite3_mprintf(
			"INSERT INTO ht_sessions (hts_id) VALUES (%Q)",
			htc.get_value().c_str());
		db.exec(S);
	    }
	}

	void set_authorized(bool a) {
	    sqlite3_mem_t<char*>
		S = sqlite3_mprintf(
			"UPDATE ht_sessions"
			" SET authorized=%d"
			" WHERE hts_id=%Q",
			(int)a,htc.get_value().c_str());
	    db.exec(S);
	}
	bool get_authorized() {
	    sqlite3_mem_t<char*>
		S = sqlite3_mprintf(
			"SELECT authorized"
			" FROM ht_sessions"
			" WHERE hts_id=%Q",
			htc.get_value().c_str());
	    sqlite3_table_t T; int nr,nc;
	    db.get_table(S,T,&nr,&nc);
	    assert(nr==1); assert(nc=1);
	    return opkele::util::string_to_long(T.get(1,0,nc));
	}

	ostream& cookie_header(ostream& o) const {
	    o << "Set-Cookie: " << htc.set_cookie_header() << "\n";
	    return o;
	}

	opkele::assoc_t alloc_assoc(const string& type,size_t klength,bool sl) {
	    uuid_t uuid; uuid_generate(uuid);
	    string a_handle = opkele::util::encode_base64(uuid,sizeof(uuid));
	    opkele::secret_t a_secret;
	    generate_n(
		    back_insert_iterator<opkele::secret_t>(a_secret),klength,
		    rand );
	    string ssecret; a_secret.to_base64(ssecret);
	    time_t now = time(0);
	    int expires_in = sl?3600*2:3600*24*7*2;
	    sqlite3_mem_t<char*>
		S = sqlite3_mprintf(
			"INSERT INTO assoc"
			" (a_handle,a_type,a_ctime,a_etime,a_secret,a_stateless)"
			" VALUES ("
			"  %Q,%Q,datetime('now'),"
			"  datetime('now','+%d seconds'),"
			"  %Q,%d );",
			a_handle.c_str(), type.c_str(),
			expires_in,
			ssecret.c_str(), sl );
	    db.exec(S);
	    return opkele::assoc_t(new opkele::association(
			"",
			a_handle, type, a_secret,
			now+expires_in, sl ));
	}

	opkele::assoc_t retrieve_assoc(const string& h) {
	    sqlite3_mem_t<char*>
		S = sqlite3_mprintf(
			"SELECT"
			"  a_handle,a_type,a_secret,a_stateless,"
			"  strftime('%%s',a_etime) AS a_etime,"
			"  a_itime"
			" FROM assoc"
			" WHERE a_handle=%Q AND a_itime IS NULL"
			"  AND datetime('now') < a_etime"
			" LIMIT 1",
			h.c_str() );
	    sqlite3_table_t T;
	    int nr,nc;
	    db.get_table(S,T,&nr,&nc);
	    if(nr<1)
		throw opkele::failed_lookup(OPKELE_CP_
			"couldn't retrieve valid unexpired assoc");
	    assert(nr==1); assert(nc==6);
	    opkele::secret_t secret; opkele::util::decode_base64(T.get(1,2,nc),secret);
	    return opkele::assoc_t(new opkele::association(
			"", h, T.get(1,1,nc), secret,
			strtol(T.get(1,4,nc),0,0),
			strtol(T.get(1,3,nc),0,0) ));
	}

	string& alloc_nonce(string& nonce,bool stateless) {
	    uuid_t uuid; uuid_generate(uuid);
	    nonce += opkele::util::encode_base64(uuid,sizeof(uuid));
	    sqlite3_mem_t<char*>
		S = sqlite3_mprintf(
			"INSERT INTO nonces"
			" (n_once) VALUES (%Q)",
			nonce.c_str() );
	    db.exec(S);
	    return nonce;
	}
	bool check_nonce(const string& nonce) {
	    sqlite3_mem_t<char*>
		S = sqlite3_mprintf(
			"SELECT 1"
			" FROM nonces"
			" WHERE n_once=%Q AND n_itime IS NULL",
			nonce.c_str());
	    sqlite3_table_t T;
	    int nr,nc;
	    db.get_table(S,T,&nr,&nc);
	    return nr>=1;
	}
	void invalidate_nonce(const string& nonce) {
	    sqlite3_mem_t<char*>
		S = sqlite3_mprintf(
			"UPDATE nonces"
			" SET n_itime=datetime('now')"
			" WHERE n_once=%Q",
			nonce.c_str());
	    db.exec(S);
	}

	const string get_op_endpoint() const {
	    return get_self_url(gw);
	}

};

int main(int argc,char *argv[]) {
    try {
	kingate::plaincgi_interface ci;
	kingate::cgi_gateway gw(ci);
	string op;
	try { op = gw.get_param("op"); }catch(kingate::exception_notfound&) { }
	string message;
	if(op=="set_password") {
	    example_op_t OP(gw);
	    string password = gw.get_param("password");
	    sqlite3_mem_t<char*>
		Sget = sqlite3_mprintf("SELECT s_password FROM setup LIMIT 1");
	    sqlite3_table_t T; int nr,nc;
	    OP.db.get_table(Sget,T,&nr,&nc);
	    if(nr>=1)
		throw opkele::exception(OPKELE_CP_ "Password already set");
	    sqlite3_mem_t<char*>
		Sset = sqlite3_mprintf(
			"INSERT INTO setup (s_password) VALUES (%Q)",
			password.c_str());
	    OP.db.exec(Sset);
	    op.clear();
	    message = "password set";
	}else if(op=="login") {
	    example_op_t OP(gw);
	    string password = gw.get_param("password");
	    sqlite3_mem_t<char*>
		Sget = sqlite3_mprintf("SELECT s_password FROM setup LIMIT 1");
	    sqlite3_table_t T; int nr,nc;
	    OP.db.get_table(Sget,T,&nr,&nc);
	    if(nr<1)
		throw opkele::exception(OPKELE_CP_ "no password set");
	    if(password!=T.get(1,0,nc))
		throw opkele::exception(OPKELE_CP_ "wrong password");
	    OP.set_authorized(true);
	    op.clear();
	    message = "logged in";
	    OP.cookie_header(cout);
	}else if(op=="logout") {
	    example_op_t OP(gw);
	    OP.set_authorized(false);
	    op.clear();
	    message = "logged out";
	}
	string om;
	try { om = gw.get_param("openid.mode"); }catch(kingate::exception_notfound&) { }
	if(op=="xrds") {
	    cout <<
		"Content-type: application/xrds+xml\n\n"
		"<?xml version='1.0' encoding='utf-8'?>"
		"<xrds:XRDS xmlns:xrds='xri://$xrds' xmlns='xri://$xrd*($v*2.0)'>"
		 "<XRD>"
		  "<Service>"
		   "<Type>" STURI_OPENID20 "</Type>"
		   "<URI>" << get_self_url(gw) << "</URI>"
		  "</Service>";
	    if(gw.has_param("idsel")){
		cout <<
		    "<Service>"
		     "<Type>" STURI_OPENID20_OP "</Type>"
		     "<URI>" << get_self_url(gw) << "</URI>";
	    }
	    cout <<
		 "</XRD>"
		"</xrds:XRDS>";
	}else if(op=="id_res" || op=="cancel") {
	    kingate_openid_message_t inm(gw);
	    example_op_t OP(gw);
	    if(gw.get_param("hts_id")!=OP.htc.get_value())
		throw opkele::exception(OPKELE_CP_ "toying around, huh?");
	    OP.checkid_(inm,0);
	    OP.cookie_header(cout);
	    opkele::openid_message_t om;
	    if(op=="id_res") {
		if(!OP.get_authorized())
		    throw opkele::exception(OPKELE_CP_ "not logged in");
		if(OP.is_id_select()) {
		    OP.select_identity( get_self_url(gw), get_self_url(gw) );
		}
		cout <<
		    "Status: 302 Going back to RP with id_res\n"
		    "Location: " << OP.id_res(om).append_query(OP.get_return_to())
		    << "\n\n";
	    }else{
		cout <<
		    "Status: 302 Going back to RP with cancel\n"
		    "Location: " << OP.cancel(om).append_query(OP.get_return_to())
		    << "\n\n";
	    }
	    om.to_keyvalues(clog);
	}else if(om=="associate") {
	    kingate_openid_message_t inm(gw);
	    opkele::openid_message_t oum;
	    example_op_t OP(gw);
	    OP.associate(oum,inm);
	    cout << "Content-type: text/plain\n\n";
	    oum.to_keyvalues(cout);
	}else if(om=="checkid_setup") {
	    kingate_openid_message_t inm(gw);
	    example_op_t OP(gw);
	    OP.checkid_(inm,0);
	    OP.cookie_header(cout) <<
		"Content-type: text/html\n"
		"\n"

		"<html>"
		 "<head>"
		  "<title>test OP: confirm authentication</title>"
		 "</head>"
		 "<body>"
		  "realm: " << OP.get_realm() << "<br/>"
		  "return_to: " << OP.get_return_to() << "<br/>"
		  "claimed_id: " << OP.get_claimed_id() << "<br/>"
		  "identity: " << OP.get_identity() << "<br/>";
	    if(OP.is_id_select()) {
		OP.select_identity( get_self_url(gw), get_self_url(gw) );
		cout <<
		    "selected claimed_id: " << OP.get_claimed_id() << "<br/>"
		    "selected identity: " << OP.get_identity() << "<br/>";
	    }
	    cout <<
		  "<form method='post'>";
	    inm.to_htmlhiddens(cout);
	    cout <<
		  "<input type='hidden' name='hts_id'"
		   " value='" << opkele::util::attr_escape(OP.htc.get_value()) << "'/>"
		  "<input type='submit' name='op' value='id_res'/>"
		  "<input type='submit' name='op' value='cancel'/>"
		  "</form>"
		 "</body>"
		"</html>";
	}else if(om=="check_authentication") {
	    kingate_openid_message_t inm(gw);
	    example_op_t OP(gw);
	    opkele::openid_message_t oum;
	    OP.check_authentication(oum,inm);
	    cout << "Content-type: text/plain\n\n";
	    oum.to_keyvalues(cout);
	    oum.to_keyvalues(clog);
	}else{
	    example_op_t OP(gw);
	    string idsel;
	    if(gw.has_param("idsel"))
		idsel = "&idsel=idsel";
	    OP.cookie_header(cout) <<
		"Content-type: text/html\n"
		"X-XRDS-Location: " << get_self_url(gw) << "?op=xrds" << idsel << "\n"
		"\n"

		"<html>"
		"<head>"
		 "<title>test OP</title>"
		 "<link rel='openid.server' href='" << get_self_url(gw) << "'/>"
		"</head>"
		"<body>"
		"test openid 2.0 endpoint"
		"<br/>"
		"<a href='" << get_self_url(gw) << "?op=xrds" << idsel << "'>XRDS document</a>"
		"<br/>"
		"<h1>" << message << "</h1>";
	    sqlite3_mem_t<char*>
		S = sqlite3_mprintf("SELECT s_password FROM setup LIMIT 1");
	    sqlite3_table_t T; int nr,nc;
	    OP.db.get_table(S,T,&nr,&nc);
	    if(nr<1) {
		cout <<
		    "<form method='post'>"
		     "set password "
		     "<input type='hidden' name='op' value='set_password'/>"
		     "<input type='password' name='password' value=''/>"
		     "<input type='submit' name='submit' value='submit'/>"
		    "</form>";
	    }else if(OP.get_authorized()) {
		cout <<
		    "<br/>"
		    "<a href='" << get_self_url(gw) << "?op=logout'>logout</a>";
	    }else{
		cout <<
		    "<form method='post'>"
		     "login "
		     "<input type='hidden' name='op' value='login'/>"
		     "<input type='password' name='password' value=''/>"
		     "<input type='submit' name='submit' value='submit'/>"
		    "</form>";
	    }
	    cout << "</body>";
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
