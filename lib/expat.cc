#include <opkele/expat.h>

namespace opkele {

    namespace util {

	expat_t::~expat_t() throw() {
	    if(_x)
		XML_ParserFree(_x);
	}

	expat_t& expat_t::operator=(XML_Parser x) {
	    if(_x)
		XML_ParserFree(_x);
	    _x = x;
	    return *this;
	}

	static void _start_element(void* ud,const XML_Char *n,const XML_Char **a) {
	    ((expat_t*)ud)->start_element(n,a);
	}
	static void _end_element(void *ud,const XML_Char *n) {
	    ((expat_t*)ud)->end_element(n);
	}

	void expat_t::set_element_handler() {
	    assert(_x);
	    XML_SetElementHandler(_x,_start_element,_end_element);
	}

	static void _character_data(void *ud,const XML_Char *s,int l) {
	    ((expat_t*)ud)->character_data(s,l);
	}

	void expat_t::set_character_data_handler() {
	    assert(_x);
	    XML_SetCharacterDataHandler(_x,_character_data);
	}

	static void _processing_instruction(void *ud,const XML_Char *t,const XML_Char *d) {
	    ((expat_t*)ud)->processing_instruction(t,d);
	}

	void expat_t::set_processing_instruction_handler() {
	    assert(_x);
	    XML_SetProcessingInstructionHandler(_x,_processing_instruction);
	}

	static void _comment(void *ud,const XML_Char *d) {
	    ((expat_t*)ud)->comment(d);
	}

	void expat_t::set_comment_handler() {
	    assert(_x);
	    XML_SetCommentHandler(_x,_comment);
	}

	static void _start_cdata_section(void *ud) {
	    ((expat_t*)ud)->start_cdata_section();
	}
	static void _end_cdata_section(void *ud) {
	    ((expat_t*)ud)->end_cdata_section();
	}

	void expat_t::set_cdata_section_handler() {
	    assert(_x);
	    XML_SetCdataSectionHandler(_x,_start_cdata_section,_end_cdata_section);
	}

	static void _default_handler(void *ud,const XML_Char *s,int l) {
	    ((expat_t*)ud)->default_handler(s,l);
	}

	void expat_t::set_default_handler() {
	    assert(_x);
	    XML_SetDefaultHandler(_x,_default_handler);
	}
	void expat_t::set_default_handler_expand() {
	    assert(_x);
	    XML_SetDefaultHandlerExpand(_x,_default_handler);
	}

	static void _start_namespace_decl(void *ud,const XML_Char *p,const XML_Char *u) {
	    ((expat_t*)ud)->start_namespace_decl(p,u);
	}
	static void _end_namespace_decl(void *ud,const XML_Char *p) {
	    ((expat_t*)ud)->end_namespace_decl(p);
	}

	void expat_t::set_namespace_decl_handler() {
	    assert(_x);
	    XML_SetNamespaceDeclHandler(_x,_start_namespace_decl,_end_namespace_decl);
	}

    }

}
