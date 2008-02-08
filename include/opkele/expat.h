#ifndef __OPKELE_EXPAT_H
#define __OPKELE_EXPAT_H

#include <cassert>
#include <expat.h>

namespace opkele {

    namespace util {

	class expat_t {
	    public:
		XML_Parser _x;

		expat_t() : _x(0) { }
		expat_t(XML_Parser x) : _x(x) { }
		virtual ~expat_t() throw();

		expat_t& operator=(XML_Parser x);

		operator const XML_Parser(void) const { return _x; }
		operator XML_Parser(void) { return _x; }

		inline bool parse(const char *s,int len,bool final=false) {
		    assert(_x);
		    return XML_Parse(_x,s,len,final);
		}

		virtual void start_element(const XML_Char * /* n */,const XML_Char ** /* a */) { }
		virtual void end_element(const XML_Char * /* n */) { }
		void set_element_handler();

		virtual void character_data(const XML_Char * /* s */,int /* l */) { }
		void set_character_data_handler();

		virtual void processing_instruction(const XML_Char * /* t */,const XML_Char * /* d */) { }
		void set_processing_instruction_handler();

		virtual void comment(const XML_Char * /* d */) { }
		void set_comment_handler();

		virtual void start_cdata_section() { }
		virtual void end_cdata_section() { }
		void set_cdata_section_handler();

		virtual void default_handler(const XML_Char * /* s */,int /* l */) { }
		void set_default_handler();
		void set_default_handler_expand();

		virtual void start_namespace_decl(const XML_Char * /* p */,const XML_Char * /* u */) { }
		virtual void end_namespace_decl(const XML_Char * /* p */) { }
		void set_namespace_decl_handler();

		inline enum XML_Error get_error_code() {
		    assert(_x); return XML_GetErrorCode(_x); }
		static inline const XML_LChar *error_string(XML_Error c) {
		    return XML_ErrorString(c); }

		inline long get_current_byte_index() {
		    assert(_x); return XML_GetCurrentByteIndex(_x); }
		inline int get_current_line_number() {
		    assert(_x); return XML_GetCurrentLineNumber(_x); }
		inline int get_current_column_number() {
		    assert(_x); return XML_GetCurrentColumnNumber(_x); }

		inline void set_user_data() {
		    assert(_x); XML_SetUserData(_x,this); }

		inline bool set_base(const XML_Char *b) {
		    assert(_x); return XML_SetBase(_x,b); }
		inline const XML_Char *get_base() {
		    assert(_x); return XML_GetBase(_x); }

		inline int get_specified_attribute_count() {
		    assert(_x); return XML_GetSpecifiedAttributeCount(_x); }

		inline bool set_param_entity_parsing(enum XML_ParamEntityParsing c) {
		    assert(_x); return XML_SetParamEntityParsing(_x,c); }

		inline static XML_Parser parser_create(const XML_Char *e=0) {
		    return XML_ParserCreate(e); }
		inline static XML_Parser parser_create_ns(const XML_Char *e=0,XML_Char s='\t') {
		    return XML_ParserCreateNS(e,s); }

	};

    }

}

#endif /* __OPKELE_EXPAT_H */
