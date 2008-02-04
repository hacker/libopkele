#ifndef __OPKELE_SREG_H
#define __OPKELE_SREG_H

/**
 * @file
 * @brief Simple registration extension
 */

#include <opkele/extension.h>

namespace opkele {
    using std::map;

    /**
     * OpenID simple registration extension implementation
     * http://openid.net/specs/openid-simple-registration-extension-1_0.html
     */
    class sreg_t : public extension_t {
	public:
	    /**
	     * sreg fields enumeration
	     */
	    enum fieldbit_t {
		/**
		 * Any UTF-8 string that the End User wants to use as a nickname.
		 */
		field_nickname = 1,
		/**
		 * The email address of the End User as specified in section 3.4.1 of [RFC2822]
		 */
		field_email = 2,
		/**
		 * UTF-8 string free text representation of the End User's full name.
		 */
		field_fullname = 4,
		/**
		 * The End User's date of birth as YYYY-MM-DD. Any values whose
		 * representation uses fewer than the specified number of
		 * digits should be zero-padded. The length of this value MUST
		 * always be 10. If the End User user does not want to reveal
		 * any particular component of this value, it MUST be set to
		 * zero.
		 *
		 * For instance, if a End User wants to specify that his date
		 * of birth is in 1980, but not the month or day, the value
		 * returned SHALL be "1980-00-00".
		 */
		field_dob = 8,
		/**
		 * Alias to field_dob
		 */
		field_birthdate = field_dob,
		/**
		 * The End User's gender, "M" for male, "F" for female.
		 */
		field_gender = 16,
		/**
		 * Alias to field_gender
		 */
		field_sex = field_gender,
		/**
		 * UTF-8 string free text that SHOULD conform to the End User's
		 * country's postal system.
		 */
		field_postcode = 32,
		/**
		 * The End User's country of residence as specified by ISO3166
		 */
		field_country = 64,
		/**
		 * End User's preferred language as specified by ISO639
		 */
		field_language = 128,
		/**
		 * ASCII string from TimeZone database
		 *
		 * For example, "Europe/Paris" or "America/Los_Angeles". 
		 */
		field_timezone = 256,
		/**
		 * All fields bits combined
		 */
		fields_ALL = 511,
		/**
		 * No fields
		 */
		fields_NONE = 0
	    };
	    /**
	     * Bitmask for fields which, if absent from the response, will
	     * prevent the Consumer from completing the registration without
	     * End User interation.
	     */
	    long fields_required;
	    /**
	     * Bitmask for fields that will be used by the Consumer, but whose
	     * absence will not prevent the registration from completing.
	     */
	    long fields_optional;
	    /**
	     * A URL which the Consumer provides to give the End User a place
	     * to read about the how the profile data will be used. The
	     * Identity Provider SHOULD display this URL to the End User if it
	     * is given. 
	     */
	    string policy_url;

	    /**
	     * Bitmask for fields present in response
	     */
	    long has_fields;
	    /**
	     * Container type for response fields values
	     */
	    typedef map<fieldbit_t,string> response_t;
	    /**
	     * Response contents
	     */
	    response_t response;

	    /**
	     * Fields bitmask to send in response
	     */
	    long fields_response;

	    /**
	     * Consumer constructor.
	     * @param fr required fields
	     * @see fields_required
	     * @param fo optional fields
	     * @see fields_optional
	     * @param pu policy url
	     * @see policy_url
	     */
	    sreg_t(long fr=fields_NONE,long fo=fields_NONE,const string& pu="")
		: fields_required(fr), fields_optional(fo), policy_url(pu), has_fields(0) { }

	    virtual void rp_checkid_hook(basic_openid_message& om);
	    virtual void rp_id_res_hook(const basic_openid_message& om,
		    const basic_openid_message& sp);
	    virtual void op_checkid_hook(const basic_openid_message& inm);
	    virtual void op_id_res_hook(basic_openid_message& oum);

	    virtual void checkid_hook(basic_openid_message& om);
	    virtual void id_res_hook(const basic_openid_message& om,
		    const basic_openid_message& sp);
	    virtual void checkid_hook(const basic_openid_message& inm,
		    basic_openid_message& oum);

	    /**
	     * Check and see if we have value for some particular field.
	     * @param fb field in question
	     * @see fieldbit_t
	     * @return true if the value is available
	     */
	    bool has_field(fieldbit_t fb) const { return has_fields&fb; }

	    /**
	     * Retrieve the value for a field.
	     * @param fb field in question
	     * @see fieldbit_t
	     * @return field value
	     * @throw failed_lookup if no data avaialble
	     */
	    const string& get_field(fieldbit_t fb) const;

	    /**
	     * Set the value for a field.
	     * @param fb field in question
	     * @see fieldbit_t
	     * @param fv field value
	     */
	    void set_field(fieldbit_t fb,const string& fv);

	    /**
	     * Remove the value for a field.
	     * @param fb field in question
	     * @see fieldbit_t
	     */
	    void reset_field(fieldbit_t fb);

	    /**
	     * Reset field data
	     */
	    void clear();

	    /**
	     * Function called after parsing sreg request to set up response
	     * fields. The default implementation tries to send as much fields
	     * as we have. The function is supposed to set the data and
	     * fields_response.
	     * @see fields_response
	     * @param inm incoming openid message
	     * @param oum outgoing openid message
	     */
	    virtual void setup_response(const basic_openid_message& inm,
		    basic_openid_message& oum);

	    virtual void setup_response();

    };
}

#endif /* __OPKELE_SREG_H */
