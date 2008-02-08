#ifndef __OPKELE_RP_H
#define __OPKELE_RP_H

#include <string>
#include <set>
#include <iterator>
#include <opkele/basic_rp.h>

namespace opkele {
    using std::string;
    using std::set;
    using std::iterator;
    using std::output_iterator_tag;

    /**
     * discovery-enabled RP implementation, prequeueing discovered endpoints
     */
    class prequeue_RP : public basic_RP {
	public:
	    /**
	     * @name Session persistent store API
	     * @{
	     */
	    /**
	     * Called before queueing discovered endpoints. Typically happens
	     * while initiating authentication session.
	     * @see queue_endpoint()
	     * @see end_queueing()
	     */
	    virtual void begin_queueing() { }
	    /**
	     * Used to queue discovered endpoint. It is implementors
	     * responsibility to store the endpoint wherever he choses to store
	     * it.
	     * @param oep the endpoint to queue
	     * @see begin_queueing()
	     * @see end_queueing()
	     */
	    virtual void queue_endpoint(const openid_endpoint_t& oep) = 0;
	    /**
	     * Called after all discovered endpoints were queued. Implementor
	     * may chose to use this virtual to commit endpoints queue to
	     * persistent store.
	     * @see begin_queueing()
	     * @see queue_endpoint()
	     */
	    virtual void end_queueing() { }

	    /**
	     * Used to store normalized id when initiating request.
	     * The default implementation does nothing, because implementor
	     * doesn't have to care.
	     * @param nid normalized id
	     * @see get_normalzied_id()
	     */
	    virtual void set_normalized_id(const string& nid);
	    /**
	     * Return the normalized id previously set by set_normalized_id().
	     * Provided for the sake of completeness because default
	     * implementation doesn't use it.
	     * @return the normalized identity
	     */
	    virtual const string get_normalized_id() const;
	    /**
	     * @}
	     */

	    /**
	     * @name Actions
	     * @{
	     */
	    /**
	     * In addition to base class implementation it does endpoints
	     * discovery and queueing
	     * @param usi User-suppled identifier
	     */
	    void initiate(const string& usi);
	    /**
	     * @}
	     */

	    void verify_OP(const string& OP,
		    const string& claimed_id,const string& identity) const;
    };

}

#endif /* __OPKELE_RP_H */
