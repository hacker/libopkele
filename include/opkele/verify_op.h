#ifndef __OPKELE_VERIFY_OP_H
#define __OPKELE_VERIFY_OP_H

#include <opkele/basic_op.h>

namespace opkele {

    /**
     * The OP implementation that does discovery verification on RP
     */
    class verify_op : public basic_OP {
	public:

	/**
	 * In addition to basic_OP::verify_return_to() functionality this
	 * implementation does the discovery on RP to see if return_to matches
	 * the realm
	 * @throw bad_return_to in case we fail to discover corresponding
	 * service endpoint
	 */
	void verify_return_to();
    };

}

#endif /* __OPKELE_VERIFY_OP_H */
