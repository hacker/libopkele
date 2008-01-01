#ifndef __OPKELE_DEBUG_H
#define __OPKELE_DEBUG_H

#ifdef NDEBUG

#define D_(x)		((void)0)
#define DOUT_(x)	((void)0)

#else /* NDEBUG */

#define D_(x)		x
#include <iostream>
#define DOUT_(x)	std::clog << x << std::endl

#endif /* NDEBUG */

#endif /* __OPKELE_DEBUG_H */
