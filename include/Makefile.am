NODIST_HEADERS_ = \
	opkele/acconfig.h \
	opkele/tr1-mem.h

nobase_include_HEADERS = \
	opkele/opkele-config.h \
	opkele/types.h \
	opkele/association.h \
	opkele/exception.h \
	opkele/server.h \
	opkele/consumer.h \
	opkele/extension.h \
	opkele/sreg.h \
	opkele/extension_chain.h \
	opkele/xconsumer.h \
	opkele/xserver.h \
	opkele/uris.h \
	opkele/tr1-mem.h \
	opkele/basic_rp.h opkele/prequeue_rp.h \
	opkele/iterator.h \
	opkele/basic_op.h opkele/verify_op.h \
	opkele/util.h \
	${NODIST_HEADERS_}

noinst_HEADERS = \
	opkele/data.h \
	opkele/curl.h opkele/expat.h opkele/tidy.h \
	opkele/util-internal.h \
	opkele/debug.h \
	opkele/discovery.h

dist-hook:
	rm -f $(addprefix ${distdir}/,${NODIST_HEADERS_})
