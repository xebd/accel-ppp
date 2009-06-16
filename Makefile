PPPD := $(shell /usr/sbin/pppd --version 2>&1 | grep version)
PPPD := $(patsubst pppd,,$(PPPD))
PPPD := $(patsubst version,,$(PPPD))
PPPD := $(strip $(PPPD))

default: module plugin pptpd
client: module plugin
server: default

module:
	echo Building kernel module
	(cd kernel/driver; make )

plugin: pppd_plugin/Makefile
	echo Building pppd plugin
	(cd pppd_plugin; make)

pptpd: pptpd-1.3.3/Makefile
	echo Building pptpd
	(cd pptpd-1.3.3; make)

pppd_plugin/Makefile: pptpd-1.3.3/Makefile
	(cd pppd_plugin; ./configure)

pptpd-1.3.3/Makefile:
	(cd pptpd-1.3.3; ./configure)


module_install: module
	(cd kernel/driver; make install)

plugin_install: plugin
	install -m 0644 pppd_plugin/src/.libs/pptp.so.0.0.0 /usr/lib/pppd/$(PPPD)/pptp.so

client_install: module_install plugin_install

server_install: server module_install plugin_install
	(cd pptpd-1.3.3; make install)

clean:
	(cd kernel/driver; make clean)
	(cd pppd_plugin; make clean)
	(cd pptpd-1.3.3; make clean)
distclean:
	(cd kernel/driver; make clean)
	(cd pppd_plugin; make distclean)
	(cd pptpd-1.3.3; make distclean)
