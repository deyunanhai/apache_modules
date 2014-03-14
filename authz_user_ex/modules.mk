mod_authz_user_ex.la: mod_authz_user_ex.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_authz_user_ex.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_authz_user_ex.la
