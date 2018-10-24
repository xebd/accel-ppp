#ifndef __LUASUPP_H
#define __LUASUPP_H

#include <lua.h>

#include "ap_session.h"

int luaopen_lpack(lua_State *L);
int luaopen_bit(lua_State *L);

#define LUA_AP_SESSION "ap_session"
int luaopen_ap_session(lua_State *L);

struct lua_session_module {
	const char *name;
	void (*init)(lua_State *L);
	int (*get_instance)(lua_State *L, struct ap_session *ses);
};

void lua_session_module_register(const struct lua_session_module *mod);

#endif
