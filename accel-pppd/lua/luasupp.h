#ifndef __LUASUPP_H
#define __LUASUPP_H

#include <lua.h>

int luaopen_lpack(lua_State *L);
int luaopen_bit(lua_State *L);

#define LUA_AP_SESSION "ap_session"
int luaopen_ap_session(lua_State *L);

#endif
