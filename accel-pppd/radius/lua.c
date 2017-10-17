#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "ap_session.h"
#include "radius_p.h"
#include "luasupp.h"
#include "utils.h"

#define LUA_RADIUS "accel-ppp.radius"

static int radius_attrs(lua_State *L)
{
	struct radius_pd_t *rpd = luaL_checkudata(L, 1, LUA_RADIUS);
	struct rad_attr_t *attr;
	int i = 1;

	if (!rpd)
		return 0;

	if (!rpd->auth_reply) {
		lua_pushnil(L);
		return 1;
	}

	lua_newtable(L);

	list_for_each_entry(attr, &rpd->auth_reply->attrs, entry) {
		lua_createtable(L, 0, 3);

		lua_pushstring(L, attr->attr->name);
		lua_setfield(L, -2, "name");

		if (attr->vendor)
			lua_pushstring(L, attr->vendor->name);
		else
			lua_pushnil(L);
		lua_setfield(L, -2, "vendor");

		lua_rawseti(L, -2, i++);
	}

	return 1;
}

static int radius_attr(lua_State *L)
{
	struct radius_pd_t *rpd = luaL_checkudata(L, 1, LUA_RADIUS);
	const char *name;
	const char *vendor;
	struct rad_attr_t *attr;
	struct rad_dict_value_t *val;
	char str[256];
	union {
		uint64_t ifid;
		uint16_t u16[4];
	} ifid_u;
	int r = 0;

	if (!rpd)
		return 0;

	if (!rpd->auth_reply) {
		lua_pushnil(L);
		return 1;
	}

	name = luaL_checkstring(L, 2);
	if (!name)
		return 0;

	vendor = luaL_optstring(L, 3, NULL);

	list_for_each_entry(attr, &rpd->auth_reply->attrs, entry) {
		if ((attr->vendor && !vendor) || (!attr->vendor && vendor))
			continue;

		if (vendor && strcmp(vendor, attr->vendor->name))
			continue;

		if (strcmp(name, attr->attr->name))
			continue;

		switch (attr->attr->type) {
			case ATTR_TYPE_STRING:
				lua_pushstring(L, attr->val.string);
				break;
			case ATTR_TYPE_INTEGER:
				val = rad_dict_find_val(attr->attr, attr->val);
				if (val) {
					lua_pushstring(L, val->name);
					break;
				}
			case ATTR_TYPE_DATE:
				lua_pushinteger(L, attr->val.integer);
				break;
			case ATTR_TYPE_IPADDR:
				u_inet_ntoa(attr->val.ipaddr, str);
				lua_pushstring(L, str);
				break;
			case ATTR_TYPE_IFID:
				ifid_u.ifid = attr->val.ifid;
				sprintf(str, "%x:%x:%x:%x", ntohs(ifid_u.u16[0]), ntohs(ifid_u.u16[1]), ntohs(ifid_u.u16[2]), ntohs(ifid_u.u16[3]));
				lua_pushstring(L, str);
				break;
			case ATTR_TYPE_IPV6ADDR:
				inet_ntop(AF_INET6, &attr->val.ipv6addr, str, sizeof(str));
				lua_pushstring(L, str);
				break;
			case ATTR_TYPE_IPV6PREFIX:
				inet_ntop(AF_INET6, &attr->val.ipv6prefix.prefix, str, sizeof(str));
				sprintf(strchr(str, 0), "/%i", attr->val.ipv6prefix.len);
				lua_pushstring(L, str);
				break;
			default:
				lua_pushlstring(L, (char *)attr->val.octets, attr->len);
				break;
		}

		r++;
	}

	if (!r) {
		lua_pushnil(L);
		r = 1;
	}

	return r;
}

static const struct luaL_Reg radius_lib [] = {
	{"attrs", radius_attrs},
	{"attr", radius_attr},
	{NULL, NULL}
};

static void radius_mod_init(lua_State *L)
{
  luaL_newmetatable(L, LUA_RADIUS);

	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");

#if LUA_VERSION_NUM < 502
  luaL_register(L, NULL, radius_lib);
#else
  luaL_setfuncs(L, radius_lib, 0);
#endif
}

static int radius_mod_get_instance(lua_State *L, struct ap_session *ses)
{
	struct radius_pd_t *rpd = find_pd(ses);

	if (!rpd) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushlightuserdata(L, rpd);
	luaL_getmetatable(L, LUA_RADIUS);
	lua_setmetatable(L, -2);

	return 1;
}

static const struct lua_session_module radius_mod = {
	.name = "radius",
	.init = radius_mod_init,
	.get_instance = radius_mod_get_instance,
};

static void init()
{
	lua_session_module_register(&radius_mod);
}

DEFINE_INIT(1, init);
