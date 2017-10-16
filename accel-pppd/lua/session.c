#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "ap_session.h"
#include "ipdb.h"
#include "utils.h"
#include "luasupp.h"

static int session_ifname(lua_State *L);
static int session_ifindex(lua_State *L);
static int session_sid(lua_State *L);
static int session_uptime(lua_State *L);
static int session_username(lua_State *L);
static int session_type(lua_State *L);
static int session_calling_sid(lua_State *L);
static int session_called_sid(lua_State *L);
static int session_ipv4(lua_State *L);
static int session_ipv6(lua_State *L);
static int session_rx_bytes(lua_State *L);
static int session_tx_bytes(lua_State *L);

static const struct luaL_Reg session_lib [] = {
	{"ifname", session_ifname},
	{"ifindex", session_ifindex},
	{"sid", session_sid},
	{"uptime", session_uptime},
	{"username", session_username},
	{"ctrl_type", session_type},
	{"calling_sid", session_calling_sid},
	{"called_sid", session_called_sid},
	{"ipv4", session_ipv4},
	{"ipv6", session_ipv6},
	{"rx_bytes", session_rx_bytes},
	{"tx_bytes", session_tx_bytes},
	{NULL, NULL}
};

int __export luaopen_ap_session(lua_State *L)
{
  luaL_newmetatable(L, LUA_AP_SESSION);

	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");

#if LUA_VERSION_NUM < 502
  luaL_register(L, NULL, session_lib);
#else
  luaL_setfuncs(L, session_lib, 0);
#endif

	return 1;
}

static int session_ifname(lua_State *L)
{
	struct ap_session *ses = luaL_checkudata(L, 1, LUA_AP_SESSION);

	if (!ses)
		return 0;

	lua_pushstring(L, ses->ifname);

	return 1;
}

static int session_ifindex(lua_State *L)
{
	struct ap_session *ses = luaL_checkudata(L, 1, LUA_AP_SESSION);

	if (!ses)
		return 0;

	lua_pushinteger(L, ses->ifindex);

	return 1;
}

static int session_sid(lua_State *L)
{
	struct ap_session *ses = luaL_checkudata(L, 1, LUA_AP_SESSION);

	if (!ses)
		return 0;

	lua_pushstring(L, ses->sessionid);

	return 1;
}

static int session_uptime(lua_State *L)
{
	struct ap_session *ses = luaL_checkudata(L, 1, LUA_AP_SESSION);
	time_t t;

	if (!ses)
		return 0;

	t = ses->stop_time ?: _time();

	lua_pushinteger(L, t - ses->start_time);

	return 1;
}

static int session_username(lua_State *L)
{
	struct ap_session *ses = luaL_checkudata(L, 1, LUA_AP_SESSION);

	if (!ses)
		return 0;

	lua_pushstring(L, ses->username);

	return 1;
}

static int session_type(lua_State *L)
{
	struct ap_session *ses = luaL_checkudata(L, 1, LUA_AP_SESSION);

	if (!ses)
		return 0;

	lua_pushstring(L, ses->ctrl->name);

	return 1;
}

static int session_calling_sid(lua_State *L)
{
	struct ap_session *ses = luaL_checkudata(L, 1, LUA_AP_SESSION);

	if (!ses)
		return 0;

	lua_pushstring(L, ses->ctrl->calling_station_id);

	return 1;
}

static int session_called_sid(lua_State *L)
{
	struct ap_session *ses = luaL_checkudata(L, 1, LUA_AP_SESSION);

	if (!ses)
		return 0;

	lua_pushstring(L, ses->ctrl->called_station_id);

	return 1;
}

static int session_ipv4(lua_State *L)
{
	struct ap_session *ses = luaL_checkudata(L, 1, LUA_AP_SESSION);
	char addr1[17], addr2[17];

	if (!ses)
		return 0;

	if (ses->ipv4) {
		u_inet_ntoa(ses->ipv4->peer_addr, addr1);
		u_inet_ntoa(ses->ipv4->addr, addr2);
		lua_pushstring(L, addr1);
		lua_pushstring(L, addr2);
		return 2;
	}

	lua_pushnil(L);

	return 1;
}

static int session_ipv6(lua_State *L)
{
	struct ap_session *ses = luaL_checkudata(L, 1, LUA_AP_SESSION);
	struct ipv6db_addr_t *a;
	struct in6_addr addr;
	char str[64];

	if (!ses)
		return 0;

	if (ses->ipv6) {
		a = list_entry(ses->ipv6->addr_list.next, typeof(*a), entry);
		if (a->prefix_len) {
			build_ip6_addr(a, ses->ipv6->peer_intf_id, &addr);
			inet_ntop(AF_INET6, &addr, str, 64);
			sprintf(strchr(str, 0), "/%i", a->prefix_len);
			lua_pushstring(L, str);
			return 1;
		}
	}

	lua_pushnil(L);

	return 1;
}

static int session_rx_bytes(lua_State *L)
{
	struct ap_session *ses = luaL_checkudata(L, 1, LUA_AP_SESSION);
	uint64_t gword_sz = (uint64_t)UINT32_MAX + 1;
	uint64_t bytes = gword_sz*ses->acct_input_gigawords + ses->acct_rx_bytes;

	if (!ses)
		return 0;

	lua_pushnumber(L, bytes);

	return 1;
}

static int session_tx_bytes(lua_State *L)
{
	struct ap_session *ses = luaL_checkudata(L, 1, LUA_AP_SESSION);
	uint64_t gword_sz = (uint64_t)UINT32_MAX + 1;
	uint64_t bytes = gword_sz*ses->acct_output_gigawords + ses->acct_tx_bytes;

	if (!ses)
		return 0;

	lua_pushnumber(L, bytes);

	return 1;
}


