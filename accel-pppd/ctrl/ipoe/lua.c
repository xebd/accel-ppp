#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

/* Include the Lua API header files. */
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "events.h"
#include "log.h"
#include "utils.h"

#include "ipoe.h"

#include "memdebug.h"

#define IPOE_PACKET4 "ipoe.packet4"

static const char *conf_filename;
static int serial;
static int file_error;

static __thread lua_State *L;
static __thread int __serial;
static pthread_key_t __key;

static int packet4_hdr(lua_State *L);
static int packet4_ifname(lua_State *L);
static int packet4_option(lua_State *L);
static int packet4_options(lua_State *L);
static int packet4_agent_circuit_id(lua_State *L);
static int packet4_agent_remote_id(lua_State *L);

int luaopen_lpack(lua_State *L);

static const struct luaL_reg packet4_lib [] = {
	{"hdr", packet4_hdr},
	{"ifname", packet4_ifname},
	{"option", packet4_option},
	{"options", packet4_options},
	{"agent_circuit_id", packet4_agent_circuit_id},
	{"agent_remote_id", packet4_agent_remote_id},
	{NULL, NULL}
};

static int luaopen_packet4(lua_State *L)
{
  luaL_newmetatable(L, IPOE_PACKET4);

	lua_pushstring(L, "__index");
	lua_pushvalue(L, -2);  /* pushes the metatable */
	lua_settable(L, -3);  /* metatable.__index = metatable */


	luaI_openlib(L, NULL, packet4_lib, 0);

  luaI_openlib(L, "packet4", packet4_lib, 0);

	return 1;
}

static int packet4_hdr(lua_State *L)
{
	struct ipoe_session *ses = luaL_checkudata(L, 1, IPOE_PACKET4);
	const char *name = luaL_checkstring(L, 2);
	char str[20];
	uint8_t *ptr;

	if (!ses)
		return 0;
	
	if (!strcmp(name, "xid"))
		lua_pushinteger(L, ses->dhcpv4_request->hdr->xid);
	else if (!strcmp(name, "ciaddr")) {
		u_inet_ntoa(ses->dhcpv4_request->hdr->ciaddr, str);
		lua_pushstring(L, str);
	} else if (!strcmp(name, "giaddr")) {
		u_inet_ntoa(ses->dhcpv4_request->hdr->giaddr, str);
		lua_pushstring(L, str);
	} else if (!strcmp(name, "chaddr")) {
		ptr = ses->dhcpv4_request->hdr->chaddr;
		sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
			ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
		lua_pushstring(L, str);
	}

	return 1;
}

static int packet4_ifname(lua_State *L)
{
	struct ipoe_session *ses = luaL_checkudata(L, 1, IPOE_PACKET4);

	if (!ses)
		return 0;
	
	lua_pushstring(L, ses->serv->ifname);
	
	return 1;
}

static int packet4_option(lua_State *L)
{
	struct ipoe_session *ses = luaL_checkudata(L, 1, IPOE_PACKET4);
	int type = luaL_checkinteger(L, 2);
	struct dhcpv4_option *opt;

	list_for_each_entry(opt, &ses->dhcpv4_request->options, entry) {
		if (opt->type == type) {
			lua_pushlstring(L, (char *)opt->data, opt->len);
			return 1;
		}
	}

	lua_pushnil(L);

	return 1;
}

static int packet4_options(lua_State *L)
{
	struct ipoe_session *ses = luaL_checkudata(L, 1, IPOE_PACKET4);
	struct dhcpv4_option *opt;
	int i = 1;

	if (!ses)
		return 0;
	
	lua_newtable(L);

	list_for_each_entry(opt, &ses->dhcpv4_request->options, entry) {
		lua_pushinteger(L, opt->type);
		lua_rawseti(L, -2, i++);
	}

	return 1;
}

static int packet4_agent_circuit_id(lua_State *L)
{
	struct ipoe_session *ses = luaL_checkudata(L, 1, IPOE_PACKET4);

	if (!ses)
		return 0;
	
	if (ses->agent_circuit_id)
		lua_pushlstring(L, (char *)ses->agent_circuit_id->data, ses->agent_circuit_id->len);
	else
		lua_pushnil(L);
	
	return 1;
}

static int packet4_agent_remote_id(lua_State *L)
{
	struct ipoe_session *ses = luaL_checkudata(L, 1, IPOE_PACKET4);

	if (!ses)
		return 0;
	
	if (ses->agent_remote_id)
		lua_pushlstring(L, (char *)ses->agent_remote_id->data, ses->agent_remote_id->len);
	else
		lua_pushnil(L);
	
	return 1;
}

static void init_lua()
{
	__serial = serial;

	L = lua_open();

	luaL_openlibs(L);

	luaopen_lpack(L);
	luaopen_packet4(L);

	if (luaL_loadfile(L, conf_filename))
		goto out_err;

	if (lua_pcall(L, 0, 0, 0))
		goto out_err;

	file_error = 0;

	pthread_setspecific(__key, L);

	return;

out_err:
	file_error = 1;
	log_ppp_error("ipoe: lua: %s\n", lua_tostring(L, -1));
	lua_close(L);
	L = NULL;
}

int ipoe_lua_set_username(struct ipoe_session *ses, const char *func)
{
	if (file_error && serial == __serial)
		return -1;

	if (L && serial != __serial) {
		lua_close(L);
		init_lua();
	} else if (!L)
		init_lua();

	if (!L)
		return -1;
	
	lua_getglobal(L, func);
	lua_pushlightuserdata(L, ses);
	luaL_getmetatable(L, IPOE_PACKET4);
	lua_setmetatable(L, -2);

	if (lua_pcall(L, 1, 1, 0)) {
		log_ppp_error("ipoe: lua: %s\n", lua_tostring(L, -1));
		return -1;
	}

	if (!lua_isstring(L, -1)) {
		log_ppp_error("ipoe: lua: function '%s' must return a string\n", func);
		return -1;
	}

	ses->ses.username = _strdup(lua_tostring(L, -1));

	lua_pop(L, 1);

	return 0;
}

static void load_config()
{
	conf_filename = conf_get_opt("ipoe", "lua-file");

	serial++;
}

static void init()
{
	load_config();

	pthread_key_create(&__key, (void (*)(void *))lua_close);

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(100, init);
