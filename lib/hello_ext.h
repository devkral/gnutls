/*
 * Copyright (C) 2000-2012 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#ifndef GNUTLS_EXTENSIONS_H
#define GNUTLS_EXTENSIONS_H

#include <gnutls/gnutls.h>

/* Functions for hello extension parsing.
 */
int _gnutls_parse_hello_extensions(gnutls_session_t session,
				   gnutls_ext_flags_t msg,
				   gnutls_ext_parse_type_t parse_type,
				   const uint8_t * data, int data_size);
int _gnutls_gen_hello_extensions(gnutls_session_t session,
				 gnutls_buffer_st * extdata,
				 gnutls_ext_flags_t msg,
				 gnutls_ext_parse_type_t);
int _gnutls_hello_ext_init(void);
void _gnutls_hello_ext_deinit(void);

void _gnutls_hello_ext_sdata_deinit(gnutls_session_t session);

/* functions to be used by extensions internally
 */
void _gnutls_hello_ext_unset_sdata(gnutls_session_t session,
				    extensions_t ext);
void _gnutls_hello_ext_set_sdata(gnutls_session_t session, extensions_t ext,
				  gnutls_ext_priv_data_t);
int _gnutls_hello_ext_get_sdata(gnutls_session_t session, extensions_t ext,
				 gnutls_ext_priv_data_t *);
int _gnutls_hello_ext_get_resumed_sdata(gnutls_session_t session,
					 extensions_t ext,
					 gnutls_ext_priv_data_t * data);

/* obtain the message this extension was received at */
inline static gnutls_ext_flags_t _gnutls_ext_get_msg(gnutls_session_t session)
{
	return session->internals.ext_msg;
}

inline static void _gnutls_ext_set_msg(gnutls_session_t session, gnutls_ext_flags_t msg)
{
	session->internals.ext_msg = msg;
}

/* for session packing */
int _gnutls_hello_ext_pack(gnutls_session_t session, gnutls_buffer_st * packed);
int _gnutls_hello_ext_unpack(gnutls_session_t session,
		       gnutls_buffer_st * packed);

inline static const char *ext_msg_validity_to_str(gnutls_ext_flags_t msg)
{
	switch(msg) {
		case GNUTLS_EXT_FLAG_CLIENT_HELLO:
			return "client hello";
		case GNUTLS_EXT_FLAG_TLS12_SERVER_HELLO:
			return "TLS 1.2 server hello";
		case GNUTLS_EXT_FLAG_TLS13_SERVER_HELLO:
			return "TLS 1.3 server hello";
		case GNUTLS_EXT_FLAG_EE:
			return "encrypted extensions";
		case GNUTLS_EXT_FLAG_HRR:
			return "hello retry request";
		default:
			return "(unknown)";
	}
}

typedef struct hello_ext_entry_st {
	const char *name; /* const overriden when free_struct is set */
	unsigned free_struct;

	uint16_t tls_id;
	unsigned gid; /* gnutls internal ID */

	gnutls_ext_parse_type_t parse_type;
	unsigned validity; /* multiple items of gnutls_ext_flags_t */

	/* this function must return 0 when Not Applicable
	 * size of extension data if ok
	 * < 0 on other error.
	 */
	gnutls_ext_recv_func recv_func;

	/* this function must return 0 when Not Applicable
	 * size of extension data if ok
	 * GNUTLS_E_INT_RET_0 if extension data size is zero
	 * < 0 on other error.
	 */
	gnutls_ext_send_func send_func;

	gnutls_ext_deinit_data_func deinit_func;	/* this will be called to deinitialize
							 * internal data 
							 */
	gnutls_ext_pack_func pack_func;	/* packs internal data to machine independent format */
	gnutls_ext_unpack_func unpack_func;	/* unpacks internal data */

	/* non-zero if that extension cannot be overriden by the applications.
	 * That should be set to extensions which allocate data early, e.g., on
	 * gnutls_init(), or modify the TLS protocol in a way that the application
	 * cannot control. */
	unsigned cannot_be_overriden;
} hello_ext_entry_st;

/* Checks if the extension @id provided has been requested
 * by us (in client side). In that case it returns non-zero,
 * otherwise zero.
 */
inline static unsigned
_gnutls_hello_ext_is_present(gnutls_session_t session, extensions_t id)
{
	if (id != 0 && ((1 << id) & session->internals.used_exts))
		return 1;

	return 0;
}

/* Adds the extension we want to send in the extensions list.
 * This list is used in client side to check whether the (later) received
 * extensions are the ones we requested.
 *
 * In server side, this list is used to ensure we don't send
 * extensions that we didn't receive a corresponding value.
 *
 * Returns zero if failed, non-zero on success.
 */
inline static
unsigned _gnutls_hello_ext_save(gnutls_session_t session,
				extensions_t id,
				unsigned check_dup)
{
	if (check_dup && _gnutls_hello_ext_is_present(session, id)) {
			return 0;
	}

	session->internals.used_exts |= (1 << id);

	return 1;
}

inline static
void _gnutls_hello_ext_save_sr(gnutls_session_t session)
{
	_gnutls_hello_ext_save(session, GNUTLS_EXTENSION_SAFE_RENEGOTIATION, 1);
}

#endif
