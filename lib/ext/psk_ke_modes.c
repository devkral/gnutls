/*
 * Copyright (C) 2017 Free Software Foundation, Inc.
 *
 * Author: Ander Juaristi
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

#include "gnutls_int.h"
#include <ext/psk_ke_modes.h>

#define PSK_DHE_KE 1

static int
send_params(gnutls_buffer_t extdata, uint8_t ke_modes_value)
{
	int ret;

	ret = _gnutls_buffer_append_prefix(extdata, 8, 1);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ret = _gnutls_buffer_append_prefix(extdata, 8, ke_modes_value);
	if (ret < 0)
		return gnutls_assert_val(ret);

	return 2;
}

/*
 * We only support ECDHE-authenticated PSKs.
 * The client just sends a "psk_key_exchange_modes" extension
 * with the value one.
 */
static int
psk_ke_modes_send_params(gnutls_session_t session,
		gnutls_buffer_t extdata)
{
	int retval = 0;
	gnutls_psk_client_credentials_t cred;
	const version_entry_st *vers;

	/* Server doesn't send psk_key_exchange_modes */
	if (session->security_parameters.entity == GNUTLS_SERVER)
		return 0;

	vers = _gnutls_version_max(session);
	if (!vers || !vers->tls13_sem)
		return 0;

	cred = (gnutls_psk_client_credentials_t)
			_gnutls_get_cred(session, GNUTLS_CRD_PSK);
	if (cred == NULL)
		return 0;

	retval = send_params(extdata, PSK_DHE_KE);
	if (retval < 0)
		gnutls_assert_val(retval);
	else
		session->internals.hsk_flags |= HSK_PSK_KE_MODES_SENT;

	return retval;
}

/*
 * Since we only support ECDHE-authenticated PSKs, the server
 * just verifies that a "psk_key_exchange_modes" extension was received,
 * and that it contains the value one.
 */
static int
psk_ke_modes_recv_params(gnutls_session_t session,
		const unsigned char *data, size_t _len)
{
	uint8_t ke_modes_len;
	ssize_t len = _len;
	const version_entry_st *vers = get_version(session);
	gnutls_psk_client_credentials_t cred;

	/* Server doesn't send psk_key_exchange_modes */
	if (session->security_parameters.entity == GNUTLS_CLIENT)
		return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION);

	if (!vers || !vers->tls13_sem)
		return 0;

	cred = (gnutls_psk_client_credentials_t)_gnutls_get_cred(session, GNUTLS_CRD_PSK);
	if (cred == NULL)
		return 0;

	DECR_LEN(len, 1);
	ke_modes_len = *(data++);

	/* We only support DH-authenticated PSKs */
	if (session->internals.priorities->groups.size == 0)
		return gnutls_assert_val(0);

	if (ke_modes_len == 1 && *data != PSK_DHE_KE)
		session->internals.hsk_flags |= HSK_PSK_KE_MODES_INVALID;
	else if (ke_modes_len > 1 && (
			data[0] != PSK_DHE_KE && data[1] != PSK_DHE_KE))
		session->internals.hsk_flags |= HSK_PSK_KE_MODES_INVALID;
	else if (ke_modes_len == 0)
		return 0;

	session->internals.hsk_flags |= HSK_PSK_KE_MODES_RECEIVED;
	return 0;
}

const hello_ext_entry_st ext_psk_ke_modes = {
	.name = "PSK Key Exchange Modes",
	.tls_id = 45,
	.gid = GNUTLS_EXTENSION_PSK_KE_MODES,
	.parse_type = GNUTLS_EXT_TLS,
	.validity = GNUTLS_EXT_FLAG_CLIENT_HELLO | GNUTLS_EXT_FLAG_TLS13_SERVER_HELLO,
	.send_func = psk_ke_modes_send_params,
	.recv_func = psk_ke_modes_recv_params
};
