/*
 * Copyright (C) 2017 Red Hat, Inc.
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

/* This file contains functions which are wrappers for the key exchange
 * part of TLS. They are called by the handshake functions (gnutls_handshake)
 */

#include "gnutls_int.h"
#include "handshake.h"
#include "errors.h"
#include "extensions.h"
#include <state.h>
#include <datum.h>
#include <mbuffers.h>

int _gnutls13_recv_encrypted_extensions(gnutls_session_t session)
{
	gnutls_buffer_st buf;
	int ret = 0;

	ret =
	    _gnutls_recv_handshake(session,
				   GNUTLS_HANDSHAKE_ENCRYPTED_EXTENSIONS,
				   0, &buf);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = _gnutls_parse_extensions(session, GNUTLS_EXT_ENCRYPTED, buf.data, buf.length);
	_gnutls_buffer_clear(&buf);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return ret;
}

