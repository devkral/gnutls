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
#ifndef SESSION_TICKET_H
#define SESSION_TICKET_H

struct tls13_nst_st {
	time_t ticket_timestamp;
	uint32_t ticket_lifetime;
	uint32_t ticket_age_add;
	gnutls_datum_t ticket_nonce;
	gnutls_datum_t ticket;
	gnutls_datum_t rms;
};

struct tls13_ticket_data {
	uint8_t *rms;
	unsigned rms_len;
	uint8_t *ticket_nonce;
	unsigned ticket_nonce_len;
	uint32_t ticket_age_add;
	uint32_t ticket_lifetime;
	gnutls_mac_algorithm_t kdf_id;
};

int _gnutls13_send_session_ticket(gnutls_session_t session, unsigned again);
int _gnutls13_recv_session_ticket(gnutls_session_t session,
		gnutls_buffer_st *buf, struct tls13_nst_st *ticket);

int _gnutls13_unpack_session_ticket(gnutls_session_t session,
		gnutls_datum_t *data,
		struct tls13_ticket_data *ticket_data);

int _gnutls13_session_ticket_set(gnutls_session_t session,
		struct tls13_nst_st *ticket,
		const uint8_t *rms, size_t rms_size,
		const mac_entry_st *prf);
int _gnutls13_session_ticket_get(gnutls_session_t session,
		struct tls13_nst_st *ticket);
int _gnutls13_session_ticket_peek(gnutls_session_t session,
		struct tls13_nst_st *ticket);

void _gnutls13_session_ticket_destroy(struct tls13_nst_st *ticket);
void _gnutls13_session_ticket_unset(gnutls_session_t session);

void _gnutls13_ticket_data_destroy(struct tls13_ticket_data *ticket_data);

#endif
