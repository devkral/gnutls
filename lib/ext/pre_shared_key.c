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
#include "auth/psk.h"
#include "secrets.h"
#include "tls13/psk_ext_parser.h"
#include "tls13/finished.h"
#include "tls13/session_ticket.h"
#include "auth/psk_passwd.h"
#include <ext/session_ticket.h>
#include <ext/pre_shared_key.h>
#include "tls13/psk_ext_parser.h"

typedef struct {
	struct tls13_nst_st *session_ticket;
	uint8_t *rms;
	size_t rms_size;
} psk_ext_st;

static int
compute_psk_from_ticket(const mac_entry_st *prf,
		const uint8_t *rms,
		gnutls_datum_t *nonce, gnutls_datum_t *key)
{
	int ret;
	unsigned hash_size = prf->output_size;
	char label[] = "resumption";

	key->data = gnutls_malloc(hash_size);
	key->size = hash_size;
	if (key->data == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	ret = _tls13_expand_secret2(prf,
			label, strlen(label),
			nonce->data, nonce->size,
			rms,
			hash_size,
			key->data);
	if (ret < 0) {
		_gnutls_free_datum(key);
		return gnutls_assert_val(ret);
	}

	return ret;
}

static int
compute_binder_key(const mac_entry_st *prf,
		const uint8_t *key, size_t keylen,
		void *out)
{
	int ret;
	char label[] = "ext_binder";
	size_t label_len = sizeof(label) - 1;
	uint8_t tmp_key[MAX_HASH_SIZE];

	/* Compute HKDF-Extract(0, psk) */
	ret = _tls13_init_secret2(prf, key, keylen, tmp_key);
	if (ret < 0)
		return ret;

	/* Compute Derive-Secret(secret, label, transcript_hash) */
	ret = _tls13_derive_secret2(prf,
			label, label_len,
			NULL, 0,
			tmp_key,
			out);
	if (ret < 0)
		return ret;

	return 0;
}

static int
compute_psk_binder(unsigned entity,
		const mac_entry_st *prf, unsigned binders_length, unsigned hash_size,
		int exts_length, int ext_offset, unsigned displacement,
		const gnutls_datum_t *psk, const gnutls_datum_t *client_hello,
		void *out)
{
	int ret;
	unsigned extensions_len_pos;
	gnutls_buffer_st handshake_buf;
	uint8_t binder_key[MAX_HASH_SIZE];

	_gnutls_buffer_init(&handshake_buf);

	if (entity == GNUTLS_CLIENT) {
		if (displacement >= client_hello->size) {
			ret = GNUTLS_E_INTERNAL_ERROR;
			goto error;
		}

		ret = gnutls_buffer_append_data(&handshake_buf,
				(const void *) (client_hello->data + displacement),
				client_hello->size - displacement);
		if (ret < 0) {
			gnutls_assert();
			goto error;
		}

		ext_offset -= displacement;
		if (ext_offset <= 0) {
			ret = GNUTLS_E_INTERNAL_ERROR;
			goto error;
		}

		/* This is a ClientHello message */
		handshake_buf.data[0] = GNUTLS_HANDSHAKE_CLIENT_HELLO;

		/*
		 * At this point we have not yet added the binders to the ClientHello,
		 * but we have to overwrite the size field, pretending as if binders
		 * of the correct length were present.
		 */
		_gnutls_write_uint24(handshake_buf.length + binders_length - 2, &handshake_buf.data[1]);
		_gnutls_write_uint16(handshake_buf.length + binders_length - ext_offset,
				&handshake_buf.data[ext_offset]);

		extensions_len_pos = handshake_buf.length - exts_length - 2;
		_gnutls_write_uint16(exts_length + binders_length + 2,
				&handshake_buf.data[extensions_len_pos]);
	} else {
		gnutls_buffer_append_data(&handshake_buf,
				(const void *) client_hello->data,
				client_hello->size - binders_length - 3);
	}

	ret = compute_binder_key(prf,
			psk->data, psk->size,
			binder_key);
	if (ret < 0)
		goto error;

	ret = _gnutls13_compute_finished(prf,
			binder_key, hash_size,
			&handshake_buf,
			out);
	if (ret < 0)
		goto error;

	_gnutls_buffer_clear(&handshake_buf);
	return 0;

error:
	_gnutls_buffer_clear(&handshake_buf);
	return gnutls_assert_val(ret);
}

static int get_credentials(gnutls_session_t session,
		const gnutls_psk_client_credentials_t cred,
		gnutls_datum_t *username, gnutls_datum_t *key)
{
	int ret, retval = 0;
	char *username_str = NULL;

	if (cred->get_function) {
		ret = cred->get_function(session, &username_str, key);
		if (ret < 0)
			return gnutls_assert_val(ret);

		username->data = (uint8_t *) username_str;
		username->size = strlen(username_str);

		retval = username->size;
	} else if (cred->username.data != NULL && cred->key.data != NULL) {
		username->size = cred->username.size;
		if (username->size > 0) {
			username->data = gnutls_malloc(username->size);
			if (!username->data)
				return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
			memcpy(username->data, cred->username.data, username->size);
		}

		key->size = cred->key.size;
		if (key->size > 0) {
			key->data = gnutls_malloc(key->size);
			if (!key->data) {
				_gnutls_free_datum(username);
				return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
			}
			memcpy(key->data, cred->key.data, key->size);
		}

		retval = username->size;
	}

	return retval;
}

static int
client_send_params(gnutls_session_t session,
		gnutls_buffer_t extdata,
		const gnutls_psk_client_credentials_t cred)
{
	int ret = 0, extdata_len = 0, ext_offset = 0;
	uint8_t binder_value[MAX_HASH_SIZE];
	size_t length, pos;
	const mac_entry_st *prf = NULL;
	unsigned hash_size = 0;
	struct tls13_nst_st ticket;
	const uint8_t *rms = NULL;
	time_t cur_time;
	int ticket_age;
	uint32_t ob_ticket_age = 0;
	gnutls_datum_t username = { NULL, 0 }, key = { NULL, 0 },
			client_hello = { NULL, 0 };

	memset(&ticket, 0, sizeof(struct tls13_nst_st));

	if (cred) {
		prf = _gnutls_mac_to_entry(cred->tls13_binder_algo);
		hash_size = _gnutls_mac_get_algo_len(prf);
		if (prf == NULL || hash_size == 0 || hash_size > 255)
			return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

		ret = get_credentials(session, cred, &username, &key);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}

	/* No out-of-band PSKs - let's see if we have a session ticket to send */
	if (prf == NULL && session->internals.session_ticket_enable) {
		ret = _gnutls13_session_ticket_get(session, &ticket);
		if (ret > 0) {
			/* We found a session ticket */
			prf = _gnutls_mac_to_entry(session->key.proto.tls13.kdf_original);
			hash_size = _gnutls_mac_get_algo_len(prf);
			if (unlikely(prf == NULL || hash_size == 0)) {
				_gnutls13_session_ticket_unset(session);
				ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
				goto cleanup;
			}

			/* Check whether the ticket is stale */
			cur_time = time(NULL);
			ticket_age = cur_time - ticket.ticket_timestamp;
			if (ticket_age < 0 || ticket_age > cur_time) {
				_gnutls13_session_ticket_unset(session);
				ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
				goto cleanup;
			}
			if ((unsigned int) ticket_age > ticket.ticket_lifetime) {
				_gnutls13_session_ticket_unset(session);
				ret = 0;
				goto cleanup;
			}

			username.data = ticket.ticket.data;
			username.size = ticket.ticket.size;

			rms = session->key.proto.tls13.ap_rms_original.data;
			ret = compute_psk_from_ticket(prf,
					rms,
					&ticket.ticket_nonce, &key);
			if (ret < 0) {
				_gnutls13_session_ticket_unset(session);
				gnutls_assert();
				goto cleanup;
			}

			/* Calculate obfuscated ticket age, in milliseconds, mod 2^32 */
			ob_ticket_age = (ticket_age * 1000 + ticket.ticket_age_add) % 4294967296;
		}
	}

	/* No credentials - this extension is not applicable */
	if (prf == NULL) {
		ret = 0;
		goto cleanup;
	}

	/* Make some room for the identities length (16 bits) */
	pos = extdata->length;
	ret = _gnutls_buffer_append_prefix(extdata, 16, 0);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	extdata_len += 2;

	if (username.size == 0 || username.size > 65536) {
		ret = gnutls_assert_val(GNUTLS_E_INVALID_PASSWORD);
		goto cleanup;
	}

	if ((ret = _gnutls_buffer_append_data_prefix(extdata, 16,
			username.data, username.size)) < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}
	/* Obfuscated ticket age */
	if ((ret = _gnutls_buffer_append_prefix(extdata, 32, ob_ticket_age)) < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}
	/* Total length appended is the length of the data, plus six octets */
	length = (username.size + 6);

	_gnutls_write_uint16(length, &extdata->data[pos]);
	extdata_len += length;

	ext_offset = _gnutls_ext_get_extensions_offset(session);

	/* Add the size of the binder (we only have one) */
	length = (hash_size + 1);

	/* Compute the binders */
	client_hello.data = extdata->data;
	client_hello.size = extdata->length;

	ret = compute_psk_binder(GNUTLS_CLIENT, prf,
			length, hash_size, extdata_len, ext_offset, sizeof(mbuffer_st),
			&key, &client_hello,
			binder_value);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	/* Now append the binders */
	ret = _gnutls_buffer_append_prefix(extdata, 16, length);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	extdata_len += 2;

	_gnutls_buffer_append_prefix(extdata, 8, hash_size);
	_gnutls_buffer_append_data(extdata, binder_value, hash_size);

	extdata_len += (hash_size + 1);

	/* Reference the selected pre-shared key */
	session->key.proto.tls13.psk = key.data;
	session->key.proto.tls13.psk_size = key.size;
	ret = extdata_len;

cleanup:
	_gnutls13_session_ticket_destroy(&ticket);
	_gnutls_free_datum(&username);
	return ret;
}

static int
server_send_params(gnutls_session_t session, gnutls_buffer_t extdata)
{
	int ret;

	if (!(session->internals.hsk_flags & HSK_PSK_SELECTED))
		return 0;

	ret = _gnutls_buffer_append_prefix(extdata, 16,
			session->key.proto.tls13.psk_index);
	if (ret < 0)
		return gnutls_assert_val(ret);

	return 2;
}

static int server_recv_params(gnutls_session_t session,
		const unsigned char *data, long len,
		const gnutls_psk_server_credentials_t pskcred)
{
	int ret;
	const mac_entry_st *prf = NULL;
	gnutls_datum_t full_client_hello;
	uint8_t binder_value[MAX_HASH_SIZE];
	int psk_index = -1;
	gnutls_datum_t key = { NULL, 0 };
	gnutls_datum_t binder_recvd = { NULL, 0 };
	gnutls_datum_t ticket_bytes = { NULL, 0 };
	gnutls_datum_t ticket_nonce = { NULL, 0 };
	int ticket_age;
	struct tls13_ticket_data ticket_data;
	unsigned hash_size;
	psk_ext_parser_t psk_parser;
	struct psk_st psk;
	enum {
		PSK = 1,
		TICKET
	} psk_kind = 0;

	ret = _gnutls13_psk_ext_parser_init(&psk_parser, data, len);
	if (ret == 0) {
		/* No PSKs advertised by client */
		return 0;
	} else if (ret < 0) {
		return gnutls_assert_val(ret);
	}

	if (_gnutls13_psk_ext_parser_next_psk(psk_parser, &psk) >= 0) {
		ticket_bytes.data = psk.identity.data;
		ticket_bytes.size = psk.identity.size;

		if (_gnutls13_unpack_session_ticket(session, &ticket_bytes, &ticket_data) > 0) {
			psk_index = psk.selected_index;
			prf = _gnutls_mac_to_entry(ticket_data.kdf_id);
			if (!prf) {
				_gnutls13_ticket_data_destroy(&ticket_data);
				return gnutls_assert_val(GNUTLS_E_INVALID_SESSION);
			}

			session->internals.tls13_session_ticket_renew = 0;

			/* Check whether ticket is stale or not */
			ticket_age = psk.ob_ticket_age - ticket_data.ticket_age_add;
			if (ticket_age < 0) {
				session->internals.tls13_session_ticket_renew = 1;
				_gnutls13_ticket_data_destroy(&ticket_data);
				return 0;
			}
			if ((unsigned int) (ticket_age / 1000) > ticket_data.ticket_lifetime) {
				session->internals.tls13_session_ticket_renew = 1;
				_gnutls13_ticket_data_destroy(&ticket_data);
				return 0;
			}

			ticket_nonce.data = ticket_data.ticket_nonce;
			ticket_nonce.size = ticket_data.ticket_nonce_len;
			ret = compute_psk_from_ticket(prf, ticket_data.rms, &ticket_nonce, &key);
			if (ret < 0) {
				session->internals.tls13_session_ticket_renew = 1;
				_gnutls13_ticket_data_destroy(&ticket_data);
				return gnutls_assert_val(GNUTLS_E_INSUFFICIENT_CREDENTIALS);
			}

			_gnutls13_ticket_data_destroy(&ticket_data);
			psk_kind = TICKET;
		}

		/* _gnutls_psk_pwd_find_entry() expects 0-terminated identities */
		if (psk.identity.size > 0 && psk_kind == 0) {
			char identity_str[psk.identity.size + 1];

			memcpy(identity_str, psk.identity.data, psk.identity.size);
			identity_str[psk.identity.size] = 0;

			ret = _gnutls_psk_pwd_find_entry(session, identity_str, &key);
			if (ret == 0) {
				psk_kind = PSK;
				psk_index = psk.selected_index;
				prf = _gnutls_mac_to_entry(pskcred->tls13_binder_algo);
			}

			session->internals.tls13_session_ticket_renew = 0;
		}
	}

	if (psk_index < 0)
		return 0;

	/* Are session tickets enabled? */
	if (psk_kind == TICKET && !session->internals.session_ticket_enable)
		return 0;

	ret = _gnutls13_psk_ext_parser_find_binder(psk_parser, psk_index,
			&binder_recvd);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ret = _gnutls13_psk_ext_parser_deinit(&psk_parser,
			&data, (size_t *) &len);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	/* Get full ClientHello */
	if (!_gnutls_ext_get_full_client_hello(session, &full_client_hello)) {
		ret = 0;
		goto cleanup;
	}

	/* Compute the binder value for this PSK */
	if (!prf) {
		ret = gnutls_assert_val(GNUTLS_E_INSUFFICIENT_CREDENTIALS);
		goto cleanup;
	}
	hash_size = prf->output_size;
	compute_psk_binder(GNUTLS_SERVER, prf, hash_size, hash_size, 0, 0, 0,
			&key, &full_client_hello,
			binder_value);
	if (_gnutls_mac_get_algo_len(prf) != binder_recvd.size ||
			safe_memcmp(binder_value, binder_recvd.data, binder_recvd.size)) {
		ret = gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
		goto cleanup;
	}

	session->internals.hsk_flags |= HSK_PSK_SELECTED;
	/* Reference the selected pre-shared key */
	session->key.proto.tls13.psk = key.data;
	session->key.proto.tls13.psk_size = key.size;
	session->key.proto.tls13.psk_index = 0;
	_gnutls_free_datum(&binder_recvd);

	return 0;

cleanup:
	_gnutls_free_datum(&binder_recvd);

	return ret;
}

static int client_recv_params(gnutls_session_t session,
		const unsigned char *data, size_t len)
{
	uint16_t selected_identity = _gnutls_read_uint16(data);
	if (selected_identity == 0)
		session->internals.hsk_flags |= HSK_PSK_SELECTED;
	return 0;
}

/*
 * Return values for this function:
 *  -  0 : Not applicable.
 *  - >0 : Ok. Return size of extension data.
 *  - GNUTLS_E_INT_RET_0 : Size of extension data is zero.
 *  - <0 : There's been an error.
 *
 * In the client, generates the PskIdentity and PskBinderEntry messages.
 *
 *      PskIdentity identities<7..2^16-1>;
 *      PskBinderEntry binders<33..2^16-1>;
 *
 *      struct {
 *          opaque identity<1..2^16-1>;
 *          uint32 obfuscated_ticket_age;
 *      } PskIdentity;
 *
 *      opaque PskBinderEntry<32..255>;
 *
 * The server sends the selected identity, which is a zero-based index
 * of the PSKs offered by the client:
 *
 *      struct {
 *          uint16 selected_identity;
 *      } PreSharedKeyExtension;
 */
static int _gnutls_psk_send_params(gnutls_session_t session,
		gnutls_buffer_t extdata)
{
	gnutls_psk_client_credentials_t cred = NULL;

	if (session->security_parameters.entity == GNUTLS_CLIENT) {
		if (session->internals.hsk_flags & HSK_PSK_KE_MODES_SENT) {
			cred = (gnutls_psk_client_credentials_t)
					_gnutls_get_cred(session, GNUTLS_CRD_PSK);
		}

		return client_send_params(session, extdata, cred);
	} else {
		if (session->internals.hsk_flags & HSK_PSK_KE_MODES_RECEIVED)
			return server_send_params(session, extdata);
		else
			return 0;
	}
}

/*
 * Return values for this function:
 *  -  0 : Not applicable.
 *  - >0 : Ok. Return size of extension data.
 *  - <0 : There's been an error.
 */
static int _gnutls_psk_recv_params(gnutls_session_t session,
		const unsigned char *data, size_t len)
{
	gnutls_psk_server_credentials_t pskcred;

	if (session->security_parameters.entity == GNUTLS_CLIENT) {
		if (session->internals.hsk_flags & HSK_PSK_KE_MODES_SENT)
			return client_recv_params(session, data, len);
		else
			return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION);
	} else {
		if (session->internals.hsk_flags & HSK_PSK_KE_MODES_RECEIVED) {
			if (session->internals.hsk_flags & HSK_PSK_KE_MODES_INVALID) {
				/* We received a "psk_ke_modes" extension, but with a value we don't support */
				return 0;
			}

			pskcred = (gnutls_psk_server_credentials_t)
					_gnutls_get_cred(session, GNUTLS_CRD_PSK);

			return server_recv_params(session, data, len, pskcred);
		} else {
			return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET);
		}
	}
}

const hello_ext_entry_st ext_pre_shared_key = {
	.name = "Pre Shared Key",
	.tls_id = 41,
	.gid = GNUTLS_EXTENSION_PRE_SHARED_KEY,
	.parse_type = GNUTLS_EXT_TLS,
	.validity = GNUTLS_EXT_FLAG_CLIENT_HELLO | GNUTLS_EXT_FLAG_TLS13_SERVER_HELLO,
	.send_func = _gnutls_psk_send_params,
	.recv_func = _gnutls_psk_recv_params
};
