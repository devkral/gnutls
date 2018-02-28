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
#include <time.h>
#include "gnutls_int.h"
#include "errors.h"
#include "extv.h"
#include "handshake.h"
#include "mbuffers.h"
#include "ext/pre_shared_key.h"
#include "ext/session_ticket.h"
#include "tls13/session_ticket.h"
#include "auth/cert.h"

#define IV_SIZE 16
#define BLOCK_SIZE 16
#define CIPHER GNUTLS_CIPHER_AES_256_CBC

#define MAC_ALGO GNUTLS_MAC_SHA1

static int parse_nst_extension(void *ctx, uint16_t tls_id, const uint8_t *data, int data_size);

static int pack_ticket(struct tls13_ticket_data *ticket_data,
		gnutls_datum_t *state)
{
	unsigned char *p;

	state->size = sizeof(uint16_t) +
			sizeof(uint32_t) * 3 +
			ticket_data->rms_len +
			sizeof(uint32_t) +
			ticket_data->ticket_nonce_len;
	state->data = gnutls_malloc(state->size);
	if (!state->data)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	p = state->data;

	_gnutls_write_uint16(ticket_data->kdf_id, p);
	p += sizeof(uint16_t);
	_gnutls_write_uint32(ticket_data->ticket_age_add, p);
	p += sizeof(uint32_t);
	_gnutls_write_uint32(ticket_data->ticket_lifetime, p);
	p += sizeof(uint32_t);
	_gnutls_write_uint32(ticket_data->rms_len, p);
	p += sizeof(uint32_t);
	memcpy(p, ticket_data->rms, ticket_data->rms_len);
	p += ticket_data->rms_len;
	_gnutls_write_uint32(ticket_data->ticket_nonce_len, p);
	p += sizeof(uint32_t);
	memcpy(p, ticket_data->ticket_nonce, ticket_data->ticket_nonce_len);

	return 0;
}

static int unpack_ticket(gnutls_datum_t *state,
		struct tls13_ticket_data *data)
{
	int retval, kdf;
	uint32_t ticket_age_add, ticket_lifetime;
	gnutls_datum_t rms = { NULL, 0 }, ticket_nonce = { NULL, 0 };
	unsigned char *p;
	size_t expected_len = sizeof(uint16_t) + sizeof(uint32_t) * 3;

	if (unlikely(state == NULL || data == NULL))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	if (state->size <= expected_len)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	p = state->data;

	kdf = _gnutls_read_uint16(p);
	p += sizeof(uint16_t);

	/* Check if the MAC ID we got is valid */
	if (_gnutls_mac_to_entry(kdf) == NULL)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	/* Read the ticket age add and the ticket lifetime */
	ticket_age_add = _gnutls_read_uint32(p);
	p += sizeof(uint32_t);

	ticket_lifetime = _gnutls_read_uint32(p);
	p += sizeof(uint32_t);

	/*
	 * Check if the whole ticket is large enough,
	 * and read the resumption master secret
	 */
	rms.size = (unsigned) _gnutls_read_uint32(p);
	p += sizeof(uint32_t);

	expected_len += rms.size;

	if (state->size < expected_len)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	rms.data = gnutls_malloc(rms.size);
	if (!rms.data) {
		retval = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto error;
	}
	memcpy(rms.data, p, rms.size);
	p += rms.size;

	/* Read the ticket nonce */
	ticket_nonce.size = (unsigned) _gnutls_read_uint32(p);
	p += sizeof(uint32_t);

	expected_len += ticket_nonce.size;

	if (state->size < ticket_nonce.size) {
		retval = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
		goto error;
	}

	ticket_nonce.data = gnutls_malloc(ticket_nonce.size);
	if (!ticket_nonce.data) {
		retval = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto error;
	}
	memcpy(ticket_nonce.data, p, ticket_nonce.size);

	/* No errors - Now return all the data to the caller */
	data->kdf_id = (gnutls_mac_algorithm_t) kdf;
	data->rms = rms.data;
	data->rms_len = rms.size;
	data->ticket_nonce = ticket_nonce.data;
	data->ticket_nonce_len = ticket_nonce.size;
	data->ticket_age_add = ticket_age_add;
	data->ticket_lifetime = ticket_lifetime;

	return 0;

error:
	_gnutls_free_datum(&rms);
	_gnutls_free_datum(&ticket_nonce);
	return retval;
}

static int digest_ticket(const gnutls_datum_t *key, struct ticket_st *ticket,
		uint8_t *digest)
{
	int ret;
	mac_hd_st digest_hd;
	uint16_t length16;

	ret = _gnutls_mac_init(&digest_hd, mac_to_entry(MAC_ALGO),
			key->data, key->size);
	if (ret < 0)
		return gnutls_assert_val(ret);

	length16 = _gnutls_conv_uint16(ticket->encrypted_state_len);

	_gnutls_mac(&digest_hd, ticket->key_name, KEY_NAME_SIZE);
	_gnutls_mac(&digest_hd, ticket->IV, IV_SIZE);
	_gnutls_mac(&digest_hd, &length16, 2);
	_gnutls_mac(&digest_hd, ticket->encrypted_state, ticket->encrypted_state_len);

	_gnutls_mac_deinit(&digest_hd, digest);

	return 0;
}

static int encrypt_ticket(gnutls_session_t session,
		gnutls_datum_t *state, struct ticket_st *enc_ticket)
{
	int ret;
	cipher_hd_st cipher_hd;
	gnutls_datum_t key, IV;
	gnutls_datum_t encrypted_state = {NULL, 0};
	gnutls_datum_t mac_secret;
	uint8_t iv[IV_SIZE];
	uint32_t t;

	memset(&cipher_hd, 0, sizeof(cipher_hd_st));

	key.data = (void *) &session->key.session_ticket_key[KEY_POS];
	key.size = CIPHER_KEY_SIZE;
	IV.data = iv;
	IV.size = IV_SIZE;

	/* Generate an IV */
	t = gnutls_time(0);
	memcpy(iv, &t, 4);
	ret = gnutls_rnd(GNUTLS_RND_NONCE, iv + 4, IV_SIZE + 4);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	/* Encrypt */
	ret = _gnutls_cipher_init(&cipher_hd, cipher_to_entry(CIPHER),
			&key, &IV, 1);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	encrypted_state.size = ((state->size + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
	encrypted_state.data = gnutls_calloc(1, encrypted_state.size);
	if (!encrypted_state.data) {
		gnutls_assert();
		ret = GNUTLS_E_MEMORY_ERROR;
		goto cleanup;
	}
	memcpy(encrypted_state.data, state->data, state->size);

	ret = _gnutls_cipher_encrypt(&cipher_hd,
			encrypted_state.data, encrypted_state.size);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	/* Compute the MAC */
	memcpy(enc_ticket->key_name, &session->key.session_ticket_key[NAME_POS], KEY_NAME_SIZE);
	memcpy(enc_ticket->IV, IV.data, IV.size);
	enc_ticket->encrypted_state = encrypted_state.data;
	enc_ticket->encrypted_state_len = encrypted_state.size;

	mac_secret.data = &session->key.session_ticket_key[MAC_SECRET_POS];
	mac_secret.size = MAC_SECRET_SIZE;

	ret = digest_ticket(&mac_secret, enc_ticket, enc_ticket->mac);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	encrypted_state.data = NULL;
	ret = 0;

cleanup:
	_gnutls_cipher_deinit(&cipher_hd);
	_gnutls_free_datum(&encrypted_state);
	return ret;
}

static int decrypt_ticket(gnutls_session_t session,
		struct ticket_st *enc_ticket, gnutls_datum_t *state)
{
	int ret;
	cipher_hd_st cipher_hd;
	gnutls_datum_t key, IV, mac_secret;
	uint8_t cmac[MAC_SIZE];

	/* Check the integrity of ticket */
	mac_secret.data = (void *) &session->key.session_ticket_key[MAC_SECRET_POS];
	mac_secret.size = MAC_SECRET_SIZE;
	ret = digest_ticket(&mac_secret, enc_ticket, cmac);
	if (ret < 0)
		return gnutls_assert_val(ret);

	if (memcmp(enc_ticket->mac, cmac, MAC_SIZE))
		return gnutls_assert_val(GNUTLS_E_DECRYPTION_FAILED);
	if (enc_ticket->encrypted_state_len % BLOCK_SIZE != 0)
		return gnutls_assert_val(GNUTLS_E_DECRYPTION_FAILED);

	key.data = (void *) &session->key.session_ticket_key[KEY_POS];
	key.size = CIPHER_KEY_SIZE;
	IV.data = enc_ticket->IV;
	IV.size = IV_SIZE;

	ret = _gnutls_cipher_init(&cipher_hd, cipher_to_entry(CIPHER),
			&key, &IV, 0);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ret = _gnutls_cipher_decrypt(&cipher_hd,
			enc_ticket->encrypted_state, enc_ticket->encrypted_state_len);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	state->data = enc_ticket->encrypted_state;
	state->size = enc_ticket->encrypted_state_len;

	ret = 0;
cleanup:
	_gnutls_cipher_deinit(&cipher_hd);
	return ret;
}

static int generate_session_ticket(gnutls_session_t session, struct tls13_nst_st *ticket)
{
	int ret;
	unsigned char *p;
	gnutls_datum_t state = { NULL, 0 };
	struct ticket_st encrypted_ticket;
	/* This is the resumption master secret */
	const uint8_t *rms = session->key.proto.tls13.ap_rms;
	unsigned rms_len = session->key.proto.tls13.temp_secret_size;
	gnutls_mac_algorithm_t kdf_id;
	struct tls13_ticket_data tdata;

	memset(&encrypted_ticket, 0, sizeof(struct ticket_st));

	/* Generate a random 128-bit ticket nonce */
	ticket->ticket_nonce.size = 16;
	ticket->ticket_nonce.data = gnutls_malloc(ticket->ticket_nonce.size);
	if (ticket->ticket_nonce.data == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	if ((ret = gnutls_rnd(GNUTLS_RND_NONCE,
			ticket->ticket_nonce.data, ticket->ticket_nonce.size)) < 0)
		return gnutls_assert_val(ret);
	if ((ret = gnutls_rnd(GNUTLS_RND_RANDOM, &ticket->ticket_age_add, sizeof(uint32_t))) < 0)
		return gnutls_assert_val(ret);

	/* Set ticket lifetime to 1 day (86400 seconds) */
	ticket->ticket_lifetime = 86400;
	kdf_id = session->security_parameters.cs->prf;

	/* Encrypt the ticket and place the result in ticket->ticket */
	tdata.rms = (uint8_t *) rms;
	tdata.rms_len = rms_len;
	tdata.ticket_nonce = ticket->ticket_nonce.data;
	tdata.ticket_nonce_len = ticket->ticket_nonce.size;
	tdata.kdf_id = kdf_id;
	tdata.ticket_age_add = ticket->ticket_age_add;
	tdata.ticket_lifetime = ticket->ticket_lifetime;
	ret = pack_ticket(&tdata, &state);
	if (ret < 0)
		return gnutls_assert_val(ret);
	ret = encrypt_ticket(session, &state, &encrypted_ticket);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ticket->ticket.size = KEY_NAME_SIZE +
			IV_SIZE +
			MAC_SIZE +
			sizeof(uint16_t) +
			encrypted_ticket.encrypted_state_len;
	ticket->ticket.data = gnutls_calloc(1, ticket->ticket.size);
	if (!ticket->ticket.data) {
		_gnutls_free_datum(&ticket->ticket_nonce);
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
	}

	p = ticket->ticket.data;

	memcpy(p, encrypted_ticket.key_name, KEY_NAME_SIZE);
	p += KEY_NAME_SIZE;
	memcpy(p, encrypted_ticket.IV, IV_SIZE);
	p += IV_SIZE;
	_gnutls_write_uint16(encrypted_ticket.encrypted_state_len, p);
	p += 2;
	memcpy(p, encrypted_ticket.encrypted_state,
			encrypted_ticket.encrypted_state_len);
	p += encrypted_ticket.encrypted_state_len;
	gnutls_free(encrypted_ticket.encrypted_state);
	memcpy(p, encrypted_ticket.mac, MAC_SIZE);
	p += MAC_SIZE;

	return 0;
}

int _gnutls13_send_session_ticket(gnutls_session_t session, unsigned again)
{
	int ret;
	mbuffer_st *bufel = NULL;
	struct tls13_nst_st ticket;
	uint16_t ticket_len;
	uint8_t *data = NULL, *p;
	int data_size = 0;

	/* Client does not send a NewSessionTicket */
	if (unlikely(session->security_parameters.entity == GNUTLS_CLIENT))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
	/* Session resumption has not been enabled */
	if (!session->internals.session_ticket_enable)
		return 0;

	memset(&ticket, 0, sizeof(struct tls13_nst_st));

	if (again == 0) {
	//	ret = _gnutls13_session_ticket_get(session, &ticket);
		ret = generate_session_ticket(session, &ticket);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ticket_len = sizeof(uint32_t) +		/* ticket_lifetime */
				sizeof(uint32_t) +	/* ticket_age_add */
				ticket.ticket_nonce.size + 1 +
				ticket.ticket.size + 2 +
				2;			/* extensions length */
		bufel = _gnutls_handshake_alloc(session, ticket_len);
		if (bufel == NULL) {
			ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
			goto cleanup;
		}

		data = _mbuffer_get_udata_ptr(bufel);
		p = data;

		/* append ticket_lifetime */
		_gnutls_write_uint32(ticket.ticket_lifetime, p);
		p += 4;
		/* append ticket_age_add */
		_gnutls_write_uint32(ticket.ticket_age_add, p);
		p += 4;
		/* append ticket_nonce */
		*p = (uint8_t) ticket.ticket_nonce.size;
		p++;
		memcpy(p, ticket.ticket_nonce.data, ticket.ticket_nonce.size);
		p += ticket.ticket_nonce.size;
		/* append ticket */
		_gnutls_write_uint16(ticket.ticket.size, p);
		p += 2;
		memcpy(p, ticket.ticket.data, ticket.ticket.size);
		p += ticket.ticket.size;

		/* No extensions */
		_gnutls_write_uint16(0, p);
		p += 2;

		data_size = p - data;
	}

cleanup:
	if (ret == 0) {
		/* No errors - send the packet */
		ret = _gnutls_send_handshake(session, data_size ? bufel : NULL,
				GNUTLS_HANDSHAKE_NEW_SESSION_TICKET);
	} else {
		_mbuffer_xfree(&bufel);
	}

	if (ticket.ticket.data)
		gnutls_free(ticket.ticket.data);
	if (ticket.ticket_nonce.data)
		gnutls_free(ticket.ticket_nonce.data);

	return ret;
}

int _gnutls13_recv_session_ticket(gnutls_session_t session, gnutls_buffer_st *buf,
		struct tls13_nst_st *ticket)
{
	int ret;

	if (unlikely(buf == NULL || ticket == NULL))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	_gnutls_handshake_log("HSK[%p]: parsing session ticket message\n", session);

	/* ticket_lifetime */
	ret = _gnutls_buffer_pop_prefix32(buf, (size_t *) &ticket->ticket_lifetime, 0);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	/* ticket_age_add */
	ret = _gnutls_buffer_pop_prefix32(buf, (size_t *) &ticket->ticket_age_add, 0);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = _gnutls_buffer_pop_datum_prefix8(buf, &ticket->ticket_nonce);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = _gnutls_buffer_pop_datum_prefix16(buf, &ticket->ticket);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = _gnutls_extv_parse(NULL, parse_nst_extension, buf->data, buf->length);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	/* Set the ticket timestamp */
	ticket->ticket_timestamp = time(NULL);

	ret = 0;
cleanup:

	return ret;
}

/*
 * Parse the ticket in 'ticket' and return the resumption master secret
 * and the KDF ID associated to it.
 */
int _gnutls13_unpack_session_ticket(gnutls_session_t session,
		gnutls_datum_t *data,
		struct tls13_ticket_data *ticket_data)
{
	int ret;
	const unsigned char *p = data->data;
	ssize_t data_size = data->size;
	struct ticket_st ticket;
	gnutls_datum_t decrypted;

	if (unlikely(data == NULL || ticket_data == NULL))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
	if (data_size == 0)
		return 0;

	memset(&ticket, 0, sizeof(struct ticket_st));
	memset(&decrypted, 0, sizeof(gnutls_datum_t));

	/* Parse the ticket fields.
	 * Format:
	 *  Key name
	 *  IV
	 *  data length
	 *  encrypted data
	 *  MAC
	 */
	DECR_LEN(data_size, KEY_NAME_SIZE);
	memcpy(ticket.key_name, p, KEY_NAME_SIZE);
	p += KEY_NAME_SIZE;

	if (memcmp(ticket.key_name,
			&session->key.session_ticket_key[NAME_POS],
			KEY_NAME_SIZE)) {
		session->internals.session_ticket_renew = 1;
		return 0;
	}

	DECR_LEN(data_size, IV_SIZE);
	memcpy(ticket.IV, p, IV_SIZE);
	p += IV_SIZE;

	DECR_LEN(data_size, 2);
	ticket.encrypted_state_len = _gnutls_read_uint16(p);
	p += 2;

	ticket.encrypted_state = gnutls_malloc(ticket.encrypted_state_len);
	if (!ticket.encrypted_state)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	DECR_LEN(data_size, ticket.encrypted_state_len);
	memcpy(ticket.encrypted_state, p, ticket.encrypted_state_len);
	p += ticket.encrypted_state_len;

	DECR_LEN(data_size, MAC_SIZE);
	memcpy(ticket.mac, p, MAC_SIZE);

	/* Check MAC and decrypt ticket */
	ret = decrypt_ticket(session, &ticket, &decrypted);
	/* Do not free, as the ticket is decrypted in-place */
//	gnutls_free(ticket.encrypted_state);

	if (ret < 0) {
		session->internals.session_ticket_renew = 1;
		return 0;
	}

	/* Return ticket parameters */
	ret = unpack_ticket(&decrypted, ticket_data);
	if (ret < 0) {
		session->internals.session_ticket_renew = 1;
		return 0;
	}

	return decrypted.size;
}

static int parse_nst_extension(void *ctx, uint16_t tls_id, const uint8_t *data, int data_size)
{
	/* ignore all extensions */
	return 0;
}

static int copy_ticket(struct tls13_nst_st *src, struct tls13_nst_st *dst)
{
	dst->ticket_lifetime = src->ticket_lifetime;
	dst->ticket_age_add = src->ticket_age_add;
	dst->ticket_timestamp = src->ticket_timestamp;

	if (src->ticket_nonce.size > 0) {
		dst->ticket_nonce.data = gnutls_malloc(src->ticket_nonce.size);
		if (dst->ticket_nonce.data == NULL)
			return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		dst->ticket_nonce.size = src->ticket_nonce.size;
		memcpy(dst->ticket_nonce.data, src->ticket_nonce.data, src->ticket_nonce.size);
	}

	if (src->ticket.size > 0) {
		dst->ticket.data = gnutls_malloc(src->ticket.size);
		if (dst->ticket.data == NULL)
			return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		dst->ticket.size = src->ticket.size;
		memcpy(dst->ticket.data, src->ticket.data, src->ticket.size);
	}

	return 0;
}

void _gnutls13_session_ticket_destroy(struct tls13_nst_st *ticket)
{
	if (ticket) {
		_gnutls_free_datum(&ticket->ticket);
		_gnutls_free_datum(&ticket->ticket_nonce);
		_gnutls_free_datum(&ticket->rms);
		memset(ticket, 0, sizeof(struct tls13_nst_st));
	}
}

void _gnutls13_ticket_data_destroy(struct tls13_ticket_data *ticket_data)
{
	if (ticket_data) {
		gnutls_free(ticket_data->rms);
		gnutls_free(ticket_data->ticket_nonce);
	}
}

/*
 * Stores a session ticket locally.
 * All the fields of the ticket are copied, so they can safely be freed when this function returns.
 * The resumption master secret ('rms') is also copied.
 */
int _gnutls13_session_ticket_set(gnutls_session_t session,
		struct tls13_nst_st *ticket,
		const uint8_t *rms, size_t rms_size,
		const mac_entry_st *prf)
{
	gnutls_datum_t *rms_original;
	struct tls13_nst_st *src, *dst;

	if (unlikely(ticket == NULL))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
	if (unlikely(rms == NULL || rms_size == 0))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	if (session->internals.tls13_ticket)
		gnutls_free(session->internals.tls13_ticket);

	session->internals.tls13_ticket = gnutls_calloc(1, sizeof(struct tls13_nst_st));
	if (session->internals.tls13_ticket == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	/* Copy the ticket */
	src = ticket;
	dst = session->internals.tls13_ticket;

	if (copy_ticket(src, dst) < 0) {
		gnutls_assert();
		goto cleanup;
	}

	/* Copy the resumption master secret ('rms') for this session */
	rms_original = &session->key.proto.tls13.ap_rms_original;
	rms_original->data = gnutls_calloc(1, rms_size);
	if (!rms_original->data) {
		gnutls_assert();
		goto cleanup;
	}
	rms_original->size = rms_size;
	memcpy(rms_original->data, rms, rms_size);

	/* Set the KDF of the original connection */
	session->key.proto.tls13.kdf_original = prf->id;

	session->internals.tls13_ticket_len = sizeof(struct tls13_nst_st);
	return 0;

cleanup:
	_gnutls13_session_ticket_destroy((struct tls13_nst_st *) session->internals.tls13_ticket);
	session->internals.tls13_ticket = NULL;
	session->internals.tls13_ticket_len = 0;
	return GNUTLS_E_MEMORY_ERROR;
}

/*
 * Copy the locally stored session ticket to 'ticket'.
 * The fields of 'ticket' are copied not referenced, so they can be safely freed
 * after this function returns.
 */
int _gnutls13_session_ticket_get(gnutls_session_t session, struct tls13_nst_st *ticket)
{
	int ret = 0;
	struct tls13_nst_st *src, *dst;

	if (unlikely(ticket == NULL))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	if (session->internals.tls13_ticket_len > 0) {
		src = session->internals.tls13_ticket;
		dst = ticket;

		if (!src)
			return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

		if ((ret = copy_ticket(src, dst)) < 0) {
			_gnutls13_session_ticket_destroy(ticket);
			return gnutls_assert_val(ret);
		}

		if ((ret = _gnutls_set_datum(&dst->rms,
				session->key.proto.tls13.ap_rms_original.data,
				session->key.proto.tls13.ap_rms_original.size)) < 0) {
			gnutls_assert();
			goto error;
		}

		ret = session->internals.tls13_ticket_len + dst->rms.size;
	}

	return ret;

error:
	_gnutls13_session_ticket_destroy(dst);
	return ret;
}

/*
 * Behaves just like _gnutls13_session_ticket_get(), but does not copy the data (except the scalars).
 * It just references the pointers.
 */
int _gnutls13_session_ticket_peek(gnutls_session_t session, struct tls13_nst_st *ticket)
{
	int ret = 0;
	struct tls13_nst_st *src, *dst;

	src = session->internals.tls13_ticket;
	dst = ticket;

	if (session->internals.tls13_ticket_len > 0) {
		if (!src)
			return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

		if (dst) {
			memcpy(dst, src, sizeof(struct tls13_nst_st));
			memcpy(&dst->rms, &session->key.proto.tls13.ap_rms_original, sizeof(gnutls_datum_t));
		}

		ret = session->internals.tls13_ticket_len + session->key.proto.tls13.ap_rms_original.size;
	}

	return ret;
}

void _gnutls13_session_ticket_unset(gnutls_session_t session)
{
	if (session->internals.tls13_ticket_len > 0) {
		_gnutls13_session_ticket_destroy(session->internals.tls13_ticket);
		gnutls_free(session->internals.tls13_ticket);
		session->internals.tls13_ticket = NULL;
		session->internals.tls13_ticket_len = 0;
	}

	if (session->key.proto.tls13.ap_rms_original.data) {
		gnutls_free(session->key.proto.tls13.ap_rms_original.data);
		session->key.proto.tls13.ap_rms_original.size = 0;
	}
}
