/*
 * Copyright (C) 2016 Red Hat, Inc.
 *
 * Authors: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GnuTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <config.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <cmocka.h>

#define MATCH_FUNC(fname, str, normalized) \
static void fname(void **glob_state) \
{ \
	gnutls_datum_t out; \
	int ret = gnutls_idna_map(str, strlen(str), &out, 0); \
	if (normalized == NULL) { /* expect failure */ \
		assert_int_not_equal(ret, 0); \
		return; \
	} else { \
		assert_int_equal(ret, 0); \
	} \
	assert_int_equal(strcmp((char*)out.data, (char*)normalized), 0); \
	gnutls_free(out.data); \
}

/* vectors taken from:
 * http://www.unicode.org/Public/idna/9.0.0/IdnaTest.txt
 */

MATCH_FUNC(test_ascii, "localhost", "localhost");
MATCH_FUNC(test_ascii_caps, "LOCALHOST", "LOCALHOST");
MATCH_FUNC(test_greek1, "βόλοσ.com", "xn--nxasmq6b.com");
MATCH_FUNC(test_greek2, "βόλος.com", "xn--nxasmq6b.com");
MATCH_FUNC(test_cap_greek3, "ΒΌΛΟΣ.com", "xn--nxasmq6b.com");
MATCH_FUNC(test_mix, "简体中文.εξτρα.com", "xn--fiqu1az03c18t.xn--mxah1amo.com");
MATCH_FUNC(test_german1, "faß.de", "fass.de");
MATCH_FUNC(test_german2, "Faß.de", "fass.de");
MATCH_FUNC(test_german3, "Ü.ü", "xn--tda.xn--tda");
MATCH_FUNC(test_german4, "Bücher.de", "xn--bcher-kva.de");
MATCH_FUNC(test_u1, "夡夞夜夙", "xn--bssffl");
MATCH_FUNC(test_jp2, "日本語.jp", "xn--wgv71a119e.jp");
MATCH_FUNC(test_dots, "a.b.c。d。", "a.b.c.d.");

int main(void)
{
	gnutls_datum_t tmp;
	int ret;
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_ascii),
		cmocka_unit_test(test_ascii_caps),
		cmocka_unit_test(test_greek1),
		cmocka_unit_test(test_greek2),
		cmocka_unit_test(test_cap_greek3),
		cmocka_unit_test(test_mix),
		cmocka_unit_test(test_german1),
		cmocka_unit_test(test_german2),
		cmocka_unit_test(test_german3),
		cmocka_unit_test(test_german4),
		cmocka_unit_test(test_u1),
		cmocka_unit_test(test_jp2),
		cmocka_unit_test(test_dots)
	};

	ret = gnutls_idna_map("x", 1, &tmp, 0);
	if (ret == GNUTLS_E_UNIMPLEMENTED_FEATURE)
		exit(77);
	gnutls_free(tmp.data);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
