// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_strbuf.h>
#include <rz_vector.h>
#include <rz_regex.h>
#include <rz_types.h>
#include <rz_util/rz_assert.h>
#include <rz_util.h>

/**
 * \file Defines the wrapper functions to PCRE2.
 */

static void print_pcre2_err(RzRegexStatus err_num, size_t err_off) {
	PCRE2_UCHAR buffer[256];
	pcre2_get_error_message(err_num, buffer, sizeof(buffer));
	RZ_LOG_ERROR("Regex compilation failed at %" PFMTSZu ": %s\n", err_off,
		buffer);
}

/**
 * \brief Compile a regex pattern to a RzRegex and return it.
 * In case of an error, an error message is printed and NULL is returned.
 *
 * \param pattern The regex pattern string.
 * \param cflags The compilation flags or zero for default.
 * \param jflags The compilation flags for the JIT compiler.
 * You can pass RZ_REGEX_JIT_PARTIAL_SOFT or RZ_REGEX_JIT_PARTIAL_HARD if you
 * intend to use the pattern for partial matching. Otherwise set it to 0.
 *
 * \return The compiled regex or NULL in case of failure.
 */
RZ_API RZ_OWN RzRegex *rz_regex_new(const char *pattern, RzRegexFlags cflags, RzRegexFlags jflags) {
	RzRegexStatus err_num;
	RzRegexSize err_off;
	bool supported = false;
	pcre2_config(PCRE2_CONFIG_UNICODE, &supported);
	if (!supported) {
		RZ_LOG_ERROR("Unicode not supported by PCRE2 library.");
		return NULL;
	}
	const char *pat = NULL;
	if ((cflags & RZ_REGEX_EXTENDED) || (cflags & RZ_REGEX_EXTENDED_MORE)) {
		if (!strchr(pattern, ' ')) {
			pat = pattern;
		} else {
			// In PCRE2 with the extended flag set, ascii space cahracters ' ' are skipped.
			// We need to replace them with \s unfortunately to keep our API stable.
			char *tmp_ptr = strdup(pattern);
			pat = rz_str_replace(tmp_ptr, " ", "\\s", 0);
			pat = tmp_ptr;
		}
	} else {
		pat = pattern;
	}

	RzRegex *regex = pcre2_compile(
		(PCRE2_SPTR)pat,
		PCRE2_ZERO_TERMINATED,
		cflags | PCRE2_UTF | PCRE2_MATCH_INVALID_UTF,
		&err_num,
		&err_off,
		NULL);
	if (!regex) {
		print_pcre2_err(err_num, err_off);
		return NULL;
	}
	RzRegexStatus jit_err = pcre2_jit_compile(regex, PCRE2_JIT_COMPLETE);
	if (jit_err < 0) {
		print_pcre2_err(jit_err, 0);
	}
	return regex;
}

/**
 * \brief Frees a given RzRegex.
 *
 * \param regex The RzRegex to free.
 */
RZ_API void rz_regex_free(RZ_OWN RzRegex *regex) {
	pcre2_code_free(regex);
}

RZ_OWN RzRegexMatchData *rz_regex_match_data_new(const RzRegex *regex, RzRegexGeneralContext *context) {
	return pcre2_match_data_create_from_pattern(regex, context);
}

void rz_regex_match_data_free(RZ_OWN RzRegexMatchData *match_data) {
	pcre2_match_data_free(match_data);
}

RZ_API RzRegexStatus rz_regex_match(const RzRegex *regex, RZ_NONNULL const char *text,
	RzRegexSize text_offset,
	RzRegexFlags mflags,
	RZ_NULLABLE RZ_OUT RzRegexMatchData *mdata) {
	bool one_time_match = false;
	if (!mdata) {
		one_time_match = true;
		mdata = pcre2_match_data_create_from_pattern(regex, NULL);
	}
	RzRegexStatus rc = pcre2_match(regex, (PCRE2_SPTR)text, PCRE2_ZERO_TERMINATED, text_offset, mflags | PCRE2_NO_UTF_CHECK, mdata, NULL);
	if (one_time_match) {
		pcre2_match_data_free(mdata);
	}
	return rc;
}

/**
 * \brief Generates the error message to \p errcode.
 *
 * \param errcode The error code.
 * \param errbuf The error message buffer.
 * \param errbuf_size The error message buffer size in bytes.
 */
RZ_API void rz_regex_error_msg(RzRegexStatus errcode, RZ_OUT char *errbuf, RzRegexSize errbuf_size) {
	pcre2_get_error_message(errcode, (PCRE2_UCHAR *)errbuf, errbuf_size);
}

RZ_API const ut8 *rz_regex_get_match_name(const RzRegex *regex, ut32 name_idx) {
	rz_return_val_if_fail(regex, NULL);

	ut32 namecount;
	ut32 name_entry_size;
	PCRE2_SPTR nametable_ptr;

	pcre2_pattern_info(
		regex,
		PCRE2_INFO_NAMECOUNT,
		&namecount);

	pcre2_pattern_info(
		regex,
		PCRE2_INFO_NAMETABLE,
		&nametable_ptr);

	pcre2_pattern_info(
		regex,
		PCRE2_INFO_NAMEENTRYSIZE,
		&name_entry_size);

	for (size_t i = 0; i < namecount; i++) {
		int n = (nametable_ptr[0] << 8) | nametable_ptr[1];
		if (n == name_idx) {
			return nametable_ptr + 2;
		}
		nametable_ptr += name_entry_size;
	}
	return NULL;
}

/**
 * \brief Finds the first match in a text and returns it as a pvector.
 * First element in the vector is always the whole match, the following possible groups.
 */
RZ_API RZ_OWN RzPVector /*<RzRegexMatch>*/ *rz_regex_match_first(
	const RzRegex *regex,
	RZ_NONNULL const char *text,
	RzRegexSize text_offset,
	RzRegexFlags mflags) {
	RzPVector *matches = rz_pvector_new(NULL);
	RzRegexMatchData *mdata = pcre2_match_data_create_from_pattern(regex, NULL);
	RzRegexStatus rc = pcre2_match(regex, (PCRE2_SPTR)text, PCRE2_ZERO_TERMINATED, text_offset, mflags | PCRE2_NO_UTF_CHECK, mdata, NULL);

	if (rc == PCRE2_ERROR_NOMATCH) {
		// Nothing matched return empty vector.
		goto fini;
	}

	if (rc < 0) {
		// Some error happend. Inform the user.
		PCRE2_UCHAR buffer[256];
		pcre2_get_error_message(rc, buffer, sizeof(buffer));
		RZ_LOG_WARN("Regex matching failed: %s\n", buffer);
		goto fini;
	}

	// Add groups to vector
	PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(mdata);

	ut32 name_entry_size;
	PCRE2_SPTR nametable_ptr;

	pcre2_pattern_info(
		regex,
		PCRE2_INFO_NAMETABLE,
		&nametable_ptr);

	pcre2_pattern_info(
		regex,
		PCRE2_INFO_NAMEENTRYSIZE,
		&name_entry_size);

	for (size_t i = 0; i < rc; i++) {
		if (ovector[2 * i] > ovector[2 * i + 1]) {
			// This happens for \K lookaround. We fail if used.
			// See pcre2demo.c for details.
			RZ_LOG_ERROR("Usage of \\K to set start of the pattern later than the end, is not implemented.\n");
			goto fini;
		}

		// Offset and length of match
		RzRegexMatch *match = RZ_NEW0(RzRegexMatch);
		match->start = ovector[2 * i];
		match->len = ovector[2 * i + 1] - match->start;

		// Match index with a name.
		// Index is saved in the first two bytes of a table entry.
		ut32 n = (nametable_ptr[0] << 8) | nametable_ptr[1];
		if (n != i) {
			// No name
			match->mname_idx = RZ_REGEX_UNSET;
			rz_pvector_push(matches, match);
			continue;
		}

		match->mname_idx = n;
		nametable_ptr += name_entry_size;
		rz_pvector_push(matches, match);
	}

fini:
	rz_regex_match_data_free(mdata);
	return matches;
}

/**
 * \brief Finds all matches in a text and returns them as vector.
 * The result is a flat vector of matches. A single match with multiple
 * groups is simply appeneded to the resulting vector.
 */
RZ_API RZ_OWN RzPVector /*<RzRegexMatch>*/ *rz_regex_match_all_not_grouped(
	const RzRegex *regex,
	RZ_NONNULL const char *text,
	RzRegexSize text_offset,
	RzRegexFlags mflags) {
	rz_return_val_if_fail(regex && text, NULL);

	RzPVector *all_matches = rz_pvector_new((RzPVectorFree)rz_vector_free);
	RzPVector *matches = rz_regex_match_first(regex, text, text_offset, mflags);
	while (matches && rz_pvector_len(matches) > 0) {
		for (size_t i = 0; i < rz_pvector_len(matches); ++i) {
			RzRegexMatch *m = rz_pvector_pop(matches);
			rz_pvector_push(all_matches, m);
		}
		RzRegexMatch *m = rz_pvector_head(matches);
		// Search again after the last match.
		text_offset = m->start + m->len;
		rz_pvector_free(matches);
		matches = rz_regex_match_first(regex, text, text_offset, mflags);
	}

	// Free last vector without matches.
	rz_pvector_free(matches);
	return all_matches;
}

/**
 * \brief Finds all matches in a text and returns them as vector of vector matches.
 */
RZ_API RZ_OWN RzPVector /*<RzVector<RzRegexMatch>>*/ *rz_regex_match_all(
	const RzRegex *regex,
	RZ_NONNULL const char *text,
	RzRegexSize text_offset,
	RzRegexFlags mflags) {
	rz_return_val_if_fail(regex && text, NULL);

	RzPVector *all_matches = rz_pvector_new((RzPVectorFree)rz_vector_free);
	RzPVector *matches = rz_regex_match_first(regex, text, text_offset, mflags);
	while (matches && rz_pvector_len(matches) > 0) {
		rz_pvector_push(all_matches, matches);
		RzRegexMatch *m = rz_pvector_head(matches);
		// Search again after the last match.
		text_offset = m->start + m->len;
		matches = rz_regex_match_first(regex, text, text_offset, mflags);
	}

	// Free last vector without matches.
	rz_pvector_free(matches);
	return all_matches;
}

/**
 * \brief Checks if \p pattern can be found in \p text.
 */
RZ_API bool rz_regex_contains(const char *pattern, const char *text, RzRegexFlags cflags, RzRegexFlags mflags) {
	RzRegex *re = rz_regex_new(pattern, cflags, 0);
	if (!re) {
		return false;
	}
	RzPVector *matches = rz_regex_match_first(re, text, 0, mflags);
	bool found = matches != NULL && !rz_pvector_empty(matches);
	rz_pvector_free(matches);
	return found;
}

/**
 * \brief Searches for a \p pattern in \p text and returns all matches as concatenated string.
 *
 */
RZ_API RZ_OWN RzStrBuf *rz_regex_full_match_str(const char *pattern, const char *text, RzRegexFlags cflags, RzRegexFlags mflags, RZ_NONNULL const char *separator) {
	rz_return_val_if_fail(pattern && text && separator, NULL);
	RzRegex *re = rz_regex_new(pattern, cflags, 0);
	RzStrBuf *sbuf = rz_strbuf_new("");
	RzPVector *matches = rz_regex_match_all_not_grouped(re, text, 0, mflags);
	if (!matches || !sbuf) {
		goto fini;
	}

	void **m;
	rz_pvector_foreach (matches, m) {
		RzRegexMatch *match = *m;
		const char *t = text + match->start;
		if (((int)match->len) < 0) {
			goto fini;
		}
		if (!rz_strbuf_appendf(sbuf, "%-.*s%s", (int)match->len, t, separator)) {
			goto fini;
		}
	}

fini:
	rz_pvector_free(matches);
	return sbuf;
}
