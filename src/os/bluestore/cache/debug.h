/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHE_DEBUG_H
#define _BCACHE_DEBUG_H

#ifdef CONFIG_BCACHE_DEBUG
#define expensive_debug_checks(c)	((c)->expensive_debug_checks)
#define key_merging_disabled(c)		((c)->key_merging_disabled)
#define bypass_torture_test(d)		((d)->bypass_torture_test)
#else /* DEBUG */
#define expensive_debug_checks(c)	((c)->expensive_debug_checks)
#define key_merging_disabled(c)		0
#define bypass_torture_test(d)		0
#endif

//bool bch_cache_set_error(struct cache_set *c, const char *fmt, ...);
void dump_stack();

#endif
