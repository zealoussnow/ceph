// SPDX-License-Identifier: GPL-2.0
/*
 * bcache journalling code, for btree insertions
 *
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "btree.h"
#include "debug.h"
#include "extents.h"

/*
 * Journal replay/recovery:
 *
 * This code is all driven from run_cache_set(); we first read the journal
 * entries, do some other stuff, then we mark all the keys in the journal
 * entries (same as garbage collection would), then we replay them - reinserting
 * them into the cache in precisely the same order as they appear in the
 * journal.
 *
 * We only journal keys that go in leaf nodes, which simplifies things quite a
 * bit.
 */

//static void journal_read_endio(struct bio *bio)
//{
//	struct closure *cl = bio->bi_private;
//	closure_put(cl);
//}
//
static int journal_read_bucket(struct cache *ca, struct list_head *list,
                               unsigned bucket_index)
{
	/*bucket_index = 2;*/
        struct journal_device *ja = &ca->journal;
//	/*struct bio *bio = &ja->bio;*/
//
	struct journal_replay *i;
	struct jset *j, *data = ca->set->journal.w[0].data;
//	struct closure cl;
	unsigned len, left, offset = 0;
	int ret = 0;
	/*printf(" ca->sb.d[%d] = %d. ca->set->bucket_bits = %d \n", bucket_index, ca->sb.d[bucket_index], ca->set->bucket_bits);*/
	/*printf("bucket_to_sector(ca->set, ca->sb.d[bucket_index] = %lu \n", bucket_to_sector(ca->set, ca->sb.d[bucket_index]));*/
	sector_t bucket = bucket_to_sector(ca->set, ca->sb.d[bucket_index]);
	/*unsigned long bucket = bucket_to_sector(ca->set, ca->sb.d[bucket_index]);*/
//	//closure_init_stack(&cl);
	while (offset < ca->sb.bucket_size) {
reread:		left = ca->sb.bucket_size - offset;
		len = min(left, PAGE_SECTORS << JSET_BITS);

		off_t start = (bucket+offset) << 9;
		size_t lenght = len << 9;
		/*printf(" bucket = %d , offset=%d\n", bucket, offset);*/
		/*printf(" read ca->fd=%d, lenght=%d, start=%d \n", ca->fd, lenght, start);*/
		/*printf(" lenght=%d, start=%d \n", lenght, start);*/
		if ( sync_read( ca->fd, data, lenght, start ) == -1 ) {
			printf(" read bucket error \n");
			exit(1);
		}
//		/*bio_reset(bio);*/
//		/*bio->bi_iter.bi_sector	= bucket + offset;*/
//		/*bio_set_dev(bio, ca->bdev);*/
//		/*bio->bi_iter.bi_size	= len << 9;*/
//
//		/*bio->bi_end_io	= journal_read_endio;*/
//		/*bio->bi_private = &cl;*/
//		/*bio_set_op_attrs(bio, REQ_OP_READ, 0);*/
//		/*bch_bio_map(bio, data);*/
//
//		/*closure_bio_submit(bio, &cl);*/
//		/*closure_sync(&cl);*/
//
//		/* This function could be simpler now since we no longer write
//		 * journal entries that overlap bucket boundaries; this means
//		 * the start of a bucket will always have a valid journal entry
//		 * if it has any journal entries at all.
//		 */
//
		j = data;
		while (len) {
			struct list_head *where;
			size_t blocks, bytes = set_bytes(j);
			if (j->magic != jset_magic(&ca->sb)) {
				/*pr_debug("%u: bad magic", bucket_index);*/
				return ret;
			}

			if (bytes > left << 9 ||
			    bytes > PAGE_SIZE << JSET_BITS) {
				/*pr_info("%u: too big, %zu bytes, offset %u",*/
					/*bucket_index, bytes, offset);*/
				printf("%u: too big, %zu bytes, offset %u \n",
					bucket_index, bytes, offset);
				return ret;
			}

			if (bytes > len << 9)
			{
			    printf(" bytes > len<<9, goto reread \n");
			    goto reread;
			}

			if (j->csum != csum_set(j)) {
				/*pr_info("%u: bad csum, %zu bytes, offset %u",*/
					/*bucket_index, bytes, offset);*/
				printf("%u: bad csum, %zu bytes, offset %u \n",
					bucket_index, bytes, offset);
				return ret;
			}

			blocks = set_blocks(j, block_bytes(ca->set));

			while (!list_empty(list)) {
				i = list_first_entry(list,
					struct journal_replay, list);
				if (i->j.seq >= j->last_seq)
					break;
				list_del(&i->list);
				free(i);
				/*kfree(i);*/
			}

			list_for_each_entry_reverse(i, list, list) {
				if (j->seq == i->j.seq)
					goto next_set;

				if (j->seq < i->j.last_seq)
					goto next_set;

				if (j->seq > i->j.seq) {
					where = &i->list;
					goto add;
				}
			}

			where = list;
add:
			i = T2Molloc(offsetof(struct journal_replay, j) + bytes);
			/*i = kT2Molloc(offsetof(struct journal_replay, j) +*/
				    /*bytes, GFP_KERNEL);*/
			if (!i)
				return -ENOMEM;
			memcpy(&i->j, j, bytes);
                        /*printf(" journal.c FUN %s: Add new jset(seq=%ld) to journal list\n",__func__,j->seq);*/
			list_add(&i->list, where);
			ret = 1;

			ja->seq[bucket_index] = j->seq;
next_set:
			offset	+= blocks * ca->sb.block_size;
			len	-= blocks * ca->sb.block_size;
			j = ((void *) j) + blocks * block_bytes(ca);
		}
	}

        return ret;
}

int bch_journal_read(struct cache_set *c, struct list_head *list)
{
#define read_bucket(b)							\
        ({								\
                int ret = journal_read_bucket(ca, list, b);		\
                __set_bit(b, bitmap);					\
                if (ret < 0)						\
                        return ret;					\
                ret;							\
        })

        struct cache *ca;
        unsigned iter;

        for_each_cache(ca, c, iter) {
                struct journal_device *ja = &ca->journal;
                /* SB_JOURNAL_BUCKETS: 256U，即占用32个字节，4个unsigned long  */
                DECLARE_BITMAP(bitmap, SB_JOURNAL_BUCKETS);
                unsigned i, l, r, m;
                uint64_t seq;

                bitmap_zero(bitmap, SB_JOURNAL_BUCKETS);
                /*pr_debug("%u journal buckets", ca->sb.njournal_buckets);*/
                /*printf("%u journal buckets \n", ca->sb.njournal_buckets);*/
//
//		/*
//		 * http://book.huihoo.com/data-structures-and-algorithms-with-object-oriented-design-patterns-in-c++/html/page214.html
//		 *
//		 * Read journal buckets ordered by golden ratio hash to quickly
//		 * find a sequence of buckets with valid journal entries
//		 * 按黄金比率散列顺序读取journal，快速查找一系列有效的journal
//		 * 条目的buckets
//		 */
		for (i = 0; i < ca->sb.njournal_buckets; i++) {
			l = (i * 2654435769U) % ca->sb.njournal_buckets;
			if (test_bit(l, bitmap))
			{
				/*printf(" test_bit break \n");*/
				break;
			}
			// 1. 如果调用read_bucket 返回 > 0, 则会goto bsearch
			if (read_bucket(l))
				goto bsearch;
		}

                /*
                 * If that fails, check all the buckets we haven't checked
                 * already
                 */
                /*printf(" journal.c FUN %s: falling back to linear search\n",__func__);*/

		for (l = find_first_zero_bit(bitmap, ca->sb.njournal_buckets);
		     l < ca->sb.njournal_buckets;
		     l = find_next_zero_bit(bitmap, ca->sb.njournal_buckets, l + 1))
		{
			if (read_bucket(l))
				goto bsearch;
		}

		/* no journal entries on this device? */
		if (l == ca->sb.njournal_buckets)
                {
                    /*printf(" journal.c FUN %s: Error: No journal entries on this device\n",__func__);*/
                    exit(1);
		    continue;
                }
bsearch:
		BUG_ON(list_empty(list));

		/* Binary search */
		m = l;
		r = find_next_bit(bitmap, ca->sb.njournal_buckets, l + 1);
                /*printf(" journal.c FUN %s: Starting binary search, l=%u, r=%u\n",__func__, l, r);*/

		while (l + 1 < r) {
			seq = list_entry(list->prev, struct journal_replay,
					 list)->j.seq;

			m = (l + r) >> 1;
			read_bucket(m);

			if (seq != list_entry(list->prev, struct journal_replay,
					      list)->j.seq)
				l = m;
			else
				r = m;
		}

		/*
		 * Read buckets in reverse order until we stop finding more
		 * journal entries
		 */
                /*printf(" journal.c FUN %s: finishing up: m=%u njournal_buckets=%u\n",__func__, m, ca->sb.njournal_buckets);*/
		l = m;

		while (1) {
			if (!l--)
				l = ca->sb.njournal_buckets - 1;

			if (l == m)
				break;

			if (test_bit(l, bitmap))
				continue;

			if (!read_bucket(l))
				break;
		}

		seq = 0;

                /*printf(" journal.c FUN %s: before(update cur_idx)cur_idx=%d,last_idx=%d,discard_idx=%d\n",__func__,ja->cur_idx,ja->last_idx,ja->discard_idx);*/
		for (i = 0; i < ca->sb.njournal_buckets; i++)
			if (ja->seq[i] > seq) {
				seq = ja->seq[i];
				/*
				 * When journal_reclaim() goes to allocate for
				 * the first time, it'll use the bucket after
				 * ja->cur_idx
				 */
				ja->cur_idx = i;
				ja->last_idx = ja->discard_idx = (i + 1) %
					ca->sb.njournal_buckets;

			}
                /*printf(" journal.c FUN %s: after(update cur_idx)cur_idx=%d,last_idx=%d,discard_idx=%d\n",__func__,ja->cur_idx,ja->last_idx,ja->discard_idx);*/
        }

	if (!list_empty(list))
		c->journal.seq = list_entry(list->prev,
					    struct journal_replay,
					    list)->j.seq;
        /*printf(" journal.c FUN %s: Now new journal seq=%d \n", __func__, c->journal.seq);*/
	return 0;
#undef read_bucket
}

void bch_journal_mark(struct cache_set *c, struct list_head *list)
{
        /*printf(" journal.c FUN %s: journal mark from read journal_replay list \n", __func__);*/
	atomic_t p = { 0 };
	struct bkey *k;
	struct journal_replay *i;
	struct journal *j = &c->journal;
	uint64_t last = j->seq;

	/*
	 * journal.pin should never fill up - we never write a journal
	 * entry when it would fill up. But if for some reason it does, we
	 * iterate over the list in reverse order so that we can just skip that
	 * refcount instead of bugging.
	 * journal.pin应该永远填不满 - 当它将要满的时候，我们从不写journal条目
	 * 但是如果有些理由要这么做，我们逆序迭代list，因此我们可以忽略引用计数
	 * 来代替debuging。
	 */

	list_for_each_entry_reverse(i, list, list) {
		BUG_ON(last < i->j.seq);
		i->pin = NULL;

		while (last-- != i->j.seq)
			if (fifo_free(&j->pin) > 1) {
				fifo_push_front(&j->pin, p);
				atomic_set(&fifo_front(&j->pin), 0);
                                /*printf(" journal.c FUN %s: journal mark fifo_push_front 0\n", __func__);*/
			}

		if (fifo_free(&j->pin) > 1) {
			fifo_push_front(&j->pin, p);
			i->pin = &fifo_front(&j->pin);
			atomic_set(i->pin, 1);
                        /*printf(" journal.c FUN %s: journal mark fifo_push_front 1\n", __func__);*/
		}

		for (k = i->j.start;
		     k < bset_bkey_last(&i->j);
		     k = bkey_next(k))
			if (!__bch_extent_invalid(c, k)) {
				unsigned j;

				for (j = 0; j < KEY_PTRS(k); j++)
					if (ptr_available(c, k, j))
						atomic_inc(&PTR_BUCKET(c, k, j)->pin);

                                /*printf(" journal.c FUN %s: journal mark initial_mark_key \n", __func__);*/
				bch_initial_mark_key(c, 0, k);
			}
	}
}

///* 下次打开时对未处理的btree insert做重新提交操作 */
int bch_journal_replay(struct cache_set *s, struct list_head *list)
{
	/*printf(" -------- \n");*/
	int ret = 0, keys = 0, entries = 0;
	struct bkey *k;
	struct journal_replay *i =
		list_entry(list->prev, struct journal_replay, list);

	uint64_t start = i->j.last_seq, end = i->j.seq, n = start;
	struct keylist keylist;

	list_for_each_entry(i, list, list) {
		BUG_ON(i->pin && atomic_read(i->pin) != 1);

		cache_set_err_on(n != i->j.seq, s,
"bcache: journal entries %llu-%llu missing! (replaying %llu-%llu)",
				 n, i->j.seq - 1, start, end);
                /*printf("<<fun %s, btree_level=%d,keys=%d\n", __func__, i->j.btree_level, i->j.keys);*/
                /*printf(" journal.c FUN %s: jset.btree_level=%d,jset.keys=%d\n",__func__,i->j.btree_level,i->j.keys);*/
		for (k = i->j.start;
		     k < bset_bkey_last(&i->j);
		     k = bkey_next(k)) {
			/*trace_bcache_journal_replay_key(k);*/
                        /*printf(" journal.c FUN %s: Reply Bkey size=%d,PTR_OFFSET=%d\n",__func__,KEY_SIZE(k),PTR_OFFSET(k,0));*/
			bch_keylist_init_single(&keylist, k);
                                
                        /*printf(" journal.c FUN %s: Start insert single keylist nkeys=%d,journal_replay.pin=%d\n",__func__,bch_keylist_nkeys(&keylist),i->pin);*/
			ret = bch_btree_insert(s, &keylist, i->pin, NULL);
			if (ret)
				goto err;

			BUG_ON(!bch_keylist_empty(&keylist));
			keys++;
			/*cond_resched();*/
		}

		if (i->pin)
			atomic_dec(i->pin);
		n = i->j.seq + 1;
		entries++;
	}

	/*pr_info("journal replay done, %i keys in %i entries, seq %llu",*/
		/*keys, entries, end);*/
	/*printf("journal replay done, %i keys in %i entries, seq %llu \n",*/
		/*keys, entries, end);*/
err:
	while (!list_empty(list)) {
		i = list_first_entry(list, struct journal_replay, list);
		list_del(&i->list);
		/*kfree(i);*/
		free(i);
	}

	return ret;
}

///* Journalling */
//
//static void btree_flush_write(struct cache_set *c)
//{
//	/*
//	 * Try to find the btree node with that references the oldest journal
//	 * entry, best is our current candidate and is locked if non NULL:
//	 */
//	struct btree *b, *best;
//	unsigned i;
//retry:
//	best = NULL;
//
//	for_each_cached_btree(b, c, i)
//		if (btree_current_write(b)->journal) {
//			if (!best)
//				best = b;
//			else if (journal_pin_cmp(c,
//					btree_current_write(best)->journal,
//					btree_current_write(b)->journal)) {
//				best = b;
//			}
//		}
//
//	b = best;
//	if (b) {
//		pthread_mutex_lock(&b->write_lock);
//		if (!btree_current_write(b)->journal) {
//			pthread_mutex_unlock(&b->write_lock);
//			/* We raced */
//			goto retry;
//		}
//
//		__bch_btree_node_write(b, NULL);
//		pthread_mutex_unlock(&b->write_lock);
//	}
//}
//
#define last_seq(j)	((j)->seq - fifo_used(&(j)->pin) + 1)
//
//static void journal_discard_endio(struct bio *bio)
//{
//	struct journal_device *ja =
//		container_of(bio, struct journal_device, discard_bio);
//	struct cache *ca = container_of(ja, struct cache, journal);
//
//	atomic_set(&ja->discard_in_flight, DISCARD_DONE);
//
//	closure_wake_up(&ca->set->journal.wait);
//	closure_put(&ca->set->cl);
//}
//
//static void journal_discard_work(struct work_struct *work)
//{
//	struct journal_device *ja =
//		container_of(work, struct journal_device, discard_work);
//
//	submit_bio(&ja->discard_bio);
//}
//
static void do_journal_discard(struct cache *ca)
{
        struct journal_device *ja = &ca->journal;
        /*struct bio *bio = &ja->discard_bio;*/
        /*printf(" journal.c FUN %s: ca->discard=%d,ja->discard_idx=%d,ja->last_idx=%d\n",__func__,ca->discard,ja->discard_idx,ja->last_idx );*/
        if (!ca->discard) {
                ja->discard_idx = ja->last_idx;
                return;
        }

        /*switch (atomic_read(&ja->discard_in_flight)) {*/
        /*case DISCARD_IN_FLIGHT:*/
                /*return;*/

        /*case DISCARD_DONE:*/
                /*ja->discard_idx = (ja->discard_idx + 1) %*/
                        /*ca->sb.njournal_buckets;*/

                /*atomic_set(&ja->discard_in_flight, DISCARD_READY);*/
                 /*fallthrough */

        /*case DISCARD_READY:*/
                /*if (ja->discard_idx == ja->last_idx)*/
                        /*return;*/

                /*atomic_set(&ja->discard_in_flight, DISCARD_IN_FLIGHT);*/

                /*bio_init(bio, bio->bi_inline_vecs, 1);*/
                /*bio_set_op_attrs(bio, REQ_OP_DISCARD, 0);*/
                /*bio->bi_iter.bi_sector	= bucket_to_sector(ca->set,*/
                                                /*ca->sb.d[ja->discard_idx]);*/
                /*bio_set_dev(bio, ca->bdev);*/
                /*bio->bi_iter.bi_size	= bucket_bytes(ca);*/
                /*bio->bi_end_io		= journal_discard_endio;*/

                /*closure_get(&ca->set->cl);*/
                /*INIT_WORK(&ja->discard_work, journal_discard_work);*/
                /*schedule_work(&ja->discard_work);*/
        /*}*/
}

static void journal_reclaim(struct cache_set *c)
{
        struct bkey *k = &c->journal.key;
        struct cache *ca;
        uint64_t last_seq;
        unsigned iter, n = 0;
        atomic_t p;

        /*printf(" journal.c <%s>: Reclaim: before update pin(pop front 0)/last_seq fifo_used=%d,last_seq=%d\n",__func__, fifo_used(&c->journal.pin),last_seq);*/
        while (!atomic_read(&fifo_front(&c->journal.pin)))
                fifo_pop(&c->journal.pin, p);

        /*#define last_seq(j)	((j)->seq - fifo_used(&(j)->pin) + 1)*/
        last_seq = last_seq(&c->journal);
        /*printf(" journal.c <%s>: Reclaim: after update pin(pop front 0)/last_seq fifo_used=%d,last_seq=%d\n",__func__, fifo_used(&c->journal.pin),last_seq);*/

        /* Update last_idx */

        for_each_cache(ca, c, iter) {
                struct journal_device *ja = &ca->journal;
                /*printf(" journal.c <%s>: befor(update last_idx) last_idx=%d,cur_idx=%d\n",__func__, ja->last_idx,ja->cur_idx);*/
                while (ja->last_idx != ja->cur_idx &&
                       ja->seq[ja->last_idx] < last_seq)
                        ja->last_idx = (ja->last_idx + 1) %
                                ca->sb.njournal_buckets;
                /*printf(" journal.c FUN %s: after(update last_idx)  last_idx=%d,cur_idx=%d\n",__func__, ja->last_idx,ja->cur_idx);*/
        }

        for_each_cache(ca, c, iter)
                do_journal_discard(ca);

        if (c->journal.blocks_free)
                goto out;

        /*
         * Allocate:
         * XXX: Sort by free journal space
         */

        for_each_cache(ca, c, iter) {
                struct journal_device *ja = &ca->journal;
                /*printf(" ja->cur_idx = %d \n", ja->cur_idx);*/
                unsigned next = (ja->cur_idx + 1) % ca->sb.njournal_buckets;
                /*printf(" next = %d \n", next);*/

                /*printf(">> function %s,cur_idx=%d,discard_idx=%d,next=%d \n", __func__,ja->cur_idx,ja->discard_idx,next);*/
                /*printf(" journal.c FUN %s: befor(update cur_idx): cur_idx=%d,next(new)=%d,discard_idx=%d\n",__func__, ja->cur_idx,next,ja->discard_idx);*/
                /* No space available on this device */
                if (next == ja->discard_idx)
                        continue;

                ja->cur_idx = next;
                /*printf(" ca->sb.d[ja->cur_idx] = %d \n", ca->sb.d[ja->cur_idx]);*/
                k->ptr[n++] = PTR(0,
                                  bucket_to_sector(c, ca->sb.d[ja->cur_idx]),
                                  ca->sb.nr_this_dev);
                /*printf(" journal.c FUN %s: after(update cur_idx): cur_idx=%d,next=%d,discard_idx=%d\n",__func__, ja->cur_idx,next,ja->discard_idx);*/
                /*printf(" journal.c FUN %s: journal new bucket nr=%d\n",__func__, ca->sb.d[ja->cur_idx]);*/
        }
        
        bkey_init(k);
        SET_KEY_PTRS(k, n);
        if (n)
                c->journal.blocks_free = c->sb.bucket_size >> c->block_bits;
        /*printf(" journal.c FUN %s: journal new blocks_free=%d\n",__func__, c->journal.blocks_free);*/
    return ;
out:
    /*printf(" journal.c FUN %s: journal bucket blocks_free=%d, no need update cur_idx\n",__func__, c->journal.blocks_free);*/
    return;
    /*if (!journal_full(&c->journal))*/
            /*__closure_wake_up(&c->journal.wait);*/
}
//
void bch_journal_next(struct journal *j)
{
        atomic_t p = { 1 };

        j->cur = (j->cur == j->w)
                ? &j->w[1]
                : &j->w[0];

        /*
         * The fifo_push() needs to happen at the same time as j->seq is
         * incremented for last_seq() to be calculated correctly
         */
        /*printf(" journal.c <%s>: Journal Next before update pin(push 1)/seq fifo_used=%d,jset->seq=%d\n",__func__,fifo_used(&j->pin),j->cur->data->seq);*/
        BUG_ON(!fifo_push(&j->pin, p));
        atomic_set(&fifo_back(&j->pin), 1);
        j->cur->data->seq	= ++j->seq;
        j->cur->dirty		= false;
        j->cur->need_write	= false;
        j->cur->data->keys	= 0;
        /*printf(" journal.c <%s>: Journal Next after update pin(push 1)/seq fifo_used=%d,jset->seq=%d\n",__func__,fifo_used(&j->pin),j->cur->data->seq);*/

        if (fifo_full(&j->pin)){
                printf(" journal.c <%s>: Journal Next fifo is full fifo_used=%d\n",__func__,fifo_used(&j->pin));
        }
}
//
//static void journal_write_endio(struct bio *bio)
//{
//	struct journal_write *w = bio->bi_private;
//
//	cache_set_err_on(bio->bi_status, w->c, "journal io error");
//	closure_put(&w->c->journal.io);
//}
//
//static void journal_write(struct closure *);
//
//static void journal_write_done(struct closure *cl)
//{
//	struct journal *j = container_of(cl, struct journal, io);
//	struct journal_write *w = (j->cur == j->w)
//		? &j->w[1]
//		: &j->w[0];
//
//	__closure_wake_up(&w->wait);
//	continue_at_nobarrier(cl, journal_write, system_wq);
//}
//
//static void journal_write_unlock(struct closure *cl)
//{
//	struct cache_set *c = container_of(cl, struct cache_set, journal.io);
//
//	c->journal.io_in_flight = 0;
//	spin_unlock(&c->journal.lock);
//}
//
/*static void journal_write_unlocked(struct closure *cl)*/
static void journal_write_unlocked(struct cache_set *c)
//	__releases(c->journal.lock)
{
//	struct cache_set *c = container_of(cl, struct cache_set, journal.io);
        struct cache *ca;
        struct journal_write *w = c->journal.cur;
        struct bkey *k = &c->journal.key;
        unsigned i, sectors = set_blocks(w->data, block_bytes(c)) *
                c->sb.block_size;
//
//	struct bio *bio;
//	struct bio_list list;
//	bio_list_init(&list);
//
        if (!w->need_write) {
             /*closure_return_with_destructor(cl, journal_write_unlock);*/
             /*journal_write_unlock();*/
             return;
        } else if (journal_full(&c->journal)) {
                journal_reclaim(c);
                pthread_spin_unlock(&c->journal.lock);
//		spin_unlock(&c->journal.lock);
//
//		btree_flush_write(c);
//		continue_at(cl, journal_write, system_wq);
                return;
        }
        /*printf(" journa write start \n");*/

        c->journal.blocks_free -= set_blocks(w->data, block_bytes(c));

        w->data->btree_level = c->root->level;

        bkey_copy(&w->data->btree_root, &c->root->key);
        bkey_copy(&w->data->uuid_bucket, &c->uuid_bucket);

        for_each_cache(ca, c, i)
	{
                w->data->prio_bucket[ca->sb.nr_this_dev] = ca->prio_buckets[0];
	}

        w->data->magic		= jset_magic(&c->sb);
        w->data->version	= BCACHE_JSET_VERSION;
        w->data->last_seq	= last_seq(&c->journal);
        w->data->csum		= csum_set(w->data);
        /*printf(" ***************** journal.c FUN %s: journal write: seq=%ld,last_seq=%d,btree_level=%d,blocks_free=%d\n",__func__,w->data->seq,w->data->last_seq,w->data->btree_level,c->journal.blocks_free);*/
        /*printf(" journal.c FUN %s: journal write: seq=%ld,last_seq=%d,btree_level=%d,blocks_free=%d\n",__func__,w->data->seq,w->data->last_seq,w->data->btree_level,c->journal.blocks_free);*/
        for (i = 0; i < KEY_PTRS(k); i++) {
                ca = PTR_CACHE(c, k, i);
                /*bio = &ca->journal.bio;*/

                atomic_long_add(sectors, &ca->meta_sectors_written);

//		bio_reset(bio);
//		bio->bi_iter.bi_sector	= PTR_OFFSET(k, i);
                // 1. start = PTR_OFFSET;
                /*off_t start = PTR_OFFSET(k, i) << 9;*/
                off_t start = PTR_OFFSET_to_bytes(k, i);
                size_t len = sectors << 9;
                /*printf(" journal.c FUN %s: journal write: fd=%d,start=0x%x,len=%d\n", __func__,ca->fd,start,len);*/
                if ( sync_write( ca->fd, w->data, len, start) == -1) {
                        printf(" write journal error \n");
                        exit(1);
                }
                SET_PTR_OFFSET(k, i, PTR_OFFSET(k, i) + sectors);
                ca->journal.seq[ca->journal.cur_idx] = w->data->seq;
                /*printf(" journal.c FUN %s: complete journal write: seq[%d]=%d\n", __func__,ca->journal.cur_idx,w->data->seq);*/
//		bio_set_dev(bio, ca->bdev);
//		bio->bi_iter.bi_size = sectors << 9;
//
//		bio->bi_end_io	= journal_write_endio;
//		bio->bi_private = w;
//		bio_set_op_attrs(bio, REQ_OP_WRITE,
//				 REQ_SYNC|REQ_META|REQ_PREFLUSH|REQ_FUA);
//		bch_bio_map(bio, w->data);
//
//		trace_bcache_journal_write(bio);
//		bio_list_add(&list, bio);
//
//		SET_PTR_OFFSET(k, i, PTR_OFFSET(k, i) + sectors);
//
//		ca->journal.seq[ca->journal.cur_idx] = w->data->seq;
        }

        atomic_dec_bug(&fifo_back(&c->journal.pin));
        /*printf(" journal.c FUN %s: Start bch_journal_next \n", __func__);*/
        bch_journal_next(&c->journal);
        /*printf(" journal.c FUN %s: Start journal_reclaim \n", __func__);*/
        journal_reclaim(c);

        /*spin_unlock(&c->journal.lock);*/
        pthread_spin_unlock(&c->journal.lock);
//
//	while ((bio = bio_list_pop(&list)))
//		closure_bio_submit(bio, cl);
//
        // ********** sync write done ************** //
        // wake other journal_write 
        // ********** sync write done ************** //
//	continue_at(cl, journal_write_done, NULL);
}
//
//static void journal_write(struct closure *cl)
//{
//	struct cache_set *c = container_of(cl, struct cache_set, journal.io);
//
//	spin_lock(&c->journal.lock);
//	journal_write_unlocked(cl);
//}
//
static void journal_try_write(struct cache_set *c)
        /*__releases(c->journal.lock)*/
{
        /*struct closure *cl = &c->journal.io;*/
        struct journal_write *w = c->journal.cur;

        w->need_write = true;
        /*printf("  c->journal.io_in_flight = %d \n", c->journal.io_in_flight);*/
        journal_write_unlocked(c);
        /*if (!c->journal.io_in_flight) {*/
                /*c->journal.io_in_flight = 1;*/
                /*journal_write_unlocked(c);*/
                /*closure_call(cl, journal_write_unlocked, NULL, &c->cl);*/
        /*} else {*/
                /*pthread_spin_unlock(&c->journal.lock);*/
                /*spin_unlock(&c->journal.lock);*/
        /*}*/
}

struct journal_write *journal_wait_for_write(struct cache_set *c,
                                                    unsigned nkeys)
{
    size_t sectors;
    /*struct closure cl;*/
    bool wait = false;

    /*closure_init_stack(&cl);*/

    /*spin_lock(&c->journal.lock);*/
    pthread_spin_lock( &c->journal.lock);
    /*c->journal.blocks_free = c->sb.bucket_size >> c->block_bits;*/
    while (1) {
        struct journal_write *w = c->journal.cur;

        sectors = __set_blocks(w->data, w->data->keys + nkeys,
                               block_bytes(c)) * c->sb.block_size;

        // 1. c->journal.blocks_free * c->sb.block_size journal现在可写的空间(即一个bucket的扇区数：1024）
        // 2. PAGE_SECTORS << JSET_BITS 一个jset占用的空间( 8 * 8 = 64个扇区）  
        /*printf(" journal: c->journal.blocks_free = %d\n", c->journal.blocks_free);*/
        /*printf(" journal: c->journal.blocks_free * c->sb.block_size = %d\n", c->journal.blocks_free * c->sb.block_size);*/
        /*printf(" journal: PAGE_SECTORS << JSET_BITS = %d\n", PAGE_SECTORS << JSET_BITS );*/
        /*printf(" journal.c <%s>: Wait Write need sectors=%d,blocks_free=%d,max_jset_sectos=%d\n", __func__,sectors,c->journal.blocks_free,PAGE_SECTORS<<JSET_BITS);*/
        if (sectors <= min_t(size_t, c->journal.blocks_free * c->sb.block_size,
                                     PAGE_SECTORS << JSET_BITS))
        {
            /*printf(" journal.c <%s>: Wait Write: Enough sectors, return journal_write\n", __func__);*/
            return w;
        }
        /*if (wait)*/
                /*closure_wait(&c->journal.wait, &cl);*/

        if (!journal_full(&c->journal)) {
                /*if (wait)*/
                        /*trace_bcache_journal_entry_full(c);*/

                /*
                 * XXX: If we were inserting so many keys that they
                 * won't fit in an _empty_ journal write, we'll
                 * deadlock. For now, handle this in
                 * bch_keylist_realloc() - but something to think about.
                 */
                BUG_ON(!w->data->keys);
                /*printf(" journal.c <%s>: Wait Write: Journal secors not enough and journal not full\n", __func__);*/
                /*printf(" journal.c <%s>: Wait Write Start Write\n",__func__);*/
                journal_try_write(c);
                /*printf(" journal.c <%s>: Wait Write End Write\n",__func__);*/
        } else {
                /*if (wait)*/
                        /*trace_bcache_journal_full(c);*/
                /*printf(" journal.c <%s>: Wait Write: Journal full blocks_free=%d,fifo_free(pin)=%d\n", __func__,c->journal.blocks_free,fifo_free(&c->journal.pin));*/
                /*printf(" journal.c <%s>: Wait Write Start journal reclaim\n", __func__);*/
                journal_reclaim(c);
                /*printf(" journal.c <%s>: Wait Write End journal reclaim\n", __func__);*/
                pthread_spin_unlock(&c->journal.lock);
                /*spin_unlock(&c->journal.lock);*/
                /*btree_flush_write(c);*/
        }

        /*closure_sync(&cl);*/
        /*spin_lock(&c->journal.lock);*/
        pthread_spin_lock(&c->journal.lock);
        wait = true;
    }
}

/*static void journal_write_work(struct work_struct *work)*/
/*{*/
	/*struct cache_set *c = container_of(to_delayed_work(work),*/
					   /*struct cache_set,*/
					   /*journal.work);*/
	/*spin_lock(&c->journal.lock);*/
	/*if (c->journal.cur->dirty)*/
		/*journal_try_write(c);*/
	/*else*/
		/*spin_unlock(&c->journal.lock);*/
/*}*/

/*
 * Entry point to the journalling code - bio_insert() and btree_invalidate()
 * pass bch_journal() a list of keys to be journalled, and then
 * bch_journal() hands those same keys off to btree_insert_async()
 * 向btree添加时，调用该函数建立journal
 */
/*atomic_t *bch_journal(struct cache_set *c,*/
                      /*struct keylist *keys,*/
                      /*struct closure *parent)*/
atomic_t *bch_journal(struct cache_set *c,
                      struct keylist *keys)
{
    struct journal_write *w = NULL;
    atomic_t *ret;

    /*printf(" journal.c FUN %s: Journal nkeys=%d\n",__func__,bch_keylist_nkeys(keys));*/
    if (!CACHE_SYNC(&c->sb))
    {
        /*printf(" journal.c FUN %s: CACHE_SYNC=0, Do not allow journal\n",__func__);*/
        return NULL;
    }
    /*printf(" journal.c FUN %s: Journal Start Wait for write\n",__func__);*/
    w = journal_wait_for_write(c, bch_keylist_nkeys(keys));
    /*printf(" journal.c FUN %s: Journal End Wait for write\n",__func__);*/

    memcpy(bset_bkey_last(w->data), keys->keys, bch_keylist_bytes(keys));
    w->data->keys += bch_keylist_nkeys(keys);
    /*printf(" journal.c FUN %s: Journal befor update pin fifo_used=%d\n",__func__,fifo_used(&c->journal.pin));*/
    ret = &fifo_back(&c->journal.pin);
    atomic_inc(ret);
    /*printf(" journal.c FUN %s: Journal after update pin fifo_used=%d\n",__func__,fifo_used(&c->journal.pin));*/

    /*printf(" journal.c FUN %s: Journal Start Write\n",__func__);*/
    journal_try_write(c);
    /*printf(" journal.c FUN %s: Journal End Write\n",__func__);*/

    /*if (parent) {*/
            /*closure_wait(&w->wait, parent);*/
            /*journal_try_write(c);*/
    /*} else if (!w->dirty) {*/
            /*w->dirty = true;*/
            /*schedule_delayed_work(&c->journal.work,*/
                                  /*msecs_to_jiffies(c->journal_delay_ms));*/
            /*spin_unlock(&c->journal.lock);*/
    /*} else {*/
            /*spin_unlock(&c->journal.lock);*/
    /*}*/


    return ret;
}

/*void bch_journal_meta(struct cache_set *c, struct closure *cl)*/
void bch_journal_meta(struct cache_set *c)
{
        struct keylist keys;
        atomic_t *ref;
        bch_keylist_init(&keys);
        ref = bch_journal(c, &keys);
        if (ref)
                atomic_dec_bug(ref);
}

/*void bch_journal_free(struct cache_set *c)*/
/*{*/
	/*free_pages((unsigned long) c->journal.w[1].data, JSET_BITS);*/
	/*free_pages((unsigned long) c->journal.w[0].data, JSET_BITS);*/
	/*free_fifo(&c->journal.pin);*/
/*}*/

int bch_journal_alloc(struct cache_set *c)
{
        struct journal *j = &c->journal;

	/*spin_lock_init(&j->lock);*/
        pthread_spin_init(&j->lock, 0);
	/*INIT_DELAYED_WORK(&j->work, journal_write_work);*/

        c->journal_delay_ms = 100;

        j->w[0].c = c;
        j->w[1].c = c;

	/*
	 * __get_free_pages(unsigned int flags, unsigned int order);
	 * order是请求的页数以2为底的对数，这里为3，就是请求分配8个页(32KB)
	 */
        /*if (!(init_fifo(&j->pin, JOURNAL_PIN, GFP_KERNEL)) ||*/
	    /*!(j->w[0].data = (void *) __get_free_pages(GFP_KERNEL, JSET_BITS)) ||*/
	    /*!(j->w[1].data = (void *) __get_free_pages(GFP_KERNEL, JSET_BITS)))*/
		/*return -ENOMEM;*/
        if (!(init_fifo(&j->pin, JOURNAL_PIN)) ||
            !(j->w[0].data = (void *) T2Molloc(PAGE_SIZE << JSET_BITS )) ||
            !(j->w[1].data = (void *) T2Molloc(PAGE_SIZE << JSET_BITS )))
                return -ENOMEM;

        /*printf(" journal.c FUN %s: pin used=%d,JSET_BITS=%d\n",__func__,fifo_used(&j->pin),JSET_BITS);*/
        return 0;
}
