/*-------------------------------------------------------------------------
 *
 * sort_utils.h
 *
 *	  Simple sorting-related algorithms specialized for arrays of
 *	  paramaterized type, using inlined comparators.
 *
 * Copyright (c) 2019, PostgreSQL Global Development Group
 *
 * Usage notes:
 *
 *	  To generate functions specialized for a type, the following parameter
 *	  macros should be #define'd before this file is included.
 *
 *	  - SA_PREFIX - prefix for all symbol names generated.
 *	  - SA_ELEMENT_TYPE - type of the referenced elements
 *	  - SA_DECLARE - if defined the functions and types are declared
 *	  - SA_DEFINE - if defined the functions and types are defined
 *	  - SA_SCOPE - scope (e.g. extern, static inline) for functions
 *
 *	  The following are relevant only when SA_DEFINE is defined:
 *
 *	  - SA_COMPARE(a, b) - an expression to compare pointers to two values
 *
 * IDENTIFICATION
 *		src/include/lib/sort_utils.h
 *
 *-------------------------------------------------------------------------
 */

#define SA_MAKE_PREFIX(a) CppConcat(a,_)
#define SA_MAKE_NAME(name) SA_MAKE_NAME_(SA_MAKE_PREFIX(SA_PREFIX),name)
#define SA_MAKE_NAME_(a,b) CppConcat(a,b)

/* function declarations */
#define SA_SORT SA_MAKE_NAME(sort)
#define SA_UNIQUE SA_MAKE_NAME(unique)
#define SA_BINARY_SEARCH SA_MAKE_NAME(binary_search)
#define SA_LOWER_BOUND SA_MAKE_NAME(lower_bound)

#ifdef SA_DECLARE

SA_SCOPE void SA_SORT(SA_ELEMENT_TYPE *first, SA_ELEMENT_TYPE *last);
SA_SCOPE SA_ELEMENT_TYPE *SA_UNIQUE(SA_ELEMENT_TYPE *first,
									SA_ELEMENT_TYPE *last);
SA_SCOPE SA_ELEMENT_TYPE *SA_BINARY_SEARCH(SA_ELEMENT_TYPE *first,
										   SA_ELEMENT_TYPE *last,
										   SA_ELEMENT_TYPE *value);
SA_SCOPE SA_ELEMENT_TYPE *SA_LOWER_BOUND(SA_ELEMENT_TYPE *first,
										 SA_ELEMENT_TYPE *last,
										 SA_ELEMENT_TYPE *value);

#endif

#ifdef SA_DEFINE

/* helper functions */
#define SA_MED3 SA_MAKE_NAME(med3)
#define SA_SWAP SA_MAKE_NAME(swap)
#define SA_SWAPN SA_MAKE_NAME(swapn)

static inline SA_ELEMENT_TYPE *
SA_MED3(SA_ELEMENT_TYPE *a,
		SA_ELEMENT_TYPE *b,
		SA_ELEMENT_TYPE *c)
{
	return SA_COMPARE(a, b) < 0 ?
		(SA_COMPARE(b, c) < 0 ? b : (SA_COMPARE(a, c) < 0 ? c : a))
		: (SA_COMPARE(b, c) > 0 ? b : (SA_COMPARE(a, c) < 0 ? a : c));
}

static inline void
SA_SWAP(SA_ELEMENT_TYPE *a, SA_ELEMENT_TYPE *b)
{
	SA_ELEMENT_TYPE tmp = *a;

	*a = *b;
	*b = tmp;
}

static inline void
SA_SWAPN(SA_ELEMENT_TYPE *a, SA_ELEMENT_TYPE *b, size_t n)
{
	size_t		i;

	for (i = 0; i < n; ++i)
		SA_SWAP(&a[i], &b[i]);
}

/*
 * Sort an array [first, last).  This is the same algorithm as
 * src/port/qsort.c, parameterized at compile-time for comparison and element
 * type.
 */
SA_SCOPE void
SA_SORT(SA_ELEMENT_TYPE *first, SA_ELEMENT_TYPE *last)
{
	SA_ELEMENT_TYPE *a = first,
			   *pa,
			   *pb,
			   *pc,
			   *pd,
			   *pl,
			   *pm,
			   *pn;
	size_t		d1,
				d2;
	int			r,
				presorted;
	size_t		n = last - first;

loop:
	if (n < 7)
	{
		for (pm = a + 1; pm < a + n; ++pm)
			for (pl = pm; pl > a && SA_COMPARE(pl - 1, pl) > 0; --pl)
				SA_SWAP(pl, pl - 1);
		return;
	}
	presorted = 1;
	for (pm = a + 1; pm < a + n; ++pm)
	{
		if (SA_COMPARE(pm - 1, pm) > 0)
		{
			presorted = 0;
			break;
		}
	}
	if (presorted)
		return;
	pm = a + (n / 2);
	if (n > 7)
	{
		pl = a;
		pn = a + (n - 1);
		if (n > 40)
		{
			size_t		d = n / 8;

			pl = SA_MED3(pl, pl + d, pl + 2 * d);
			pm = SA_MED3(pm - d, pm, pm + d);
			pn = SA_MED3(pn - 2 * d, pn - d, pn);
		}
		pm = SA_MED3(pl, pm, pn);
	}
	SA_SWAP(a, pm);
	pa = pb = a + 1;
	pc = pd = a + (n - 1);
	for (;;)
	{
		while (pb <= pc && (r = SA_COMPARE(pb, a)) <= 0)
		{
			if (r == 0)
			{
				SA_SWAP(pa, pb);
				++pa;
			}
			++pb;
		}
		while (pb <= pc && (r = SA_COMPARE(pc, a)) >= 0)
		{
			if (r == 0)
			{
				SA_SWAP(pc, pd);
				--pd;
			}
			--pc;
		}
		if (pb > pc)
			break;
		SA_SWAP(pb, pc);
		++pb;
		--pc;
	}
	pn = a + n;
	d1 = Min(pa - a, pb - pa);
	SA_SWAPN(a, pb - d1, d1);
	d1 = Min(pd - pc, pn - pd - 1);
	SA_SWAPN(pb, pn - d1, d1);
	d1 = pb - pa;
	d2 = pd - pc;
	if (d1 <= d2)
	{
		/* Recurse on left partition, then iterate on right partition */
		if (d1 > 1)
			SA_SORT(a, a + d1);
		if (d2 > 1)
		{
			/* Iterate rather than recurse to save stack space */
			/* SA_SORT(pn - d2, pn + d2) */
			a = pn - d2;
			n = d2;
			goto loop;
		}
	}
	else
	{
		/* Recurse on right partition, then iterate on left partition */
		if (d2 > 1)
			SA_SORT(pn - d2, pn);
		if (d1 > 1)
		{
			/* Iterate rather than recurse to save stack space */
			/* SA_SORT(a, a + d1) */
			n = d1;
			goto loop;
		}
	}
}

/*
 * Remove duplicates from an array [first, last).  Return the new last pointer
 * (ie one past the new end).
 */
SA_SCOPE SA_ELEMENT_TYPE *
SA_UNIQUE(SA_ELEMENT_TYPE *first, SA_ELEMENT_TYPE *last)
{
	SA_ELEMENT_TYPE *write_head;
	SA_ELEMENT_TYPE *read_head;

	if (last - first <= 1)
		return last;

	write_head = first;
	read_head = first + 1;

	while (read_head < last)
	{
		if (SA_COMPARE(read_head, write_head) != 0)
			*++write_head = *read_head;
		++read_head;
	}
	return write_head + 1;
}

/*
 * Find an element in the array of sorted values [first, last) that is equal
 * to a given value, in a sorted array.  Return NULL if there is none.
 */
SA_SCOPE SA_ELEMENT_TYPE *
SA_BINARY_SEARCH(SA_ELEMENT_TYPE *first,
				 SA_ELEMENT_TYPE *last,
				 SA_ELEMENT_TYPE *value)
{
	SA_ELEMENT_TYPE *lower = first;
	SA_ELEMENT_TYPE *upper = last - 1;

	while (lower <= upper)
	{
		SA_ELEMENT_TYPE *mid;
		int			cmp;

		mid = lower + (upper - lower) / 2;
		cmp = SA_COMPARE(mid, value);
		if (cmp < 0)
			lower = mid + 1;
		else if (cmp > 0)
			upper = mid - 1;
		else
			return mid;
	}

	return NULL;
}

/*
 * Find the first element in the range [first, last) that is not less than
 * value, in a sorted array.
 */
SA_SCOPE SA_ELEMENT_TYPE *
SA_LOWER_BOUND(SA_ELEMENT_TYPE *first,
			   SA_ELEMENT_TYPE *last,
			   SA_ELEMENT_TYPE *value)
{
	ptrdiff_t		count;

	count = last - first;
	while (count > 0)
	{
		SA_ELEMENT_TYPE *iter = first;
		ptrdiff_t		step = count / 2;

		iter += step;
		if (SA_COMPARE(iter, value) < 0)
		{
			first = ++iter;
			count -= step + 1;
		}
		else
			count = step;
	}
	return first;
}

#endif

#undef SA_BINARY_SEARCH
#undef SA_DECLARE
#undef SA_DEFINE
#undef SA_LOWER_BOUND
#undef SA_MAKE_NAME
#undef SA_MAKE_NAME
#undef SA_MAKE_NAME_
#undef SA_MAKE_PREFIX
#undef SA_MED3
#undef SA_SORT
#undef SA_SWAP
#undef SA_UNIQUE
