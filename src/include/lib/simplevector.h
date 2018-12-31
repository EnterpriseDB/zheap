/*-------------------------------------------------------------------------
 *
 * simplevector.h
 *
 *	  Vector implementation that will be specialized for user-defined types,
 *	  by including this file to generate the required code.  Suitable for
 *	  value types that can be bitwise copied and moved.  Includes an in-place
 *	  small-vector optimization, so that allocation can be avoided until the
 *	  internal space is exceeded.
 *
 * Copyright (c) 2019, PostgreSQL Global Development Group
 *
 * Usage notes:
 *
 *	  To generate a type and associates functions, the following parameter
 *	  macros should be #define'd before this file is included.
 *
 *	  - SV_PREFIX - prefix for all symbol names generated.
 *	  - SV_ELEMENT_TYPE - type of the contained elements
 *	  - SV_DECLARE - if defined the functions and types are declared
 *	  - SV_DEFINE - if defined the functions and types are defined
 *	  - SV_SCOPE - scope (e.g. extern, static inline) for functions
 *
 * IDENTIFICATION
 *		src/include/lib/simplevector.h
 *
 *-------------------------------------------------------------------------
 */

/* helpers */
#define SV_MAKE_PREFIX(a) CppConcat(a,_)
#define SV_MAKE_NAME(name) SV_MAKE_NAME_(SV_MAKE_PREFIX(SV_PREFIX),name)
#define SV_MAKE_NAME_(a,b) CppConcat(a,b)

/* type declarations */
#define SV_TYPE SV_PREFIX

/* function declarations */
#define SV_INIT SV_MAKE_NAME(init)
#define SV_DESTROY SV_MAKE_NAME(destroy)
#define SV_RESET SV_MAKE_NAME(reset)
#define SV_CLEAR SV_MAKE_NAME(clear)
#define SV_DATA SV_MAKE_NAME(data)
#define SV_EMPTY SV_MAKE_NAME(empty)
#define SV_SIZE SV_MAKE_NAME(size)
#define SV_RESIZE SV_MAKE_NAME(resize)
#define SV_CAPACITY SV_MAKE_NAME(capacity)
#define SV_RESERVE SV_MAKE_NAME(reserve)
#define SV_APPEND SV_MAKE_NAME(append)
#define SV_APPEND_N SV_MAKE_NAME(append_n)
#define SV_INSERT SV_MAKE_NAME(insert)
#define SV_INSERT_N SV_MAKE_NAME(insert_n)
#define SV_ERASE SV_MAKE_NAME(erase)
#define SV_ERASE_N SV_MAKE_NAME(erase_n)
#define SV_BEGIN SV_MAKE_NAME(begin)
#define SV_END SV_MAKE_NAME(end)
#define SV_BACK SV_MAKE_NAME(back)
#define SV_POP_BACK SV_MAKE_NAME(pop_back)
#define SV_SWAP SV_MAKE_NAME(swap)

#ifndef SV_IN_PLACE_CAPACITY
#define SV_IN_PLACE_CAPACITY 3
#endif

#ifdef SV_DECLARE

typedef struct SV_TYPE
{
	/*
	 * If size is <= SV_IN_PLACE_CAPACITY, then it represents the number of
	 * elements stored in u.elements.  Otherwise, it is the capacity of the
	 * buffer in u.overflow.data (in number of potential elements), and
	 * u.overflow.count represents the number of occupied elements.
	 */
	uint32		size;
	union
	{
		struct
		{
			void	   *data;
			uint32		count;
		} overflow;
		SV_ELEMENT_TYPE elements[SV_IN_PLACE_CAPACITY];
	} u;
}		SV_TYPE;

/* externally visible function prototypes */
SV_SCOPE void SV_INIT(SV_TYPE *vec);
SV_SCOPE void SV_DESTROY(SV_TYPE *vec);
SV_SCOPE void SV_RESET(SV_TYPE *vec);
SV_SCOPE void SV_CLEAR(SV_TYPE *vec);
SV_SCOPE SV_ELEMENT_TYPE *SV_DATA(SV_TYPE *vec);
SV_SCOPE bool SV_EMPTY(SV_TYPE *vec);
SV_SCOPE uint32 SV_SIZE(SV_TYPE *vec);
SV_SCOPE void SV_RESIZE(SV_TYPE *vec, uint32 size);
SV_SCOPE uint32 SV_CAPACITY(SV_TYPE *vec);
SV_SCOPE void SV_RESERVE(SV_TYPE *vec, uint32 capacity);
SV_SCOPE void SV_APPEND(SV_TYPE *vec, const SV_ELEMENT_TYPE *value);
SV_SCOPE void SV_APPEND_N(SV_TYPE *vec, const SV_ELEMENT_TYPE *values,
						  uint32 size);
SV_SCOPE void SV_INSERT(SV_TYPE *vec,
						SV_ELEMENT_TYPE *position,
						const SV_ELEMENT_TYPE *value);
SV_SCOPE void SV_INSERT_N(SV_TYPE *vec,
						  SV_ELEMENT_TYPE *position,
						  const SV_ELEMENT_TYPE *values,
						  uint32 n);
SV_SCOPE void SV_ERASE(SV_TYPE *vec, SV_ELEMENT_TYPE *position);
SV_SCOPE void SV_ERASE_N(SV_TYPE *vec, SV_ELEMENT_TYPE *position, uint32 n);
SV_SCOPE void SV_SWAP(SV_TYPE *a, SV_TYPE *b);
SV_SCOPE SV_ELEMENT_TYPE *SV_BEGIN(SV_TYPE *vec);
SV_SCOPE SV_ELEMENT_TYPE *SV_END(SV_TYPE *vec);
SV_SCOPE SV_ELEMENT_TYPE *SV_BACK(SV_TYPE *vec);
SV_SCOPE void SV_POP_BACK(SV_TYPE *vec);

#endif

#ifdef SV_DEFINE

/*
 * Initialize a vector in-place.
 */
SV_SCOPE void
SV_INIT(SV_TYPE *vec)
{
	vec->size = 0;
}

/*
 * Free any resources owned by the vector.
 */
SV_SCOPE void
SV_DESTROY(SV_TYPE *vec)
{
	SV_RESET(vec);
}

/*
 * Free any resources owned by the vector.
 */
SV_SCOPE void
SV_RESET(SV_TYPE *vec)
{
	if (vec->size > SV_IN_PLACE_CAPACITY)
		pfree(vec->u.overflow.data);
	vec->size = 0;
}

/*
 * Clear the vector so that it contains no elements.
 */
SV_SCOPE void
SV_CLEAR(SV_TYPE *vec)
{
	if (vec->size > SV_IN_PLACE_CAPACITY)
		vec->u.overflow.count = 0;
	else
		vec->size = 0;
}

/*
 * Return a pointer to the elements in the vector.
 */
SV_SCOPE SV_ELEMENT_TYPE *
SV_DATA(SV_TYPE *vec)
{
	if (vec->size > SV_IN_PLACE_CAPACITY)
		return vec->u.overflow.data;
	else
		return &vec->u.elements[0];
}

/*
 * Check if the vector is empty (has no elements).
 */
SV_SCOPE bool
SV_EMPTY(SV_TYPE *vec)
{
	return SV_SIZE(vec) == 0;
}

/*
 * Return the number of elements in the vector.
 */
SV_SCOPE uint32
SV_SIZE(SV_TYPE *vec)
{
	if (vec->size > SV_IN_PLACE_CAPACITY)
		return vec->u.overflow.count;
	else
		return vec->size;
}

/*
 * Resize the vector, discarding elements at the end, or creating new
 * zero-initialized elements as required.
 */
SV_SCOPE void
SV_RESIZE(SV_TYPE *vec, uint32 size)
{
	uint32		old_size = SV_SIZE(vec);

	/* Growing? */
	if (size > old_size)
	{
		SV_RESERVE(vec, size);
		memset(&SV_DATA(vec)[old_size], 0,
			   sizeof(SV_ELEMENT_TYPE) * (size - old_size));
	}

	/* Set the new size. */
	if (vec->size <= SV_IN_PLACE_CAPACITY)
		vec->size = size;
	else
		vec->u.overflow.count = size;
}

/*
 * Return the number of elements that can be held in the vector before it
 * needs to reallocate.
 */
SV_SCOPE uint32
SV_CAPACITY(SV_TYPE *vec)
{
	if (vec->size > SV_IN_PLACE_CAPACITY)
		return vec->size;
	else
		return SV_IN_PLACE_CAPACITY;
}

/*
 * Make sure we have capacity for a given number of elements without having to
 * reallocate.
 */
SV_SCOPE void
SV_RESERVE(SV_TYPE *vec, uint32 capacity)
{
	void *new_buffer;

	/* Do nothing if we already have that much capacity. */
	if (capacity <= SV_IN_PLACE_CAPACITY || capacity < vec->size)
		return;

	/* Allocate larger buffer. */
#ifdef SV_GLOBAL_MEMORY_CONTEXT
	new_buffer = MemoryContextAlloc(SV_GLOBAL_MEMORY_CONTEXT,
									sizeof(SV_ELEMENT_TYPE) * capacity);
#else
	new_buffer = palloc(sizeof(SV_ELEMENT_TYPE) * capacity);
#endif

	/* Copy existing data to new buffer. */
	if (vec->size <= SV_IN_PLACE_CAPACITY)
	{
		/* Promote from in-line format. */
		if (vec->size > 0)
			memcpy(new_buffer,
				   vec->u.elements,
				   sizeof(SV_ELEMENT_TYPE) * vec->size);
		vec->u.overflow.count = vec->size;
	}
	else
	{
		/* Copy from existing smaller overflow buffer, and free it. */
		if (vec->u.overflow.count > 0)
			memcpy(new_buffer,
				   vec->u.overflow.data,
				   sizeof(SV_ELEMENT_TYPE) * vec->u.overflow.count);
		Assert(vec->u.overflow.data);
		pfree(vec->u.overflow.data);
	}
	vec->u.overflow.data = new_buffer;
	vec->size = capacity;
}

/*
 * Append a value to the end of a vector.
 */
SV_SCOPE void
SV_APPEND(SV_TYPE *vec, const SV_ELEMENT_TYPE *value)
{
	SV_APPEND_N(vec, value, 1);
}

/*
 * Append N values to the end of a vector.
 */
SV_SCOPE void
SV_APPEND_N(SV_TYPE *vec, const SV_ELEMENT_TYPE *values, uint32 n)
{
	uint32		size = SV_SIZE(vec);

	SV_RESERVE(vec, size + n);
	memcpy(&SV_DATA(vec)[size], values, sizeof(SV_ELEMENT_TYPE) * n);
	if (vec->size > SV_IN_PLACE_CAPACITY)
		vec->u.overflow.count += n;
	else
		vec->size += n;
}

/*
 * Insert a value before an arbitrary position in the vector.  This is not
 * especially efficient as it must shift values to make space.
 */
SV_SCOPE void
SV_INSERT(SV_TYPE *vec, SV_ELEMENT_TYPE *position, const SV_ELEMENT_TYPE *value)
{
	SV_INSERT_N(vec, position, value, 1);
}

/*
 * Insert N values before an arbitrary position in the vector.  This is not
 * especially efficient as it must shift values to make space.
 */
SV_SCOPE void
SV_INSERT_N(SV_TYPE *vec, SV_ELEMENT_TYPE *position,
			const SV_ELEMENT_TYPE *values, uint32 n)
{
	uint32		size = SV_SIZE(vec);
	uint32		i = position - SV_DATA(vec);
	SV_ELEMENT_TYPE *data;

	if (n == 0)
		return;

	Assert(position >= SV_DATA(vec) &&
		   position <= SV_DATA(vec) + size);
	SV_RESERVE(vec, size + n);
	data = SV_DATA(vec);
	memmove(&data[i + n],
			&data[i],
			sizeof(SV_ELEMENT_TYPE) * (size - i));
	memcpy(&data[i], values, sizeof(SV_ELEMENT_TYPE) * n);
	if (vec->size > SV_IN_PLACE_CAPACITY)
		vec->u.overflow.count += n;
	else
		vec->size += n;
}

/*
 * Erase an arbitarary element in the vector.  This is not especially
 * efficient as it must shift trailing values.
 */
SV_SCOPE void
SV_ERASE(SV_TYPE *vec, SV_ELEMENT_TYPE *position)
{
	SV_ERASE_N(vec, position, 1);
}

/*
 * Erase N values begining with an arbitarary element in the vector.  This is
 * not especially efficient as it must shift trailing values.
 */
SV_SCOPE void
SV_ERASE_N(SV_TYPE *vec, SV_ELEMENT_TYPE *position, uint32 n)
{
	Assert(position >= SV_DATA(vec) &&
		   position + n <= SV_DATA(vec) + SV_SIZE(vec));
	memmove(position,
			position + n,
			sizeof(SV_ELEMENT_TYPE) * (SV_SIZE(vec) - n));
	if (vec->size > SV_IN_PLACE_CAPACITY)
		vec->u.overflow.count -= n;
	else
		vec->size -= n;
}

/*
 * Get a pointer to the first element, if there is one.
 */
SV_SCOPE SV_ELEMENT_TYPE *
SV_BEGIN(SV_TYPE *vec)
{
	return SV_DATA(vec);
}

/*
 * Get a pointer to the element past the last element.
 */
SV_SCOPE SV_ELEMENT_TYPE *
SV_END(SV_TYPE *vec)
{
	return SV_DATA(vec) + SV_SIZE(vec);
}

/*
 * Get a pointer to the back (last) element.
 */
SV_SCOPE SV_ELEMENT_TYPE *
SV_BACK(SV_TYPE *vec)
{
	Assert(!SV_EMPTY(vec));
	return SV_DATA(vec) + SV_SIZE(vec) - 1;
}

/*
 * Remove the back (last) element.
 */
SV_SCOPE void
SV_POP_BACK(SV_TYPE *vec)
{
	Assert(!SV_EMPTY(vec));
	SV_RESIZE(vec, SV_SIZE(vec) - 1);
}

/*
 * Swap the contents of two vectors.
 */
SV_SCOPE void
SV_SWAP(SV_TYPE *a, SV_TYPE *b)
{
	SV_TYPE		tmp;

	tmp = *a;
	*a = *b;
	*b = tmp;
}

#endif

#undef SV_APPEND
#undef SV_APPEND_N
#undef SV_BACK
#undef SV_BEGIN
#undef SV_CAPACITY
#undef SV_CLEAR
#undef SV_DATA
#undef SV_DECLARE
#undef SV_DEFINE
#undef SV_DESTROY
#undef SV_EMPTY
#undef SV_END
#undef SV_ERASE
#undef SV_ERASE_N
#undef SV_INIT
#undef SV_INSERT
#undef SV_INSERT_N
#undef SV_IN_PLACE_CAPACITY
#undef SV_MAKE_NAME
#undef SV_MAKE_NAME_
#undef SV_MAKE_PREFIX
#undef SV_POP_BACK
#undef SV_RESERVE
#undef SV_RESET
#undef SV_RESIZE
#undef SV_SIZE
#undef SV_SWAP
