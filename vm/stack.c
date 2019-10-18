#include "master.h"

void reset_datastack(void)
{
	ds = ds_bot - CELLS;
}

void reset_retainstack(void)
{
	rs = rs_bot - CELLS;
}

void reset_callstack(void)
{
	cs = cs_bot;
}

void fix_stacks(void)
{
	if(ds + CELLS < ds_bot || ds >= ds_top) reset_datastack();
	if(rs + CELLS < rs_bot || rs >= rs_top) reset_retainstack();
	if(cs < cs_bot || cs + 1 >= cs_top) reset_callstack();
}

/* called before entry into foreign C code. Note that ds, rs and cs might
be stored in registers, so callbacks must save and restore the correct values */
void save_stacks(void)
{
	stack_chain->data = ds;
	stack_chain->retain = rs;
	stack_chain->call = cs;
}

/* called on entry into a compiled callback */
void nest_stacks(void)
{
	F_CONTEXT *new_stacks = safe_malloc(sizeof(F_CONTEXT));
	
	/* note that these register values are not necessarily valid stack
	pointers. they are merely saved non-volatile registers, and are
	restored in unnest_stacks(). consider this scenario:
	- factor code calls C function
	- C function saves ds/cs registers (since they're non-volatile)
	- C function clobbers them
	- C function calls Factor callback
	- Factor callback returns
	- C function restores registers
	- C function returns to Factor code */
	new_stacks->data_save = ds;
	new_stacks->retain_save = rs;
	new_stacks->call_save = cs;
	new_stacks->primitives = primitives;

	new_stacks->callframe = callframe;

	/* save per-callback userenv */
	new_stacks->current_callback_save = userenv[CURRENT_CALLBACK_ENV];
	new_stacks->catchstack_save = userenv[CATCHSTACK_ENV];

	new_stacks->data_region = alloc_segment(ds_size);
	new_stacks->retain_region = alloc_segment(rs_size);
	new_stacks->call_region = alloc_segment(cs_size);

	new_stacks->extra_roots = extra_roots;

	new_stacks->next = stack_chain;
	stack_chain = new_stacks;

	reset_datastack();
	reset_retainstack();
	reset_callstack();
	init_primitives();
	init_interpreter();
}

/* called when leaving a compiled callback */
void unnest_stacks(void)
{
	dealloc_segment(stack_chain->data_region);
	dealloc_segment(stack_chain->retain_region);
	dealloc_segment(stack_chain->call_region);

	ds = stack_chain->data_save;
	rs = stack_chain->retain_save;
	cs = stack_chain->call_save;
	primitives = stack_chain->primitives;

	callframe = stack_chain->callframe;

	/* restore per-callback userenv */
	userenv[CURRENT_CALLBACK_ENV] = stack_chain->current_callback_save;
	userenv[CATCHSTACK_ENV] = stack_chain->catchstack_save;

	extra_roots = stack_chain->extra_roots;

	F_CONTEXT *old_stacks = stack_chain;
	stack_chain = old_stacks->next;
	free(old_stacks);
}

/* called on startup */
void init_stacks(CELL ds_size_, CELL rs_size_, CELL cs_size_)
{
	ds_size = ds_size_;
	rs_size = rs_size_;
	cs_size = cs_size_;
	stack_chain = NULL;
}

void primitive_drop(void)
{
	dpop();
}

void primitive_2drop(void)
{
	ds -= 2 * CELLS;
}

void primitive_3drop(void)
{
	ds -= 3 * CELLS;
}

void primitive_dup(void)
{
	dpush(dpeek());
}

void primitive_2dup(void)
{
	CELL top = dpeek();
	CELL next = get(ds - CELLS);
	ds += CELLS * 2;
	put(ds - CELLS,next);
	put(ds,top);
}

void primitive_3dup(void)
{
	CELL c1 = dpeek();
	CELL c2 = get(ds - CELLS);
	CELL c3 = get(ds - CELLS * 2);
	ds += CELLS * 3;
	put (ds,c1);
	put (ds - CELLS,c2);
	put (ds - CELLS * 2,c3);
}

void primitive_rot(void)
{
	CELL c1 = dpeek();
	CELL c2 = get(ds - CELLS);
	CELL c3 = get(ds - CELLS * 2);
	put(ds,c3);
	put(ds - CELLS,c1);
	put(ds - CELLS * 2,c2);
}

void primitive__rot(void)
{
	CELL c1 = dpeek();
	CELL c2 = get(ds - CELLS);
	CELL c3 = get(ds - CELLS * 2);
	put(ds,c2);
	put(ds - CELLS,c3);
	put(ds - CELLS * 2,c1);
}

void primitive_dupd(void)
{
	CELL top = dpeek();
	CELL next = get(ds - CELLS);
	put(ds,next);
	put(ds - CELLS,next);
	dpush(top);
}

void primitive_swapd(void)
{
	CELL top = get(ds - CELLS);
	CELL next = get(ds - CELLS * 2);
	put(ds - CELLS,next);
	put(ds - CELLS * 2,top);
}

void primitive_nip(void)
{
	CELL top = dpop();
	drepl(top);
}

void primitive_2nip(void)
{
	CELL top = dpeek();
	ds -= CELLS * 2;
	drepl(top);
}

void primitive_tuck(void)
{
	CELL top = dpeek();
	CELL next = get(ds - CELLS);
	put(ds,next);
	put(ds - CELLS,top);
	dpush(top);
}

void primitive_over(void)
{
	dpush(get(ds - CELLS));
}

void primitive_pick(void)
{
	dpush(get(ds - CELLS * 2));
}

void primitive_swap(void)
{
	CELL top = dpeek();
	CELL next = get(ds - CELLS);
	put(ds,next);
	put(ds - CELLS,top);
}

void primitive_to_r(void)
{
	rpush(dpop());
}

void primitive_from_r(void)
{
	dpush(rpop());
}

void stack_to_vector(CELL bottom, CELL top)
{
	F_FIXNUM depth = (F_FIXNUM)(top - bottom + CELLS) / CELLS;
	if(depth < 0)
		depth = 0;
	F_ARRAY *a = allot_array_internal(ARRAY_TYPE,depth);
	memcpy(a + 1,(void*)bottom,depth * CELLS);
	dpush(tag_object(a));
	primitive_array_to_vector();
}

void primitive_datastack(void)
{
	stack_to_vector(ds_bot,ds);
}

void primitive_retainstack(void)
{
	stack_to_vector(rs_bot,rs);
}

void primitive_callstack(void)
{
	F_FIXNUM depth = (F_FIXNUM)(cs - cs_bot) - 1;
	if(depth < 0)
		depth = 0;
	F_ARRAY *a = allot_array_internal(ARRAY_TYPE,depth * 3);

	CELL i;
	for(i = 0; i < depth; i++)
	{
		F_INTERP_FRAME *frame = cs_bot + i;
		CELL untagged = UNTAG(frame->quot);
		CELL scan = tag_fixnum(UNAREF(untagged,frame->scan));
		CELL end = tag_fixnum(UNAREF(untagged,frame->end));
		set_array_nth(a,3 * i,frame->quot);
		set_array_nth(a,3 * i + 1,scan);
		set_array_nth(a,3 * i + 2,end);
	}

	dpush(tag_object(a));
	primitive_array_to_vector();
}

/* returns pointer to top of stack */
CELL vector_to_stack(F_VECTOR* vector, CELL bottom)
{
	CELL start = bottom;
	CELL len = untag_fixnum_fast(vector->top) * CELLS;
	memcpy((void*)start,untag_array_fast(vector->array) + 1,len);
	return start + len - CELLS;
}

void primitive_set_datastack(void)
{
	ds = vector_to_stack(untag_vector(dpop()),ds_bot);
}

void primitive_set_retainstack(void)
{
	rs = vector_to_stack(untag_vector(dpop()),rs_bot);
}

void primitive_set_callstack(void)
{
	F_VECTOR *v = untag_vector(dpop());
	F_ARRAY *a = untag_array_fast(v->array);
	CELL depth = untag_fixnum_fast(v->top) / 3;

	CELL i;
	for(i = 0; i < depth; i++)
	{
		CELL quot = get(AREF(a,3 * i));
		type_check(QUOTATION_TYPE,quot);

		F_ARRAY *untagged = untag_array_fast(quot);
		CELL length = array_capacity(untagged);

		F_FIXNUM position = to_fixnum(get(AREF(a,3 * i + 1)));
		F_FIXNUM end = to_fixnum(get(AREF(a,3 * i + 2)));

		if(end < 0) end = 0;
		if(end > length) end = length;
		if(position < 0) position = 0;
		if(position > end) position = end;

		cs_bot[i].quot = quot;
		cs_bot[i].scan = AREF(untagged,position);
		cs_bot[i].end = AREF(untagged,end);
	}

	cs = cs_bot + depth;
}
