/*
 * avl_tree.c
 * 
 * Copyright 2020 Che Hongwei <htc.chehw@gmail.com>
 * 
 * The MIT License (MIT)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"), to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
 * copies of the Software, and to permit persons to whom the Software is 
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all 
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
 * IN THE SOFTWARE.
 * 
 * 
 */

/**
 * origin: [ musl_libc-1.2.0 ]( https://www.musl-libc.org )
 *     musl as a whole is licensed under the following standard MIT license.
 *     Copyright © 2005-2020 Rich Felker, et al.
 * 
 * modified by: chehw (htc.chehw@gmail.com)
 *    - append a context parameter (user_data) to twalk() 
 *    - add items count
 *    - add tree_iterator
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <search.h>
#include "avl_tree.h"
#include "clib-stack.h"

struct avl_node {
	const void * key;
	struct avl_node * a[2];	// children: [0]==left, [1]==right
	int h;
};



/*************************************
 * AVL_tree
 ************************************/

static inline int height_of(struct avl_node * node) { return node ? node->h : 0; }
static int avl_rot(struct avl_node **p, struct avl_node *x, int dir /* deeper side */)
{
	struct avl_node * y = x->a[dir];
	struct avl_node * z = y->a[!dir];
	int hx = x->h;
	int hz = height_of(z);
	if (hz > height_of(y->a[dir])) {
		/*
		 *   x
		 *  / \ dir          z
		 * A   y            / \
		 *    / \   -->    x   y
		 *   z   D        /|   |\
		 *  / \          A B   C D
		 * B   C
		 */
		x->a[dir] = z->a[!dir];
		y->a[!dir] = z->a[dir];
		z->a[!dir] = x;
		z->a[dir] = y;
		x->h = hz;
		y->h = hz;
		z->h = hz+1;
	} else {
		/*
		 *   x               y
		 *  / \             / \
		 * A   y    -->    x   D
		 *    / \         / \
		 *   z   D       A   z
		 */
		x->a[dir] = z;
		y->a[!dir] = x;
		x->h = hz+1;
		y->h = hz+2;
		z = y;
	}
	*p = z;
	return z->h - hx;
}

/* balance *p, return 0 if height is unchanged.  */
static int avl_tree_balance(struct avl_node **p)
{
	struct avl_node *n = *p;
	int h0 = height_of(n->a[0]);
	int h1 = height_of(n->a[1]);
	if (h0 - h1 + 1u < 3u) {
		int old = n->h;
		n->h = h0<h1 ? h1+1 : h0+1;
		return n->h - old;
	}
	return avl_rot(p, n, h0<h1);
}

avl_tree_t * avl_tree_init(avl_tree_t * tree, void * user_data)
{
	if(NULL == tree) tree = calloc(1, sizeof(*tree));
	assert(tree);
	
	tree->user_data = user_data;
	return tree;
}

void avl_tree_cleanup(avl_tree_t * tree)
{
	avl_tree_destroy(tree->root, tree->on_free_data);
	tree->count = 0;
	tree->root = NULL;
	
	if(tree->stack) {
		clib_stack_cleanup(tree->stack);
		free(tree->stack);
		tree->stack = NULL;
	}
}

/* AVL tree height < 1.44*log2(nodes+2)-0.3, MAXH is a safe upper bound.  */
#define AVL_TREE_MAX_HEIGHT (sizeof(void*)*8*3/2)
void * avl_tree_add(struct avl_tree * tree, const void *key, int (*cmp)(const void *, const void *))
{
	assert(tree);
	struct avl_node **rootp = &tree->root;
	struct avl_node *n = *rootp;
	
	struct avl_node ** a[AVL_TREE_MAX_HEIGHT];
	struct avl_node *r;
	int i=0;
	a[i++] = rootp;
	
	for (;;) {
		if (!n)
			break;
		int c = cmp(key, n->key);
		if (!c)
			return n;
		a[i++] = &n->a[c>0];
		n = n->a[c>0];
	}
	
	r = malloc(sizeof *r);
	if (!r) return NULL;
	
	r->key = key;
	r->a[0] = r->a[1] = 0;
	r->h = 1;
	
	/* insert new node, rebalance ancestors.  */
	*a[--i] = r;
	++tree->count;
	while (i && avl_tree_balance(a[--i]));
	
	// printf("add node %p, value=%d\n", r, *(int *)r->key); 
	return r;
}

void * avl_tree_del(struct avl_tree * tree, const void *restrict key, int (*cmp)(const void *, const void *))
{
	assert(tree);
	struct avl_node ** rootp = &tree->root;
	
	struct avl_node **a[AVL_TREE_MAX_HEIGHT+1];
	struct avl_node *n = *rootp;
	int i=0;
	/* *a[0] is an arbitrary non-null pointer that is returned when
	   the root node is deleted.  */
	a[i++] = rootp;
	a[i++] = rootp;
	
	while(n) {
		int rc = cmp(key, n->key);
		if(0 == rc) break;
		a[i++] = &n->a[rc>0];
		n = n->a[rc>0];
	}
	if(NULL == n) return NULL;

	struct avl_node * parent = *a[i-2];
	struct avl_node *child = NULL;
	if (n->a[0]) {
		/* free the preceding node instead of the deleted one.  */
		struct avl_node *deleted = n;
		a[i++] = &n->a[0];
		n = n->a[0];
		while (n->a[1]) {
			a[i++] = &n->a[1];
			n = n->a[1];
		}
		deleted->key = n->key;
		child = n->a[0];
	} else {
		child = n->a[1];
	}
	/* freed node has at most one child, move it up and rebalance.  */
	free(n);
	*a[--i] = child;
	--tree->count;
	while (--i && avl_tree_balance(a[i]));
	return parent;
}

#undef AVL_TREE_MAX_HEIGHT

void *avl_tree_find(struct avl_tree * tree, const void *key, int (*cmp)(const void *, const void *))
{
	assert(tree);
	struct avl_node * n = tree->root;
	
	while(n) {
		int rc = cmp(key, n->key);
		if (0 == rc) break;
		n = n->a[(rc > 0)];
	}
	return n;
}

void avl_tree_destroy(struct avl_node *root, void (*on_free_data)(void *))
{
	struct avl_node *r = root;
	if (r == 0) return;
	
	avl_tree_destroy(r->a[0], on_free_data);
	avl_tree_destroy(r->a[1], on_free_data);
	
	if (on_free_data) on_free_data((void *)r->key);
	free(r);
}

static void walk(const struct avl_node *r, void (*action)(const struct avl_node *, const VISIT, int, void * user_data), int d, void * user_data)
{
	if (!r)
		return;
	if (r->h == 1)
		action(r, leaf, d, user_data);
	else {
		action(r, preorder, d, user_data);
		walk(r->a[0], action, d+1, user_data);
		action(r, postorder, d, user_data);
		walk(r->a[1], action, d+1, user_data);
		action(r, endorder, d, user_data);
	}
}

void  avl_tree_traverse(struct avl_tree * tree,
	void (* on_traverse)(const struct avl_node * nodep, const VISIT which, const int depth, void * user_data),
	void * user_data
)
{
	walk(tree->root, on_traverse, 0, user_data);
	return;
}


struct avl_tree_iter {
	struct avl_node * n;
	struct avl_tree_iter * parent;
	VISIT which;
};

static struct avl_tree_iter * avl_tree_iter_new(struct avl_node * n, struct avl_tree_iter * parent)
{
	struct avl_tree_iter * iter = calloc(1, sizeof(*iter));
	assert(iter);
	iter->n = n;
	iter->parent = parent;
	iter->which = preorder;
	return iter;
}

static void avl_tree_iter_free(struct avl_tree_iter * iter)
{
	free(iter);
	return;
}

static inline struct avl_node * get_next_iter(clib_stack_t * stack)
{
	// printf("=== %s()...\n", __FUNCTION__);
	assert(stack);
	
	if(NULL == stack->top) return NULL;
	
	struct avl_tree_iter * current = NULL;
	struct avl_node * r = NULL;
	while(stack->top)
	{
		current = clib_node_get_data(stack->top);
		if(NULL == current) return NULL;
		struct avl_tree_iter * child = NULL;
		
		r = current->n;
		if(NULL == r) {
			current = stack->pop(stack);
			avl_tree_iter_free(current);
			continue;
		}
		//~ printf("\tcurrent: %p, which=%d, r=%p(%d), a[0]=(%d), a[1]=(%d), r->h=%d\n", 
			//~ current, current->which, 
			//~ r, *(int *)r->key,
			//~ r->a[0]?*(int *)r->a[0]->key:-1,
			//~ r->a[1]?*(int *)r->a[1]->key:-1,
			//~ r->h);
		
		if(r->h == 1) {
			current->which = leaf;
		}
		
		switch(current->which)
		{
		case leaf: 
			current = stack->pop(stack);
			if(current->parent) {
				++current->parent->which;
			}
			avl_tree_iter_free(current);
			//~ printf("\t-- leaf: push back parent: %p\n", parent);
			//~ if(parent) {
				//~ parent->which++;
				//~ stack->push(stack, parent);
			//~ }
			return r;
		
		case preorder:
			if(r->a[0]) {
				child = avl_tree_iter_new(r->a[0], current);
				stack->push(stack, child);
				continue;
			}
			++current->which;
		case postorder:
			if(r->a[1]){
				child = avl_tree_iter_new(r->a[1], current);
				stack->push(stack, child);
				return r;
			}
			++current->which;
			current= stack->pop(stack);
			if(current->parent) {
				++current->parent->which;
			}
			avl_tree_iter_free(current);
			return r;
		case endorder:
			current= stack->pop(stack);
			if(current->parent) {
				++current->parent->which;
			}
			avl_tree_iter_free(current);
			break;
		default:
			assert(current->which >= preorder);
			assert(current->which <= leaf);
		}
	}
	return NULL;
}

struct avl_node * avl_tree_iter_begin(struct avl_tree * tree)
{
	if(NULL == tree->root) return NULL;
	
	clib_stack_t * stack = tree->stack;
	if(NULL == stack) {
		stack = clib_stack_init(NULL);
		assert(stack);
		
		tree->stack = stack;
	}
	assert(stack);
	clib_stack_cleanup(stack);
	
	struct avl_tree_iter * current = avl_tree_iter_new(tree->root, NULL);
	assert(current);
	
	stack->push(stack, current);
	return get_next_iter(stack);
}

struct avl_node * avl_tree_iter_next(struct avl_tree * tree)
{
	clib_stack_t * stack = tree->stack;
	if(NULL == stack) return avl_tree_iter_begin(tree);
	
	return get_next_iter(stack);
}


#undef AVL_TREE_MAX_HEIGHT

/******************************************************
 * TEST Module
 *****************************************************/
#if defined(_TEST_AVL_TREE) && defined(_STAND_ALONE)

struct sort_context
{
	int * data;
	int max_size;
	int count;
	
};

static void get_sorted_result(const struct avl_node * nodep, const VISIT which, const int depth, void * user_data)
{
	struct sort_context * ctx = user_data;
	assert(ctx);
	
	switch(which) 
	{
	case preorder: case endorder: break;
	case postorder: case leaf:
		assert(ctx->count < ctx->max_size);
		ctx->data[ctx->count++] = *(int *)nodep->key;
		break;
	default:
		break;
	}
}

static int on_compare(const void * a, const void * b)
{
	return *(int *)a - *(int *)b;
}


int main(int argc, char **argv)
{
#define N (10)
	int a[N] = { 1, 3, 5, 7, 9,
				  8, 6, 4, 2, 0 };
				  
	int sorted[N] = { 0 };
				  
	struct sort_context ctx = {
		.data = sorted,
		.max_size = N,
		.count = 0,
	};

	avl_tree_t tree[1];
	memset(tree, 0, sizeof(tree));
	
	avl_tree_init(tree, &ctx);
	for(int i = 0; i < N; ++i) avl_tree_add(tree, &a[i], on_compare);
	
	printf("tree.count: %d\n", (int)tree->count);

	avl_tree_traverse(tree, get_sorted_result, &ctx);
	
	for(int i = 0; i < N; ++i) printf("%d\n", sorted[i]);
	
	struct avl_node * node = avl_tree_iter_begin(tree);
	int i = 0;
	while(node)
	{
		printf("node %d(%p): value=%d\n", i++, node, *(int *)node->key);
		node = avl_tree_iter_next(tree); 
		
		clib_stack_t * stack = tree->stack;
		assert(stack);
		printf("-------- stack.count: %d, top=%p\n", (int)stack->count, stack->top);
		
		if(i > 10) break;
	}
	
	avl_tree_cleanup(tree);
#undef N
	return 0;
}
#endif

