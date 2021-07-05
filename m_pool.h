#ifndef _M_POOL_H
#define _M_POOL_H

struct m_pool{
	/*最大的节点有多大*/
	int node_size_max;
	/*最小的节点有多小*/
	int node_size_min;
	/*目前这个池中有多少节点*/
	int node_num;
	/*内存池是一个链表，链中的每个节点就是一个内存块，这里的pool指向链表中的第一个节点*/
	/*链表中的内存块是按其size从小到大顺序排好的，为的是方便查找合适的尺寸的内存块*/
	struct node *pool;
};
struct node{
	int size;
	int using;
	struct node *next;
	char user_area[0];
};

void m_init(struct m_pool *self);
void *m_malloc(struct m_pool *self,int bytes);
int m_free(char *p);
int m_destroy(struct m_pool *self);

#endif
