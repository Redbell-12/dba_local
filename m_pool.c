#include<stdlib.h>
#include<stdio.h>
//#include"m_pool.h"
#include "define.h"

static void insert_node(struct m_pool *self,struct node *p){
	/*节点入链-按size从小到大的顺序找一个合适的位置插入*/
	struct node *h=self->pool;//h最后指向size不大于待插入节点的size，我们要将待插入节点插入h节点的前面，所以我们还需要一个h_before指针
	struct node *h_before=self->pool;
	while(h->next!=NULL){
		h=h->next;
		if(p->size > h->size){
			continue;
printf("here\n");
}
		else
			break;
	}
	//判断while循环是因为h等NULL而跳出还是因为break
	//如果是前者说明待插入节点的size比目前内存块链中所有节点的size都要大，则我们将其插入链的末尾
	if(h->next==NULL){
		//此时h指向最后一个节点。插入待插入节点在最后一个节点后
		h->next=p;
	}else{//因为break而跳出
		//将h_before移动到h所指节点的前一个节点
		while(h_before->next!=h)
			h_before=h_before->next;
		//将待插入节点插入h_before所指节点的后面
		p->next=h_before->next;
		h_before->next=p;
	}

	/*更新内存池的统计信息*/
	if(p->size > self->node_size_max)
		self->node_size_max=p->size;
	if(p->size < self->node_size_min)
		self->node_size_min=p->size;
	self->node_num++;
}
	
/*初始化内存池*/
void m_init(struct m_pool *self){
	self->node_size_max=0;
	//如果初始化设成0的话，那么这个成员将永远是0，因为用户不可能申请比0还小的内存块
	//所以这里设成此成员所能存放的最大正整数
	self->node_size_min=0x7fffffff;
	self->node_num=0;
	struct node *h=malloc(sizeof(struct node));//头节点
	if(h==NULL)
		fprintf(stderr,"初始化内存池失败\n");
	//初始化头节点
	h->size=0;
	h->using=1;//头节点不被用户使用，所以我们永远置为忙状态
	self->pool=h;
}
/*从self指向的池中申请bytes字节的内存空间*/
void *m_malloc(struct m_pool *self,int bytes){
	/*搜索self指向的内存池中的节点，找size大于等于bytes的节点*/
	struct node *h=self->pool;
	while(h->next!=NULL){
		h=h->next;
		/*节点当前没在使用，且尺寸大于申请要求*/
		if(h->using==0 && h->size >= bytes){
			h->using=1;
			return h->user_area;
		}
	}
	/*池中没找到合适的节点，那咱们向系统申请*/
	struct node *r=malloc(sizeof(struct node)+bytes);
	if(r==NULL){
		fprintf(stderr,"向系统申请内存失败\n");
		return NULL;
	}else{
		//初始化节点
		r->size=bytes;
		r->using=1;
		r->next=NULL;
		//节点入链-按size从小到大的顺序
		insert_node(self,r);
		return r->user_area;
	}
}
/*用户要释放某内存块时，送给m_free的地址是内存块的用户区地址，即node
 *的user_area处，所以m_free函数要通过这个地址反向移动到node的开头处*/
int m_free(char *p){
	/*将p从节点的用户数据区移动到节点的开头*/
	struct node *q=(struct node *)(p-sizeof(struct node));
	/*将这个内存块的使用状态置0，即未使用*/
	q->using=0;
	/*将用户区清零。这一步做或不做均可，这里不做的话，就由用户做*/
}

/*销毁内存池，释放池中所有内存块*/
int m_destroy(struct m_pool *self){
	struct node *p=self->pool;
	struct node *q;
	while(p!=NULL){
		q=p->next;
		free(p);
		p=q;
	}
}
