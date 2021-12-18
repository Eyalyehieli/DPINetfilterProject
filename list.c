
#include <stdlib.h>
#include "list.h"
#include <stdio.h>

/*!@*****************************************************************************
 *!
 *! FUNCTION:			list_create
 *!
 *! GENERAL DESCRIPTION: This function initialize the list object to known state.
 *!						 This action must be done by the object list 's user before
 *!						 start to insert elements to the list otherwise the program
 *!						 may collapse.
 *!
 *!
 *!
 *! Input:				none.
 *!
 *! Output:				pointer to list object.
 *!						NULL if error
 *!
 *! ALGORITHM:			The algorithm is base on allocation space for new list
 *!						set all pointers reside in the list to NULL.
 *!
 *!
 *! ASSUMPTIONS:		There is enough room for list allocation.
 *! REMARKS:			none.
 *!
 *!*****************************************************************************
 *!@*/
list *list_create()
{
	list  *new_list =(list*)malloc (sizeof(list)); /* create new list object */
	if (new_list==NULL)
	{   /* in case of memory allocation fail */
		printf("List object : Error while memory allocation \n\r");
		return NULL;
	}

	/* list initialization */
	new_list->head=new_list->current=new_list->tail=NULL;
	new_list->nitems=0;
	return new_list;
}

/*!@*****************************************************************************
 *!
 *! FUNCTION:			list_add
 *!
 *! GENERAL DESCRIPTION: This function adds element to the list.
 *!						 The element is added in the tail of the list.
 *!
 *!
 *! Input:				list *listptr - pointer to list structure.
 *!						void *data    - pointer to element.
 *!
 *! Output:				ERROR - if fail.
 *						OK    - if success .
 *!
 *! ALGORITHM:			The algorithm is base on the following operations:
 *!						1. New node allocation.
 *!						2. Handle pointer reside in the object.
 *!
 *! ASSUMPTIONS:	    Before used this method the list_create function have been
 *!						established.
 *!					    The void * handle is under the user 's responsibility.
 *!
 *! REMARKS:			none.
 *!
 *!*****************************************************************************
 *!@*/
int list_add(list *listptr,void *data)
{

	node *nnode=(node*)malloc(sizeof(node)); /* create new node */
	if (nnode==NULL)
	{   /* in case of error return ERROR and send notification */
		printf("List object : list_add method error ehile memory allocation \n\r");
		return ERROR ;
	}

	if (listptr->head==NULL)
	{   /* in case of new list and this is the first element */
		listptr->head=listptr->tail=nnode;
		nnode->next=NULL;
		nnode->data=data;
		listptr->nitems=1;
		return OK;

	}
	else {  /* add the element to the tail of the list
			   update pointers */
			listptr->tail->next=nnode;
			nnode->next=NULL;
			nnode->data=data;
			listptr->tail=listptr->tail->next;
			listptr->nitems++;
			return OK;
	}
}


/*!@*****************************************************************************
 *!
 *! FUNCTION:			list_next
 *!
 *! GENERAL DESCRIPTION: This function increment the internal iterator pointing
 *!						 the next list's element.
 *!						 The function also return the void* data pointer reside in the
 *!						 current  element.
 *!
 *! Input:				list *lptr - list 's pointer object.
 *!
 *! Output:				void* data - The data reside in the current element.
 *!						If end of the list return NULL
 *!
 *! ALGORITHM:			The algorithm is base on the following operations:
 *!						if it isn't end list  increment the iterator pointer otherwise
 *!						return NULL.
 *!
 *!
 *! ASSUMPTIONS:	    Before used this method the list_create function have been
 *!						established.
 *!					    The void * handle is under the user 's responsibility.
 *!
 *! REMARKS:			none.
 *!
 *!*****************************************************************************
 *!@*/
void *list_next(list *lptr)
{
	if (lptr->current!=NULL)                  /* if there are more element return void */
		lptr->current=lptr->current->next;    /* if not return NULL */
	return(lptr->current?lptr->current->data:0);
}

/*!@*****************************************************************************
 *!
 *! FUNCTION:			list_remove
 *!
 *! GENERAL DESCRIPTION: This function remove the element that is pointed out by
 *!						 intenal iterator.
 *!                      before using it you need to identify (by itertively
 *!                      using list_first and list_next. once you see that the data
 *!                      equal to content that you want to remove you can
 *!                      use list_remove to take this element out of the list
 *!
 *! Input:				list *listptr - pointer to list structure.
 *!						The internal iterator need to point out on the element that
 *!                     need to be removed
 *!
 *! Output:				ERROR - if fail.
 *						OK    - if success .
 *!
 *! ALGORITHM:			The algorithm is base on the following operations:
 *!						1. New node allocation.
 *!						2. Handle pointer reside in the object.
 *!
 *! ASSUMPTIONS:	    Before used this method the the internal iterator should
 *!                     point to the element ot be removed.
 *!
 *! REMARKS:			none.
 *!
 *!*****************************************************************************
 *!@*/
void * list_remove_item(list *lptr)
{
	void *return_data;
	node *nnode;
	if (lptr->current == NULL)
		return NULL;

	return_data = lptr->current->data;
	// there is single element in the list
	if ((lptr->current == lptr->head) && (lptr->current == lptr->tail))
	{
		free(lptr->current);
		lptr->head = lptr->current = lptr->tail = NULL;
		lptr->nitems = 0;
		return return_data;
	}

	// in case the iterator is pointed to the first element
	if (lptr->head == lptr->current)
	{
		lptr->head = lptr->head->next;
		lptr->nitems--;
		free(lptr->current);
		return return_data;
	}
	// if there are at least 2 element and the iterator is not eqaul to
	// the head.
	// we need to find
	// the element that is before the current so we will run from
	// head till we will find the element before the current.
	nnode = lptr->head;
	while (nnode->next != lptr->current)
		nnode = nnode->next;
	if (lptr->current == lptr->tail)
		lptr->tail = NULL;
	nnode->next = lptr->current->next;
	free(lptr->current);
	lptr->current = nnode;
	return return_data;


}

/*!@*****************************************************************************
 *!
 *! FUNCTION:			list_search_and_remove_item
 *!
 *! GENERAL DESCRIPTION: This function search for element in the list and remove it.
 *!						 in order to iterface with the function you need to supply comapre function
 *!                      the will enable the function to identify the requsted element to be deleted.
 *!
 *! Input:				list *listptr - pointer to list structure.
 *!						function pointer for enable the link list to find the first
 *!                     element that need to be remove.
 *!
 *!
 *! Output:				ERROR - if fail.
 *						OK    - if success .
 *!
 *! ALGORITHM:			The algorithm is base on the following operations:
 *!						1. New node allocation.
 *!						2. Handle pointer reside in the object.
 *!
 *! ASSUMPTIONS:	    Before used this method the the internal iterator should
 *!                     point to the element ot be removed.
 *!
 *! REMARKS:			none.
 *!
 *!*****************************************************************************
 *!@*/

void list_search_and_remove_item(list* listptr, int (*comapre_fun)(void*, void*),void *item_to_remove)
{

	void* element_data = (void*)list_first(listptr);
	while (element_data)
	{
		if (comapre_fun(element_data, item_to_remove))
		{
			void* deleted_task = (void*)list_remove_item(listptr);
			//task_delete(deleted_task);
			free(deleted_task);
			break;

		}
		element_data = (void*)list_next(listptr);
	}
}







/*!@*****************************************************************************
 *!
 *! FUNCTION:			list_first
 *!
 *! GENERAL DESCRIPTION: This function set the internal iterator pointing
 *!						 the first list's element.
 *!						 The function also return the void* data pointer reside in the
 *!						 current  element.
 *!
 *!
 *! Input:				list *lptr - list 's pointer object.
 *!
 *! Output:				void* data - The data reside in the first element.
 *!						If null list return NULL.
 *!
 *! ALGORITHM:			The algorithm is base on the following operations:
 *!						1. set the iterator to the list 's head.
 *!						2. return void* data if exists otherwise NULL.
 *!
 *!
 *! ASSUMPTIONS:        none
 *! REMARKS:			none.
 *!
 *!*****************************************************************************
 *!@*/
void *list_first(list *lptr)
{
	/* update the current pointer (iterator) points to the head */
	/* if null list return NULL                                 */
	lptr->current=lptr->head;
	lptr->current->next=lptr->head->next;
	return(lptr->current? lptr->current->data:0);
}


