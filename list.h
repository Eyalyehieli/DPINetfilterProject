#ifndef LIST_H_INCLUDED
#define LIST_H_INCLUDED

/*! CONSTANT DECLARATIONS   */
#define ERROR -1
#define OK 0

/*! STRUCTURE TYPE DEFINITION 	 */

typedef int (*comapre_fun)(void*,void *);
/* Node type definition */

typedef struct node_t {
	struct node_t *next;
	void *data;
}node;


/* list type definition */
/* The  list type element are as follow :
   head - point to list's head.
   tail - point to list's tail.
   current - point and functions as iterator for the the
   list_next and list_first methods.
*/
typedef struct list_t {
	node *head;    /* points to list 's head                     */
	node *current; /* points to list 's current iterator         */
	node *tail;    /* points to list 's tail                     */
	int nitems;    /* store the number of element had been store */

} list ;

/*! function prototypes definition  */

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
list *list_create();


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
int list_add(list *listptr,void *data);


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
void* list_remove_item(list *listptr);


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
void list_search_and_remove_item(list* listptr, int (*comapre_fun)(void*, void*),void *);




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
void *list_next(list *lptr);


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
void *list_first(list *lptr);

#endif // LIST_H_INCLUDED
