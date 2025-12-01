/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "hash.h"
#include "userprog/process.h"
#include "threads/vaddr.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
    vm_anon_init();
    vm_file_init();
#ifdef EFILESYS /* For project 4 */
    pagecache_init();
#endif
    register_inspect_intr();
    /* DO NOT MODIFY UPPER LINES. */
    /* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type page_get_type(struct page* page)
{
    int ty = VM_TYPE(page->operations->type);
    switch (ty) {
    case VM_UNINIT:
        return VM_TYPE(page->uninit.type);
    default:
        return ty;
    }
}

/* Helpers */
static struct frame* vm_get_victim(void);
static bool vm_do_claim_page(struct page* page);
static struct frame* vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void* upage, bool writable, vm_initializer* init, void* aux)
{

    ASSERT(VM_TYPE(type) != VM_UNINIT)

    struct supplemental_page_table* spt = &thread_current()->spt;

    /* Check wheter the upage is already occupied or not. */
    if (spt_find_page(spt, upage) == NULL) {
        /* TODO: Create the page, fetch the initialier according to the VM type,
         * TODO: and then create "uninit" page struct by calling uninit_new. You
         * TODO: should modify the field after calling the uninit_new. */
        /* TODO: Insert the page into the spt. */
        // 1.페이지 구조체를 생성하고
        struct page* p = (struct page*)malloc(sizeof(struct page));
        bool (*page_initializer)(struct page*, enum vm_type, void*);

        switch (VM_TYPE(type)) {
        case VM_ANON:
            page_initializer = anon_initializer;
            break;
        case VM_FILE:
            page_initializer = file_backed_initializer;
            break;
        }
        uninit_new(p, upage, init, type, aux, page_initializer);
        p->writable = writable;
        return spt_insert_page(spt, p);
    }
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page* spt_find_page(struct supplemental_page_table* spt UNUSED, void* va UNUSED)
{
    struct page* page = NULL;
    /* TODO: Fill this function. */
    struct hash_elem* hash_e;

    page = (struct page*)malloc(sizeof(struct page));
    page->va = pg_round_down(va);
    hash_e = hash_find(&spt->hash_table, &page->hash_elem);
    free(page);
    if (hash_e == NULL)
        return NULL;
    else
        return hash_entry(hash_e, struct page, hash_elem);
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table* spt UNUSED, struct page* page UNUSED)
{ /* TODO: Fill this function. */
    if (hash_insert(&spt->hash_table, &page->hash_elem) == NULL)
        return true;
    return false;
}

void spt_remove_page(struct supplemental_page_table* spt, struct page* page)
{
    vm_dealloc_page(page);
    return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame* vm_get_victim(void)
{
    struct frame* victim = NULL;
    /* TODO: The policy for eviction is up to you. */

    return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame* vm_evict_frame(void)
{
    struct frame* victim UNUSED = vm_get_victim();
    /* TODO: swap out the victim and return the evicted frame. */

    return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame* vm_get_frame(void)
{
    struct frame* frame = NULL;
    /* TODO: Fill this function. */
    void* kva = palloc_get_page(PAL_USER);
    if (kva == NULL) {
        PANIC("todo");
    }
    frame = (struct frame*)malloc(sizeof(struct frame));
    frame->kva = kva;
    frame->page = NULL;
    ASSERT(frame != NULL);
    ASSERT(frame->page == NULL);
    return frame;
}

/* Growing the stack. */
static void vm_stack_growth(void* addr UNUSED)
{
    // todo: 스택 크기를 증가시키기 위해 anon page를 하나 이상 할당하여 주어진 주소(addr)가 더 이상 예외 주소(faulted
    // address)가 되지 않도록 합니다. todo: 할당할 때 addr을 PGSIZE로 내림하여 처리
    vm_alloc_page(VM_ANON | VM_MARKER_0, pg_round_down(addr), 1);
}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page* page UNUSED)
{
}

bool vm_try_handle_fault(struct intr_frame* f UNUSED, void* addr UNUSED, bool user UNUSED, bool write UNUSED,
                         bool not_present UNUSED)
{
    struct supplemental_page_table* spt UNUSED = &thread_current()->spt;
    struct page* page = NULL;
    if (addr == NULL)
        return false;

    if (is_kernel_vaddr(addr))
        return false;

    if (not_present) // 접근한 메모리의 physical page가 존재하지 않은 경우
    {
        /* TODO: Validate the fault */
        // todo: 페이지 폴트가 스택 확장에 대한 유효한 경우인지를 확인해야 합니다.
        void* rsp = f->rsp; // user access인 경우 rsp는 유저 stack을 가리킨다.
        if (!user)          // kernel access인 경우 thread에서 rsp를 가져와야 한다.
            rsp = thread_current()->rsp;

        // 스택 확장으로 처리할 수 있는 폴트인 경우, vm_stack_growth를 호출
        if ((USER_STACK - (1 << 20) <= rsp - 8 && rsp - 8 == addr && addr <= USER_STACK) ||
            (USER_STACK - (1 << 20) <= rsp && rsp <= addr && addr <= USER_STACK))
            vm_stack_growth(addr);

        page = spt_find_page(spt, addr);
        if (page == NULL)
            return false;
        if (write == 1 && page->writable == 0) // write 불가능한 페이지에 write 요청한 경우
            return false;
        return vm_do_claim_page(page);
    }
    return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page* page)
{
    destroy(page);
    free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void* va UNUSED)
{
    struct page* page = NULL;
    /* TODO: Fill this function */
    page = spt_find_page(&thread_current()->spt, va);
    if (page == NULL)
        return false;
    return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool vm_do_claim_page(struct page* page)
{
    struct frame* frame = vm_get_frame();

    /* Set links */
    frame->page = page;
    page->frame = frame;

    /* TODO: Insert page table entry to map page's VA to frame's PA. */
    struct thread* current = thread_current();
    pml4_set_page(current->pml4, page->va, frame->kva, page->writable);

    return swap_in(page, frame->kva);
}

unsigned page_hash(const struct hash_elem* p_h_e, void* aux UNUSED)
{
    struct page* page = hash_entry(p_h_e, struct page, hash_elem);
    return hash_bytes(&page->va, sizeof(page->va));
}

bool page_less(const struct hash_elem* a, const struct hash_elem* b, void* aux UNUSED)
{
    struct page* page_a = hash_entry(a, struct page, hash_elem);
    struct page* page_b = hash_entry(b, struct page, hash_elem);
    return page_a->va < page_b->va;
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table* spt UNUSED)
{
    hash_init(&spt->hash_table, page_hash, page_less, NULL);
}

bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
								  struct supplemental_page_table *src UNUSED)
{
	// TODO: 보조 페이지 테이블을 src에서 dst로 복사합니다.
	// TODO: src의 각 페이지를 순회하고 dst에 해당 entry의 사본을 만듭니다.
	// TODO: uninit page를 할당하고 그것을 즉시 claim해야 합니다.
	struct hash_iterator i;
	hash_first(&i, &src->hash_table);
	while (hash_next(&i))
	{
		// src_page 정보
		struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
		enum vm_type type = src_page->operations->type;
		void *upage = src_page->va;
		bool writable = src_page->writable;

		/* 1) type이 uninit이면 */
		if (type == VM_UNINIT)
		{ // uninit page 생성 & 초기화
			vm_initializer *init = src_page->uninit.init;
			void *aux = src_page->uninit.aux;
			vm_alloc_page_with_initializer(VM_ANON, upage, writable, init, aux);
			continue;
		}

		/* 2) type이 file이면 */
		if (type == VM_FILE)
		{
			struct lazy_load_arg *file_aux = malloc(sizeof(struct lazy_load_arg));
			file_aux->file = src_page->file.file;
			file_aux->ofs = src_page->file.ofs;
			file_aux->read_bytes = src_page->file.read_bytes;
			file_aux->zero_bytes = src_page->file.zero_bytes;
			if (!vm_alloc_page_with_initializer(type, upage, writable, NULL, file_aux))
				return false;
			struct page *file_page = spt_find_page(dst, upage);
			file_backed_initializer(file_page, type, NULL);
			file_page->frame = src_page->frame;
			pml4_set_page(thread_current()->pml4, file_page->va, src_page->frame->kva, src_page->writable);
			continue;
		}

		/* 3) type이 anon이면 */
		if (!vm_alloc_page(type, upage, writable)) // uninit page 생성 & 초기화
			return false;						   // init이랑 aux는 Lazy Loading에 필요. 지금 만드는 페이지는 기다리지 않고 바로 내용을 넣어줄 것이므로 필요 없음

		// vm_claim_page으로 요청해서 매핑 & 페이지 타입에 맞게 초기화
		if (!vm_claim_page(upage))
			return false;

		// 매핑된 프레임에 내용 로딩
		struct page *dst_page = spt_find_page(dst, upage);
		memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
	}
	return true;
}

/* Free the resource hold by the supplemental page table */
// SPT가 보유하고 있던 모든 리소스를 해제하는 함수 (process_exit(), process_cleanup()에서 호출)
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	// todo: 페이지 항목들을 순회하며 테이블 내의 페이지들에 대해 destroy(page)를 호출
	hash_clear(&spt->hash_table, hash_page_destroy); // 해시 테이블의 모든 요소를 제거

	/** hash_destroy가 아닌 hash_clear를 사용해야 하는 이유
	 * 여기서 hash_destroy 함수를 사용하면 hash가 사용하던 메모리(hash->bucket) 자체도 반환한다.
	 * process가 실행될 때 hash table을 생성한 이후에 process_clean()이 호출되는데,
	 * 이때는 hash table은 남겨두고 안의 요소들만 제거되어야 한다.
	 * 따라서, hash의 요소들만 제거하는 hash_clear를 사용해야 한다.
	 */

	// todo🚨: 모든 수정된 내용을 스토리지에 기록
}

void hash_page_destroy(struct hash_elem *e, void *aux)
{
	struct page *page = hash_entry(e, struct page, hash_elem);
	destroy(page);
	free(page);
}
