/*
 *  Copyright (c) 2020 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include <cstddef>

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "drcctlib.h"
#include <list>
#include <map>
#include <algorithm>
using namespace std;

#define DRCCTLIB_PRINTF(format, args...) \
    DRCCTLIB_PRINTF_TEMPLATE("memory_footprint", format, ##args)
#define DRCCTLIB_EXIT_PROCESS(format, args...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("memory_footprint", format, ##args)

static int tls_idx;

enum {
    INSTRACE_TLS_OFFS_BUF_PTR,
    INSTRACE_TLS_COUNT, /* total number of TLS slots allocated */
};
static reg_id_t tls_seg;
static uint tls_offs;
#define TLS_SLOT(tls_base, enum_val) (void **)((byte *)(tls_base) + tls_offs + (enum_val))
#define BUF_PTR(tls_base, type, offs) *(type **)TLS_SLOT(tls_base, offs)
#define MINSERT instrlist_meta_preinsert
#define MAX_CLIENT_CCT_PRINT_DEPTH 10
#define TOP_REACH_NUM_SHOW 200
#ifdef ARM_CCTLIB
#    define OPND_CREATE_CCT_INT OPND_CREATE_INT
#else
#    define OPND_CREATE_CCT_INT OPND_CREATE_INT32
#endif

typedef struct _mem_ref_t {
    app_pc addr;
    size_t size;
} mem_ref_t;

typedef struct _per_thread_t {
    mem_ref_t *cur_buf_list;
    void *cur_buf;
} per_thread_t;

// struct context_mem {
//     context_handle_t cur_ctxt_hndl;
//     app_pc addr;
//     size_t size;
// };

std::map<context_handle_t, std::list<app_pc>> context_mem_list;

#define TLS_MEM_REF_BUFF_SIZE 100

static file_t gTraceFile;

// client want to do
void
DoWhatClientWantTodo(void *drcontext, context_handle_t cur_ctxt_hndl, mem_ref_t *ref)
{
    // add online analysis here
    size_t mem_size = ref->size;
    app_pc mem_addr = ref->addr;
    // DRCCTLIB_PRINTF("cur_ctxt_hndl:%d addr:%d size:%d", cur_ctxt_hndl, ref->addr,
    // ref->size);

    for (size_t i = 0; i < mem_size; i++) {
        bool found = false;
        for (std::list<app_pc>::const_iterator it =
                 context_mem_list[cur_ctxt_hndl].begin();
             it != context_mem_list[cur_ctxt_hndl].end(); ++it) {
            if (*it == mem_addr + i) {
                found = true;
            }
        }
        if (!found) {
            context_mem_list[cur_ctxt_hndl].push_back(mem_addr + i);
        }
    }

    // struct context_mem cm = {cur_ctxt_hndl, ref->addr, ref->size};
    // bool found = false;
    // std::list<context_mem>::iterator it;
    // for (it = context_mem_list.begin(); it != context_mem_list.end(); it++)
    // {
    //     if (it->cur_ctxt_hndl == cur_ctxt_hndl || it->addr == ref->addr) {
    //         found = true;
    //         break;
    //     }
    // }

    // if (!found) {
    //     context_mem_list.push_back(cm);
    //     // DRCCTLIB_PRINTF("cur_ctxt_hndl:%d addr:%d size:%d", cur_ctxt_hndl,
    //     ref->addr, ref->size);
    // }
}
// dr clean call
void
InsertCleancall(int32_t slot, int32_t num)
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    context_handle_t cur_ctxt_hndl = drcctlib_get_context_handle(drcontext, slot);
    for (int i = 0; i < num; i++) {
        if (pt->cur_buf_list[i].addr != 0) {
            DoWhatClientWantTodo(drcontext, cur_ctxt_hndl, &pt->cur_buf_list[i]);
        }
    }
    BUF_PTR(pt->cur_buf, mem_ref_t, INSTRACE_TLS_OFFS_BUF_PTR) = pt->cur_buf_list;
}

// insert
static void
InstrumentMem(void *drcontext, instrlist_t *ilist, instr_t *where, opnd_t ref)
{
    /* We need two scratch registers */
    reg_id_t reg_mem_ref_ptr, free_reg;
    if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_mem_ref_ptr) !=
            DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &free_reg) !=
            DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("InstrumentMem drreg_reserve_register != DRREG_SUCCESS");
    }
    if (!drutil_insert_get_mem_addr(drcontext, ilist, where, ref, free_reg,
                                    reg_mem_ref_ptr)) {
        MINSERT(ilist, where,
                XINST_CREATE_load_int(drcontext, opnd_create_reg(free_reg),
                                      OPND_CREATE_CCT_INT(0)));
    }
    dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg,
                           tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, reg_mem_ref_ptr);
    // store mem_ref_t->addr
    MINSERT(ilist, where,
            XINST_CREATE_store(
                drcontext, OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_t, addr)),
                opnd_create_reg(free_reg)));

    // store mem_ref_t->size
#ifdef ARM_CCTLIB
    MINSERT(ilist, where,
            XINST_CREATE_load_int(
                drcontext, opnd_create_reg(free_reg),
                OPND_CREATE_CCT_INT(drutil_opnd_mem_size_in_bytes(ref, where))));
    MINSERT(ilist, where,
            XINST_CREATE_store(
                drcontext, OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_t, size)),
                opnd_create_reg(free_reg)));
#else
    MINSERT(ilist, where,
            XINST_CREATE_store(
                drcontext, OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_t, size)),
                OPND_CREATE_CCT_INT(drutil_opnd_mem_size_in_bytes(ref, where))));
#endif

#ifdef ARM_CCTLIB
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(free_reg),
                                  OPND_CREATE_CCT_INT(sizeof(mem_ref_t))));
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(reg_mem_ref_ptr),
                             opnd_create_reg(free_reg)));
#else
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(reg_mem_ref_ptr),
                             OPND_CREATE_CCT_INT(sizeof(mem_ref_t))));
#endif
    dr_insert_write_raw_tls(drcontext, ilist, where, tls_seg,
                            tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, reg_mem_ref_ptr);
    /* Restore scratch registers */
    if (drreg_unreserve_register(drcontext, ilist, where, reg_mem_ref_ptr) !=
            DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, free_reg) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("InstrumentMem drreg_unreserve_register != DRREG_SUCCESS");
    }
}

// analysis
void
InstrumentInsCallback(void *drcontext, instr_instrument_msg_t *instrument_msg)
{

    instrlist_t *bb = instrument_msg->bb;
    instr_t *instr = instrument_msg->instr;
    int32_t slot = instrument_msg->slot;
    int num = 0;
    for (int i = 0; i < instr_num_srcs(instr); i++) {
        if (opnd_is_memory_reference(instr_get_src(instr, i))) {
            num++;
            InstrumentMem(drcontext, bb, instr, instr_get_src(instr, i));
        }
    }
    for (int i = 0; i < instr_num_dsts(instr); i++) {
        if (opnd_is_memory_reference(instr_get_dst(instr, i))) {
            num++;
            InstrumentMem(drcontext, bb, instr, instr_get_dst(instr, i));
        }
    }
    dr_insert_clean_call(drcontext, bb, instr, (void *)InsertCleancall, false, 2,
                         OPND_CREATE_CCT_INT(slot), OPND_CREATE_CCT_INT(num));
}

static void
ClientThreadStart(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    if (pt == NULL) {
        DRCCTLIB_EXIT_PROCESS("pt == NULL");
    }
    drmgr_set_tls_field(drcontext, tls_idx, (void *)pt);

    pt->cur_buf = dr_get_dr_segment_base(tls_seg);
    pt->cur_buf_list =
        (mem_ref_t *)dr_global_alloc(TLS_MEM_REF_BUFF_SIZE * sizeof(mem_ref_t));
    BUF_PTR(pt->cur_buf, mem_ref_t, INSTRACE_TLS_OFFS_BUF_PTR) = pt->cur_buf_list;
}

static void
ClientThreadEnd(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    dr_global_free(pt->cur_buf_list, TLS_MEM_REF_BUFF_SIZE * sizeof(mem_ref_t));
    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
}

static void
ClientInit(int argc, const char *argv[])
{
#ifdef ARM_CCTLIB
    char name[MAXIMUM_PATH] = "arm.drcctlib_memory_footprint.out.";
#else
    char name[MAXIMUM_PATH] = "x86.drcctlib_memory_footprint.out.";
#endif

    gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));
    pid_t pid = getpid();
    sprintf(name + strlen(name), "%d", pid);
    DRCCTLIB_PRINTF("Creating log file at:%s", name);

    gTraceFile = dr_open_file(name, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(gTraceFile != INVALID_FILE);
    // print the arguments passed
    dr_fprintf(gTraceFile, "\n");
    for (int i = 0; i < argc; i++) {
        dr_fprintf(gTraceFile, "%d %s ", i, argv[i]);
    }
    dr_fprintf(gTraceFile, "\n");
}

typedef struct _output_format_t {
    context_handle_t handle;
    size_t memory;
} output_format_t;

struct memory_footprint {
    context_handle_t handle;
    std::list<app_pc> mem_footprint;
};

static void
ClientExit(void)
{
    // add output module here
    output_format_t *output_list =
        (output_format_t *)dr_global_alloc(TOP_REACH_NUM_SHOW * sizeof(output_format_t));
    for (int32_t i = 0; i < TOP_REACH_NUM_SHOW; i++) {
        output_list[i].handle = 0;
        output_list[i].memory = 0;
    }

    for (std::map<context_handle_t, std::list<app_pc>>::const_iterator it =
             context_mem_list.begin();
         it != context_mem_list.end(); ++it) {
        context_t *cur_ctxt = drcctlib_get_full_cct(it->first, 0);
        context_handle_t parent_ctxt = cur_ctxt->pre_ctxt->ctxt_hndl;
        // DRCCTLIB_PRINTF("parent context:%d", parent_ctxt);

        std::list<app_pc> parent_footprint = context_mem_list[parent_ctxt];
        std::list<app_pc> child_footprint = it->second;

        parent_footprint.sort();
        child_footprint.sort();
        // for (std::list<app_pc>::const_iterator it2 = parent_footprint.begin();
        //      it2 != parent_footprint.end(); ++it2) {
        //     DRCCTLIB_PRINTF("parent_footprint:%d", *it2);
        // }
        // for (std::list<app_pc>::const_iterator it2 = child_footprint.begin();
        //      it2 != child_footprint.end(); ++it2) {
        //     DRCCTLIB_PRINTF("child_footprint:%d", *it2);
        // }

        parent_footprint.merge(child_footprint);
        parent_footprint.unique();
        context_mem_list[parent_ctxt] = parent_footprint;
        // for (std::list<app_pc>::const_iterator it2 = parent_footprint.begin();
        //      it2 != parent_footprint.end(); ++it2) {
        //     DRCCTLIB_PRINTF("merged footprint:%d", *it2);
        // }

        // for (std::list<app_pc>::const_iterator it2 = (it->second).begin();
        //      it2 != (it->second).end(); ++it2) {
        //     DRCCTLIB_PRINTF("cur_ctxt_hndl:%d addr:%d", it->first, *it2);
        // }
        // // std::cout << it->first << " " << it->second.first << " " <<
        // it->second.second
        // // << "\n";
    }

    int i = 0;
    for (std::map<context_handle_t, std::list<app_pc>>::const_iterator it =
             context_mem_list.begin();
         it != context_mem_list.end(); ++it) {
        output_list[i].handle = it->first;
        output_list[i].memory = (it->second).size();

        i++;
        if (i == TOP_REACH_NUM_SHOW) {
            break;
        }
    }

    for (int32_t i = 0; i < TOP_REACH_NUM_SHOW; i++) {
        if (output_list[i].handle == 0) {
            break;
        }
        dr_fprintf(gTraceFile, "NO. %d memory footprint is %lld bytes for ", i + 1,
                   output_list[i].memory);
        drcctlib_print_ctxt_hndl_msg(gTraceFile, output_list[i].handle, false, false);
        dr_fprintf(gTraceFile,
                   "====================================================================="
                   "===========\n");
        drcctlib_print_full_cct(gTraceFile, output_list[i].handle, true, false,
                                MAX_CLIENT_CCT_PRINT_DEPTH);
        dr_fprintf(gTraceFile,
                   "====================================================================="
                   "===========\n\n\n");
    }
    dr_global_free(output_list, TOP_REACH_NUM_SHOW * sizeof(output_format_t));
    drcctlib_exit();
    dr_close_file(gTraceFile);

    if (!dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT)) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_memory_footprint dr_raw_tls_calloc fail");
    }
    if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
        !drmgr_unregister_thread_exit_event(ClientThreadEnd) ||
        !drmgr_unregister_tls_field(tls_idx)) {
        DRCCTLIB_PRINTF("ERROR: drcctlib_memory_footprint failed to "
                        "unregister in ClientExit");
    }
    drmgr_exit();
    if (drreg_exit() != DRREG_SUCCESS) {
        DRCCTLIB_PRINTF("failed to exit drreg");
    }
    drutil_exit();
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_memory_footprint'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);

    if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_memory_footprint "
                              "unable to initialize drmgr");
    }
    drreg_options_t ops = { sizeof(ops), 4 /*max slots needed*/, false };
    if (drreg_init(&ops) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_memory_footprint "
                              "unable to initialize drreg");
    }
    if (!drutil_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_memory_footprint "
                              "unable to initialize drutil");
    }
    drmgr_register_thread_init_event(ClientThreadStart);
    drmgr_register_thread_exit_event(ClientThreadEnd);

    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_memory_footprint "
                              "drmgr_register_tls_field fail");
    }
    if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, INSTRACE_TLS_COUNT, 0)) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_memory_footprint dr_raw_tls_calloc fail");
    }
    drcctlib_init(DRCCTLIB_FILTER_MEM_ACCESS_INSTR, INVALID_FILE, InstrumentInsCallback,
                  false);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif