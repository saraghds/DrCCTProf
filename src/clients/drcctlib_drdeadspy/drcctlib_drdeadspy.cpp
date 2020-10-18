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
#include <map>
#include <vector>
#include <algorithm>
using namespace std;

#define DRCCTLIB_PRINTF(format, args...) \
    DRCCTLIB_PRINTF_TEMPLATE("drdeadspy", format, ##args)
#define DRCCTLIB_EXIT_PROCESS(format, args...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("drdeadspy", format, ##args)

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

typedef struct _context_handle_status {
    context_handle_t ctxt_hndl;
    int is_write;
} context_handle_status;

std::map<app_pc, context_handle_status> shadow_memory;
std::map<reg_id_t, context_handle_status> shadow_register;
std::map<int64_t, int32_t> dead_stores_mem;
std::map<int64_t, int32_t> dead_stores_reg;

#define TLS_MEM_REF_BUFF_SIZE 100
#define TOP_REACH_NUM_SHOW 100
#define MAX_CLIENT_CCT_PRINT_DEPTH 10

static file_t gTraceFile;

// client want to do
void
DoWhatClientWantTodoForMem(void *drcontext, context_handle_t cur_ctxt_hndl,
                           mem_ref_t *ref, int is_write)
{
    // DRCCTLIB_PRINTF("******DoWhatClientWantTodoForMem");
    // add online analysis here
    app_pc mem_addr = ref->addr;

    if (shadow_memory.count(mem_addr) > 0) {
        std::map<app_pc, context_handle_status>::iterator it;
        it = shadow_memory.find(mem_addr);
        if (it->second.is_write == 1) {
            // add to dead_stores_mem
            int64_t concat_contexts =
                ((int64_t)it->second.ctxt_hndl << 32) | cur_ctxt_hndl;
            std::map<int64_t, int32_t>::iterator it2;
            if (dead_stores_mem.count(concat_contexts) > 0) {
                it2 = dead_stores_mem.find(concat_contexts);
                it2->second++;
            } else {
                dead_stores_mem.insert(std::pair<int64_t, int32_t>(concat_contexts, 1));
            }
        } else {
            it->second.is_write = 0;
        }
    } else {
        context_handle_status cs;
        cs.ctxt_hndl = cur_ctxt_hndl;
        cs.is_write = is_write;
        shadow_memory.insert(std::pair<app_pc, context_handle_status>(mem_addr, cs));
    }
}

void
DoWhatClientWantTodoForReg(void *drcontext, context_handle_t cur_ctxt_hndl,
                           reg_id_t reg_id, int is_write)
{
    // DRCCTLIB_PRINTF("******DoWhatClientWantTodoForReg");
    if (shadow_register.count(reg_id) > 0) {
        std::map<reg_id_t, context_handle_status>::iterator it;
        it = shadow_register.find(reg_id);
        if (it->second.is_write == 1) {
            // add to dead_stores
            int64_t concat_contexts =
                ((int64_t)it->second.ctxt_hndl << 32) | cur_ctxt_hndl;
            std::map<int64_t, int32_t>::iterator it2;
            if (dead_stores_reg.count(concat_contexts) > 0) {
                it2 = dead_stores_reg.find(concat_contexts);
                it2->second++;
            } else {
                dead_stores_reg.insert(std::pair<int64_t, int32_t>(concat_contexts, 1));
            }
        } else {
            it->second.is_write = 0;
        }
    } else {
        context_handle_status cs;
        cs.ctxt_hndl = cur_ctxt_hndl;
        cs.is_write = is_write;
        shadow_register.insert(std::pair<reg_id_t, context_handle_status>(reg_id, cs));
    }
}

// dr clean call
void
InsertMemCleancall(int32_t slot, int32_t num, int is_write)
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    context_handle_t cur_ctxt_hndl = drcctlib_get_context_handle(drcontext, slot);
    for (int i = 0; i < num; i++) {
        if (pt->cur_buf_list[i].addr != 0) {
            DoWhatClientWantTodoForMem(drcontext, cur_ctxt_hndl, &pt->cur_buf_list[i],
                                       is_write);
        }
    }
    BUF_PTR(pt->cur_buf, mem_ref_t, INSTRACE_TLS_OFFS_BUF_PTR) = pt->cur_buf_list;
}

void
InsertRegCleancall(int32_t slot, reg_id_t reg_id, int is_write)
{
    void *drcontext = dr_get_current_drcontext();
    // per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    context_handle_t cur_ctxt_hndl = drcctlib_get_context_handle(drcontext, slot);
    // for (int i = 0; i < num; i++) {
    //     if (pt->cur_buf_list[i].addr != 0) {
    //         DoWhatClientWantTodo(drcontext, cur_ctxt_hndl, &pt->cur_buf_list[i]);
    //     }
    // }
    DoWhatClientWantTodoForReg(drcontext, cur_ctxt_hndl, reg_id, is_write);
    // BUF_PTR(pt->cur_buf, mem_ref_t, INSTRACE_TLS_OFFS_BUF_PTR) = pt->cur_buf_list;
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
    bool is_mem = false;
    for (int i = 0; i < instr_num_srcs(instr); i++) {
        opnd_t op = instr_get_src(instr, i);
        if (opnd_is_memory_reference(op)) {
            num++;
            InstrumentMem(drcontext, bb, instr, op);
            is_mem = true;
        }

        if (opnd_is_reg(op)) {
            int num_temp = opnd_num_regs_used(op);
            for (int j = 0; j < num_temp; j++) {
                reg_id_t reg = opnd_get_reg_used(op, j);
                dr_insert_clean_call(drcontext, bb, instr, (void *)InsertRegCleancall,
                                     false, 3, OPND_CREATE_CCT_INT(slot),
                                     OPND_CREATE_CCT_INT(reg), OPND_CREATE_CCT_INT(0));
            }
        }
    }
    for (int i = 0; i < instr_num_dsts(instr); i++) {
        opnd_t op = instr_get_dst(instr, i);
        if (opnd_is_memory_reference(op)) {
            num++;
            InstrumentMem(drcontext, bb, instr, op);
            is_mem = true;

            int num_temp = opnd_num_regs_used(op);
            for (int j = 0; j < num_temp; j++) {
                reg_id_t reg = opnd_get_reg_used(op, j);
                dr_insert_clean_call(drcontext, bb, instr, (void *)InsertRegCleancall,
                                     false, 3, OPND_CREATE_CCT_INT(slot),
                                     OPND_CREATE_CCT_INT(reg), OPND_CREATE_CCT_INT(0));
            }
        }

        if (opnd_is_reg(op)) {
            int num_temp = opnd_num_regs_used(op);
            for (int j = 0; j < num_temp; j++) {
                reg_id_t reg = opnd_get_reg_used(op, j);
                dr_insert_clean_call(drcontext, bb, instr, (void *)InsertRegCleancall,
                                     false, 3, OPND_CREATE_CCT_INT(slot),
                                     OPND_CREATE_CCT_INT(reg), OPND_CREATE_CCT_INT(1));
            }
        }
    }

    if (is_mem) {
        bool is_mem_write = instr_writes_memory(instr);
        int write = 0;
        if (is_mem_write)
            write = 1;
        dr_insert_clean_call(drcontext, bb, instr, (void *)InsertMemCleancall, false, 3,
                             OPND_CREATE_CCT_INT(slot), OPND_CREATE_CCT_INT(num),
                             OPND_CREATE_CCT_INT(write));
    }
}

static void
ClientThreadStart(void *drcontext)
{
    // DRCCTLIB_PRINTF("******ClientThreadStart");
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
    char name[MAXIMUM_PATH] = "arm.drcctlib_drdeadspy.out.";
#else
    char name[MAXIMUM_PATH] = "x86.drcctlib_drdeadspy.out.";
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

bool
sortByVal(const std::pair<int64_t, int32_t> &a, const std::pair<int64_t, int32_t> &b)
{
    return (a.second > b.second);
}

static void
ClientExit(void)
{
    dr_fprintf(gTraceFile,
               "=========================MEMORY DEAD STORES==========================\n");

    dr_fprintf(gTraceFile,
               "=====================================================================\n");

    std::vector<std::pair<int64_t, int32_t>> sorted_mem;

    std::map<int64_t, int32_t>::iterator it;
    for (it = dead_stores_mem.begin(); it != dead_stores_mem.end(); it++) {
        sorted_mem.push_back(make_pair(it->first, it->second));
    }

    sort(sorted_mem.begin(), sorted_mem.end(), sortByVal);

    int count = 0;
    for (uint i = 0; i < sorted_mem.size(); i++) {
        if (count >= TOP_REACH_NUM_SHOW) {
            break;
        }
        dr_fprintf(gTraceFile, "dead occurances: %d\n", sorted_mem[i].second);
        dr_fprintf(
            gTraceFile,
            "---------------------------------------------------------------------\n");

        int32_t dead_context = (int32_t)(sorted_mem[i].first & 0xffffffffUL);
        int32_t killing_context = (int32_t)(sorted_mem[i].first >> 32);
        drcctlib_print_full_cct(gTraceFile, dead_context, true, true,
                                MAX_CLIENT_CCT_PRINT_DEPTH);
        dr_fprintf(gTraceFile, "***************************************************\n");
        drcctlib_print_full_cct(gTraceFile, killing_context, true, true,
                                MAX_CLIENT_CCT_PRINT_DEPTH);

        dr_fprintf(
            gTraceFile,
            "=====================================================================\n");
        count++;
    }

    // TODO: register output
    dr_fprintf(gTraceFile,
               "=========================REGISTER DEAD STORES========================\n");

    dr_fprintf(gTraceFile,
               "=====================================================================\n");

    std::vector<std::pair<int64_t, int32_t>> sorted_reg;

    std::map<int64_t, int32_t>::iterator it2;
    for (it2 = dead_stores_reg.begin(); it2 != dead_stores_reg.end(); it++) {
        sorted_reg.push_back(make_pair(it2->first, it2->second));
    }

    sort(sorted_reg.begin(), sorted_reg.end(), sortByVal);

    count = 0;
    for (uint i = 0; i < sorted_reg.size(); i++) {
        if (count >= TOP_REACH_NUM_SHOW) {
            break;
        }
        dr_fprintf(gTraceFile, "dead occurances: %d\n", sorted_reg[i].second);
        dr_fprintf(
            gTraceFile,
            "---------------------------------------------------------------------\n");

        int32_t dead_context = (int32_t)(sorted_reg[i].first & 0xffffffffUL);
        int32_t killing_context = (int32_t)(sorted_reg[i].first >> 32);
        drcctlib_print_full_cct(gTraceFile, dead_context, true, true,
                                MAX_CLIENT_CCT_PRINT_DEPTH);
        dr_fprintf(gTraceFile, "***************************************************\n");
        drcctlib_print_full_cct(gTraceFile, killing_context, true, true,
                                MAX_CLIENT_CCT_PRINT_DEPTH);

        dr_fprintf(
            gTraceFile,
            "=====================================================================\n");
        count++;
    }

    drcctlib_exit();
    dr_close_file(gTraceFile);

    if (!dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT)) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_drdeadspy dr_raw_tls_calloc fail");
    }
    if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
        !drmgr_unregister_thread_exit_event(ClientThreadEnd) ||
        !drmgr_unregister_tls_field(tls_idx)) {
        DRCCTLIB_PRINTF("ERROR: drcctlib_drdeadspy failed to "
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
    dr_set_client_name("DynamoRIO Client 'drcctlib_drdeadspy'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);

    if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_drdeadspy "
                              "unable to initialize drmgr");
    }
    drreg_options_t ops = { sizeof(ops), 4 /*max slots needed*/, false };
    if (drreg_init(&ops) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_drdeadspy "
                              "unable to initialize drreg");
    }
    if (!drutil_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_drdeadspy "
                              "unable to initialize drutil");
    }
    drmgr_register_thread_init_event(ClientThreadStart);
    drmgr_register_thread_exit_event(ClientThreadEnd);

    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_drdeadspy "
                              "drmgr_register_tls_field fail");
    }
    if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, INSTRACE_TLS_COUNT, 0)) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_drdeadspy dr_raw_tls_calloc fail");
    }
    drcctlib_init(DRCCTLIB_FILTER_MEM_ACCESS_INSTR, INVALID_FILE, InstrumentInsCallback,
                  false);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif