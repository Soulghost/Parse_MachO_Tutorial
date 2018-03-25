//
//  main.cpp
//  CapFramework
//
//  Created by soulghost on 24/3/2018.
//  Copyright © 2018 soulghost. All rights reserved.
//

#include <iostream>
#include <capstone/capstone.h>
#include <cstring>
#include <vector>

#include <mach-o/loader.h>
#include <mach-o/swap.h>

uint64_t asm_begin;
uint64_t asm_size;

struct _cpu_type_names {
    cpu_type_t cputype;
    const char *cpu_name;
};

static struct _cpu_type_names cpu_type_names[] = {
    { CPU_TYPE_I386, "i386" },
    { CPU_TYPE_X86_64, "x86_64" },
    { CPU_TYPE_ARM, "arm" },
    { CPU_TYPE_ARM64, "arm64" }
};

void dasm_arm64Bytes(void *bytes, uint64_t len);

uint32_t read_magic(FILE *f, int offset) {
    uint32_t magic;
    fseek(f, offset, SEEK_SET);
    fread(&magic, sizeof(uint32_t), 1, f);
    return magic;
}

bool isMagic64(uint32_t magic) {
    return magic == MH_MAGIC_64 || magic == MH_CIGAM_64;
}

bool shouldSwapBytes(uint32_t magic) {
    return magic == MH_CIGAM || magic == MH_CIGAM_64;
}

void* loadBytes(FILE *f, uint64_t offset, uint64_t size) {
    void *buf = calloc(1, size);
    fseek(f, offset, SEEK_SET);
    fread(buf, size, 1, f);
    return buf;
}

void dump_segment_cmds(FILE *f, int offset, int shouldSwap, uint32_t number_of_cmds) {
    int total_offset = offset;
    for (int i = 0; i < number_of_cmds; i++) {
        struct load_command *cmd = static_cast<struct load_command *>(loadBytes(f, total_offset, sizeof(struct load_command)));
        if (shouldSwap) {
            swap_load_command(cmd, NX_UnknownByteOrder);
        }
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = static_cast<struct segment_command_64 *>(loadBytes(f, total_offset, sizeof(struct segment_command_64)));
            printf(">> [Segment Load Command] %d(0x%x~0x%x)\n", cmd->cmdsize, total_offset, total_offset + cmd->cmdsize);
            if (shouldSwap) {
                swap_segment_command_64(seg, NX_UnknownByteOrder);
            }
            int section_header_offset = total_offset + sizeof(struct segment_command_64);
            int sec_count = seg->nsects;
            for (int i = 0; i < sec_count; i++) {
                struct section_64 *section = static_cast<struct section_64 *>(loadBytes(f, section_header_offset, sizeof(struct section_64)));
                printf(">>    [Section %s] %lld(0x%x~0x%llx)\n", section->sectname, section->size, section->offset, section->offset + section->size);
                section_header_offset += sizeof(struct section_64);
                if (strcmp(section->sectname, "__text") == 0) {
                    asm_begin = section->offset;
                    asm_size = section->size;
                }
            }
        } else if (cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = static_cast<struct segment_command *>(loadBytes(f, total_offset, sizeof(struct segment_command)));
            if (shouldSwap) {
                swap_segment_command(seg, NX_UnknownByteOrder);
            }
            printf("segment: %s\n", seg->segname);
            free(seg);
        } else {
            printf(">> [Other Load Command] %d(0x%x~0x%x)\n", cmd->cmdsize, total_offset, total_offset + cmd->cmdsize);
        }
        total_offset += cmd->cmdsize;
        free(cmd);
    }
}

static const char *cpu_type_name(cpu_type_t cpu_type) {
    static int cpu_type_names_size = sizeof(cpu_type_names);
    for (int i = 0; i < cpu_type_names_size; i++) {
        if (cpu_type == cpu_type_names[i].cputype) {
            return cpu_type_names[i].cpu_name;
        }
    }
    return "unknown";
}

void dump_mach_header(FILE *f, int offset, int is64, int shouldSwap) {
    uint32_t number_of_cmds;
    int load_cmds_offset = offset;
    if (is64) {
        int size = sizeof(struct mach_header_64);
        printf(">> header size is %d(%d~%d)\n", size, offset, offset + size);
        struct mach_header_64 *header = static_cast<struct mach_header_64 *>(loadBytes(f, offset, size));
        if (shouldSwap) {
            swap_mach_header_64(header, NX_UnknownByteOrder);
        }
        number_of_cmds = header->ncmds;
        load_cmds_offset += size;
        printf(">> cpu type: %s\n", cpu_type_name(header->cputype));
        free(header);
    } else {
        int size = sizeof(struct mach_header);
        struct mach_header *header = static_cast<struct mach_header *>(loadBytes(f, offset, size));
        if (shouldSwap) {
            swap_mach_header(header, NX_UnknownByteOrder);
        }
        number_of_cmds = header->ncmds;
        load_cmds_offset += size;
        printf(">> cpu type: %s\n", cpu_type_name(header->cputype));
        free(header);
    }
    dump_segment_cmds(f, load_cmds_offset, shouldSwap, number_of_cmds);
}

void dump_segments(FILE *f) {
    printf("===== begin of dump mach-o file =====\n");
    uint32_t magic = read_magic(f, 0);
    bool is64 = isMagic64(magic);
    if (is64) {
        printf(">> 64bit\n");
    } else {
        printf(">> not 64bit\n");
    }
    bool shouldSwap = shouldSwapBytes(magic);
    if (shouldSwap) {
        printf(">> needs to swap bytes\n");
    } else {
        printf(">> no needs to swap bytes\n");
    }
    dump_mach_header(f, 0, is64, shouldSwap);
    printf("===== end of dump mach-o file =====\n");
}

void dump_machO(FILE *f) {
    dump_segments(f);
}

int main(int argc, const char * argv[]) {
    const char *filePath = "/Users/soulghost/Desktop/ios_re/asm/blog/a.out";
    FILE *machOFile = fopen(filePath, "rb");
    dump_machO(machOFile);
    void *bytes = loadBytes(machOFile, asm_begin, asm_size);
    printf("dasm results:\n");
    dasm_arm64Bytes(bytes, asm_size);
    fclose(machOFile);
    return 0;
}

void dasm_arm64Bytes(void *bytes, uint64_t len) {
    csh handle;
    cs_insn *insn;
    size_t count;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        printf("ERROR OCCUR\n");
        return;
    }
    count = cs_disasm(handle, (uint8_t *)bytes, len, 0, 0, &insn);
    if (count <= 0) {
        printf("Error: Failed to disassemble given code!\n");
        return;
    }
    for (size_t j = 0; j < count; j++) {
        printf("0x%llx:\t%s\t\t%s\n", insn[j].address,
               insn[j].mnemonic,insn[j].op_str);
    }
    cs_close(&handle);
}
