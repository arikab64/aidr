find_program(BPFTOOL bpftool REQUIRED)
find_program(CLANG clang REQUIRED)
# Rust skeletons come from libbpf-cargo; bpftool's own `gen skeleton` is C-only.
find_program(CARGO cargo REQUIRED)

set(VMLINUX ${CMAKE_CURRENT_SOURCE_DIR}/vmlinux.h)

# Where staged build outputs live, shared with src/mon. CMAKE_BINARY_DIR (top
# of the build tree) on purpose, not CMAKE_CURRENT_BINARY_DIR.
set(MON_OUTPUT_DIR ${CMAKE_BINARY_DIR}/var/aidr)

# Map the host machine to the BPF target arch (x86_64 -> x86, aarch64 -> arm64)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
    set(BPF_ARCH x86)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(BPF_ARCH arm64)
else()
    set(BPF_ARCH ${CMAKE_SYSTEM_PROCESSOR})
endif()

# Extra clang flags applied to every BPF program, driven by build options.
set(DEFAULT_AIDR_TEST_FENTRY OFF)
if(EXISTS "/sys/kernel/security/lsm")
    file(READ "/sys/kernel/security/lsm" ACTIVE_LSMS)
    if(NOT ACTIVE_LSMS MATCHES "bpf")
        set(DEFAULT_AIDR_TEST_FENTRY ON)
    endif()
endif()
option(AIDR_TEST_FENTRY
       "Attach the security_* hooks with fentry instead of BPF-LSM (record-only; for kernels booted without lsm=bpf)"
       ${DEFAULT_AIDR_TEST_FENTRY})
set(BPF_CFLAGS)
if(AIDR_TEST_FENTRY)
    list(APPEND BPF_CFLAGS -DAIDR_TEST_FENTRY)
endif()

# Toggling the option changes only the compile command, which a Makefile
# generator would not notice on its own. Depending on this stamp forces the
# rebuild: file(GENERATE) rewrites it only when the flag set actually changes.
set(BPF_CFLAGS_STAMP ${CMAKE_CURRENT_BINARY_DIR}/bpf_cflags.stamp)
file(GENERATE OUTPUT ${BPF_CFLAGS_STAMP} CONTENT "${BPF_CFLAGS}")

add_custom_command(
    OUTPUT ${VMLINUX}
    COMMAND ${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX}
    COMMENT "GEN ${VMLINUX}"
    VERBATIM
)
add_custom_target(vmlinux DEPENDS ${VMLINUX})

# add_bpf_program(<name>) compiles <name>.bpf.c to <name>.bpf.o and generates
# the Rust skeleton <name>.skel.rs next to it, for the userspace loader to
# pull in with a module directive.
function(add_bpf_program name)
    set(src ${CMAKE_CURRENT_SOURCE_DIR}/${name}.bpf.c)
    set(obj ${CMAKE_CURRENT_BINARY_DIR}/${name}.bpf.o)
    # Generated next to the BPF sources so the Rust code can pull it in with
    # a plain module directive (no build.rs indirection).
    set(skel ${CMAKE_CURRENT_SOURCE_DIR}/${name}.skel.rs)
    set(obj_staged ${MON_OUTPUT_DIR}/${name}.bpf.o)
    # clang writes a Makefile-style depfile listing every header it actually
    # included (mon.bpf.h, logger.h, vmlinux.h, libbpf's), so header edits
    # rebuild the object without keeping a hand-maintained DEPENDS list.
    set(dep ${obj}.d)
    add_custom_command(
        OUTPUT ${obj}
        COMMAND ${CLANG} -g -O2 -target bpf -D__TARGET_ARCH_${BPF_ARCH}
                ${BPF_CFLAGS}
                -I${CMAKE_CURRENT_SOURCE_DIR}
                -MD -MF ${dep}
                -c ${src} -o ${obj}
        DEPENDS ${src} ${VMLINUX} ${BPF_CFLAGS_STAMP}
        DEPFILE ${dep}
        COMMENT "BPF ${obj}"
        VERBATIM
    )
    # --object reads the prebuilt .o and writes the skeleton to stdout, so this
    # reuses the clang output above instead of recompiling the program.
    add_custom_command(
        OUTPUT ${skel}
        COMMAND ${CARGO} libbpf gen --object ${obj} > ${skel}
        DEPENDS ${obj}
        COMMENT "SKEL ${skel}"
        VERBATIM
    )
    # Stage the object at build/var/aidr/, alongside the mon binary.
    add_custom_command(
        OUTPUT ${obj_staged}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${MON_OUTPUT_DIR}
        COMMAND ${CMAKE_COMMAND} -E copy ${obj} ${obj_staged}
        DEPENDS ${obj}
        COMMENT "STAGE ${obj_staged}"
        VERBATIM
    )
    add_custom_target(bpf_${name} ALL DEPENDS ${obj_staged} ${skel})
endfunction()

add_bpf_program(mon_files)
add_bpf_program(mon_procs)
