import idaapi
import idautils
import idc
import ida_segment
import string

BAD_PREFIXES = ("sub_", "loc_", "unk_", "byte_", "word_", "dword_", "qword_", "off_")
ALLOWED_CHARS = string.ascii_letters + string.digits + "_$?@"

def is_bad_prefix(name):
    for pfx in BAD_PREFIXES:
        if name.startswith(pfx):
            return True
    return False

def sanitize_name(name):
    if not name:
        return ""
    sanitized = ''.join(c if c in ALLOWED_CHARS else '_' for c in name)
    if sanitized and sanitized[0].isdigit():
        sanitized = '_' + sanitized
    return sanitized

def has_name(ea):
    return idc.get_name(ea) != ""

def extract_target_name_from_disasm(ea):
    disasm = idc.generate_disasm_line(ea, 0)
    if not disasm:
        return ""
    off_pos = disasm.find("offset ")
    if off_pos == -1:
        return ""
    start = off_pos + len("offset ")
    end = disasm.find(" ", start)
    if end == -1:
        name = disasm[start:]
    else:
        name = disasm[start:end]
    return name.strip()

def is_extern_segment(ea):
    seg = ida_segment.getseg(ea)
    if seg and seg.type == ida_segment.SEG_XTRN:
        return True
    return False

def rename_pass():
    renamed = 0
    errors = 0

    for seg in idautils.Segments():
        seg_start = idc.get_segm_start(seg)
        seg_end = idc.get_segm_end(seg)
        ea = seg_start
        while ea < seg_end:
            if is_extern_segment(ea):
                ea = idc.next_head(ea, seg_end)
                continue

            if has_name(ea):
                name = idc.get_name(ea)
                if name.startswith("off_"):
                    target = idc.get_qword(ea)
                    target_name = ""

                    if target != idaapi.BADADDR and has_name(target):
                        tmp = idc.get_name(target)
                        if not is_bad_prefix(tmp):
                            target_name = tmp

                    if not target_name:
                        target_name = extract_target_name_from_disasm(ea)

                    if target_name and not is_bad_prefix(target_name):
                        clean_target = sanitize_name(target_name)
                        if not clean_target:
                            print(f"ERROR: Invalid name '{target_name}' for {name} at {hex(ea)}")
                            errors += 1
                            ea = idc.next_head(ea, seg_end)
                            continue

                        new_name = "ptr_" + clean_target
                        flags = idaapi.SN_NOCHECK | idaapi.SN_NOWARN | idaapi.SN_FORCE

                        if idc.set_name(ea, new_name, flags):
                            print(f"Renamed {name} -> {idc.get_name(ea)}")
                            renamed += 1
                        else:
                            print(f"ERROR: Failed to rename {name} at {hex(ea)} to {new_name}")
                            errors += 1

            ea = idc.next_head(ea, seg_end)

    return renamed, errors

def main():
    total_renamed = 0
    total_errors = 0
    iteration = 0
    max_iterations = 20

    print("Starting iterative renaming...")
    while iteration < max_iterations:
        iteration += 1
        print(f"\n--- Pass {iteration} ---")
        renamed, errors = rename_pass()
        total_renamed += renamed
        total_errors += errors
        print(f"Pass {iteration}: renamed {renamed}, errors {errors}")

        if renamed == 0:
            break

    print("\n" + "=" * 40)
    print(f"Total renamed: {total_renamed}")
    print(f"Total errors: {total_errors}")
    print(f"Iterations: {iteration}")

if __name__ == "__main__":
    main()
