package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
)

// link resolves bpf-to-bpf calls.
//
// Each library may contain multiple functions / labels, and is only linked
// if prog references one of these functions.
//
// Libraries also linked.
func link(prog *ProgramSpec, libs []*ProgramSpec) error {
	var (
		linked  = make(map[*ProgramSpec]bool)
		pending = []asm.Instructions{prog.Instructions}
		insns   asm.Instructions
	)
	for len(pending) > 0 {
		insns, pending = pending[0], pending[1:]
		for _, lib := range libs {
			if linked[lib] {
				continue
			}

			needed, err := needSection(insns, lib.Instructions)
			if err != nil {
				return fmt.Errorf("linking %s: %w", lib.Name, err)
			}

			if !needed {
				continue
			}

			linked[lib] = true
			prog.Instructions = append(prog.Instructions, lib.Instructions...)
			pending = append(pending, lib.Instructions)

			if prog.BTF != nil && lib.BTF != nil {
				if err := prog.BTF.Append(lib.BTF); err != nil {
					return fmt.Errorf("linking BTF of %s: %w", lib.Name, err)
				}
			}
		}
	}

	return nil
}

func needSection(insns, section asm.Instructions) (bool, error) {
	// A map of symbols to the libraries which contain them.
	symbols, err := section.SymbolOffsets()
	if err != nil {
		return false, err
	}

	for _, ins := range insns {
		ref := ins.Reference()
		if ref == "" {
			continue
		}

		if !ins.IsFunctionCall() && !ins.IsLoadOfFunctionPointer() {
			continue
		}

		if ins.Constant != -1 {
			// This is already a valid call, no need to link again.
			continue
		}

		if _, ok := symbols[ref]; !ok {
			// Symbol isn't available in this section
			continue
		}

		// At this point we know that at least one function in the
		// library is called from insns, so we have to link it.
		return true, nil
	}

	// None of the functions in the section are called.
	return false, nil
}

func fixupJumpsAndCalls(insns asm.Instructions) error {
	symbolOffsets := make(map[string]asm.RawInstructionOffset)
	iter := insns.Iterate()
	for iter.Next() {
		sym := iter.Ins.Symbol()
		if sym == "" {
			continue
		}

		if _, ok := symbolOffsets[sym]; ok {
			return fmt.Errorf("duplicate symbol %s", sym)
		}

		symbolOffsets[sym] = iter.Offset
	}

	iter = insns.Iterate()
	for iter.Next() {
		ins := iter.Ins
		ref := ins.Reference()
		if ref == "" {
			continue
		}

		offset := iter.Offset
		symOffset, ok := symbolOffsets[ref]
		switch {
		case ins.IsLoadOfFunctionPointer() && ins.Constant == -1:
			fallthrough

		case ins.IsFunctionCall() && ins.Constant == -1:
			if !ok {
				break
			}

			ins.Constant = int64(symOffset - offset - 1)
			continue

		case ins.OpCode.Class() == asm.JumpClass && ins.Offset == -1:
			if !ok {
				break
			}

			ins.Offset = int16(symOffset - offset - 1)
			continue

		case ins.IsLoadFromMap() && ins.MapPtr() == -1:
			return fmt.Errorf("map %s: %w", ref, errUnsatisfiedReference)
		default:
			// no fixup needed
			continue
		}

		return fmt.Errorf("%s at %d: reference to missing symbol %q", ins.OpCode, iter.Index, ref)
	}

	// fixupBPFCalls replaces bpf_probe_read_{kernel,user}[_str] with bpf_probe_read[_str] on older kernels
	// https://github.com/libbpf/libbpf/blob/master/src/libbpf.c#L6009
	iter = insns.Iterate()
	for iter.Next() {
		ins := iter.Ins
		if !ins.IsBuiltinCall() {
			continue
		}
		switch asm.BuiltinFunc(ins.Constant) {
		case asm.FnProbeReadKernel, asm.FnProbeReadUser:
			if err := haveProbeReadKernel(); err != nil {
				ins.Constant = int64(asm.FnProbeRead)
			}
		case asm.FnProbeReadKernelStr, asm.FnProbeReadUserStr:
			if err := haveProbeReadKernel(); err != nil {
				ins.Constant = int64(asm.FnProbeReadStr)
			}
		}
	}

	return nil
}
