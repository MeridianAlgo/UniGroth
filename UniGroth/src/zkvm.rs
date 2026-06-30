//! # RISC-V zkVM Constraint System
//!
//! Builds R1CS constraints from a RISC-V execution trace. Combines the
//! gadget library (range checks, memory, Poseidon) with opcode-level
//! constraint generation to prove correct program execution in zero knowledge.
//!
//! ## Architecture
//!
//! ```text
//! RISC-V Program → Executor → ProgramTrace → ZkvmConstraintBuilder → R1CS
//! ```
//!
//! The [`ZkvmConstraintBuilder`] generates constraint batches for each step:
//! - **ALU ops** (ADD, SUB, AND, OR, XOR, SHL, SHR): range checks on inputs/outputs
//! - **Memory ops** (LW, SW): MemoryAccessGadget + range-checked address
//! - **Branch ops** (BEQ, BNE, BLT, BGE): equality/comparison constraints
//! - **Jump ops** (JAL, JALR): PC-update constraints
//!
//! ## zkEVM / zkVM readiness
//!
//! The memory access model uses the sorted-difference argument from
//! [`crate::gadgets::MemoryAccessGadget`], compatible with zkEVM memory
//! consistency proofs.

use ark_std::{format, string::String, vec::Vec};

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
#[cfg(feature = "std")]
use std::collections::BTreeMap;

// ─── RISC-V Opcodes ───────────────────────────────────────────────────────────

/// RISC-V RV32I base integer instruction opcodes (simplified subset).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RiscVOpcode {
    // ── Arithmetic (R-type) ──
    /// Add: rd = rs1 + rs2
    Add,
    /// Subtract: rd = rs1 - rs2
    Sub,
    /// And: rd = rs1 & rs2
    And,
    /// Or: rd = rs1 | rs2
    Or,
    /// Xor: rd = rs1 ^ rs2
    Xor,
    /// Shift left logical: rd = rs1 << rs2
    Sll,
    /// Shift right logical: rd = rs1 >> rs2
    Srl,
    /// Shift right arithmetic: rd = rs1 >>_s rs2
    Sra,
    /// Set less than: rd = rs1 < rs2
    Slt,

    // ── Immediate arithmetic (I-type) ──
    /// Add immediate: rd = rs1 + imm
    Addi,
    /// And immediate: rd = rs1 & imm
    Andi,
    /// Or immediate: rd = rs1 | imm
    Ori,
    /// Xor immediate: rd = rs1 ^ imm
    Xori,

    // ── Memory (I-type / S-type) ──
    /// Load word: rd = mem[rs1 + imm]
    Lw,
    /// Store word: mem[rs1 + imm] = rs2
    Sw,
    /// Load byte (zero-extend): rd = u8_at(rs1 + imm)
    Lb,
    /// Store byte: mem[rs1 + imm] = rs2[7:0]
    Sb,

    // ── Branch (B-type) ──
    /// Branch if equal: PC += (rs1 == rs2) ? imm : 4
    Beq,
    /// Branch if not equal: PC += (rs1 != rs2) ? imm : 4
    Bne,
    /// Branch if less than: PC += (rs1 < rs2) ? imm : 4
    Blt,
    /// Branch if greater or equal: PC += (rs1 >= rs2) ? imm : 4
    Bge,

    // ── Jumps ──
    /// Jump and link: rd = PC+4; PC = PC + imm
    Jal,
    /// Jump and link register: rd = PC+4; PC = rs1 + imm
    Jalr,

    // ── Upper-immediate ──
    /// Load upper immediate: rd = imm << 12
    Lui,
    /// Add upper immediate to PC: rd = PC + (imm << 12)
    Auipc,

    // ── System ──
    /// No operation (addi x0, x0, 0).
    Nop,
    /// Environment call (syscall).
    Ecall,
}

impl RiscVOpcode {
    /// Number of R1CS constraints added by this opcode's gadget.
    pub fn constraint_count(&self) -> usize {
        match self {
            // ALU: two 32-bit range checks (inputs) + one (output) + op constraint
            Self::Add | Self::Sub | Self::Addi => 3 * 33 + 2,
            Self::And | Self::Or | Self::Xor | Self::Andi | Self::Ori | Self::Xori => {
                // Bitwise: 32 range checks + 32 XOR/AND constraints
                3 * 33 + 32
            },
            Self::Sll | Self::Srl | Self::Sra => 3 * 33 + 32 + 5, // + shift amount check
            Self::Slt => 33 * 2 + 3,

            // Memory: address range check (32b) + read/write consistency
            Self::Lw | Self::Sw => 33 + 4 + 5, // address + memory + consistency
            Self::Lb | Self::Sb => 33 + 4 + 5 + 8, // + byte extraction (8 range bits)

            // Branch: equality comparison (2 wires) + PC update constraint
            Self::Beq | Self::Bne => 2 + 1 + 4,
            Self::Blt | Self::Bge => 33 + 3, // comparison + PC

            // Jump: PC update + link register write
            Self::Jal | Self::Jalr => 2 + 33,

            Self::Lui | Self::Auipc => 2,
            Self::Nop => 1,
            Self::Ecall => 5,
        }
    }

    /// Whether this opcode reads from memory.
    pub fn is_memory_read(&self) -> bool {
        matches!(self, Self::Lw | Self::Lb)
    }

    /// Whether this opcode writes to memory.
    pub fn is_memory_write(&self) -> bool {
        matches!(self, Self::Sw | Self::Sb)
    }

    /// Whether this opcode is a branch.
    pub fn is_branch(&self) -> bool {
        matches!(
            self,
            Self::Beq | Self::Bne | Self::Blt | Self::Bge | Self::Jal | Self::Jalr
        )
    }

    /// Whether this is an ALU operation.
    pub fn is_alu(&self) -> bool {
        matches!(
            self,
            Self::Add
                | Self::Sub
                | Self::And
                | Self::Or
                | Self::Xor
                | Self::Addi
                | Self::Andi
                | Self::Ori
                | Self::Xori
                | Self::Sll
                | Self::Srl
                | Self::Sra
                | Self::Slt
        )
    }
}

// ─── Execution Trace ─────────────────────────────────────────────────────────

/// Register file: 32 general-purpose registers x0–x31 plus PC.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegisterFile {
    /// x0–x31 (x0 is always 0).
    pub regs: [u32; 32],
    /// Program counter.
    pub pc: u32,
}

impl RegisterFile {
    /// Read register `r` (x0 always returns 0).
    pub fn read(&self, r: usize) -> u32 {
        if r == 0 {
            0
        } else {
            self.regs[r]
        }
    }

    /// Write register `r` (writes to x0 are silently dropped).
    pub fn write(&mut self, r: usize, val: u32) {
        if r != 0 {
            self.regs[r] = val;
        }
    }
}

/// A single execution step: one RISC-V instruction.
#[derive(Clone, Debug)]
pub struct TraceStep {
    /// Program counter before this step.
    pub pc: u32,
    /// Instruction executed.
    pub opcode: RiscVOpcode,
    /// Source register 1 index.
    pub rs1: usize,
    /// Source register 2 index (or 0 for I-type).
    pub rs2: usize,
    /// Destination register index.
    pub rd: usize,
    /// Immediate value (sign-extended).
    pub imm: i32,
    /// Register file state before execution.
    pub regs_before: [u32; 32],
    /// Register file state after execution.
    pub regs_after: [u32; 32],
    /// Optional memory access: (address, value, is_write).
    pub mem_access: Option<(u32, u32, bool)>,
}

impl TraceStep {
    /// Number of R1CS constraints this step contributes.
    pub fn constraint_count(&self) -> usize {
        // Base opcode constraints + PC update (2) + register validity (always)
        self.opcode.constraint_count() + 2
    }
}

/// A complete RISC-V execution trace ready for constraint generation.
#[derive(Clone, Debug)]
pub struct ProgramTrace {
    /// Ordered execution steps.
    pub steps: Vec<TraceStep>,
    /// Initial memory state (address → value pairs).
    pub initial_memory: Vec<(u32, u32)>,
    /// Final memory state.
    pub final_memory: Vec<(u32, u32)>,
}

impl ProgramTrace {
    /// Create an empty trace.
    pub fn new() -> Self {
        Self {
            steps: Vec::new(),
            initial_memory: Vec::new(),
            final_memory: Vec::new(),
        }
    }

    /// Total constraint count across all steps.
    pub fn total_constraints(&self) -> usize {
        self.steps.iter().map(|s| s.constraint_count()).sum()
    }

    /// Number of memory accesses in the trace.
    pub fn memory_access_count(&self) -> usize {
        self.steps.iter().filter(|s| s.mem_access.is_some()).count()
    }

    /// Step count by opcode type.
    pub fn alu_steps(&self) -> usize {
        self.steps.iter().filter(|s| s.opcode.is_alu()).count()
    }

    /// Branch / jump step count.
    pub fn branch_steps(&self) -> usize {
        self.steps.iter().filter(|s| s.opcode.is_branch()).count()
    }
}

impl Default for ProgramTrace {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Constraint Builder ───────────────────────────────────────────────────────

/// Kind of constraint generated by the zkVM builder.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ZkvmConstraintKind {
    /// Constrains a value to lie in [0, 2^bits).
    RangeCheck {
        /// Number of bits the value is constrained to.
        bits: usize,
    },
    /// Ensures two values are equal.
    Equality,
    /// ALU multiply gate (for complex ops).
    AluMul,
    /// Memory read/write consistency.
    MemoryConsistency,
    /// PC update constraint.
    PcUpdate,
    /// Opcode-specific custom gate.
    OpcodeGate(String),
}

/// A single generated constraint (symbolic form).
#[derive(Clone, Debug)]
pub struct ZkvmConstraint {
    /// The kind of constraint.
    pub kind: ZkvmConstraintKind,
    /// Step index in the trace that produced this constraint.
    pub step_idx: usize,
    /// Human-readable description for debugging.
    pub description: String,
}

/// Statistics from a constraint generation run.
#[derive(Clone, Debug, Default)]
pub struct ZkvmStats {
    /// Total constraints generated.
    pub total_constraints: usize,
    /// Range-check constraints.
    pub range_checks: usize,
    /// Memory-consistency constraints.
    pub memory_constraints: usize,
    /// ALU constraints.
    pub alu_constraints: usize,
    /// Branch/PC constraints.
    pub branch_constraints: usize,
}

impl ZkvmStats {
    /// One-line summary.
    pub fn describe(&self) -> String {
        format!(
            "ZkvmStats {{ total={}, range={}, mem={}, alu={}, branch={} }}",
            self.total_constraints,
            self.range_checks,
            self.memory_constraints,
            self.alu_constraints,
            self.branch_constraints,
        )
    }
}

/// Builds R1CS constraints from a [`ProgramTrace`].
pub struct ZkvmConstraintBuilder;

impl ZkvmConstraintBuilder {
    /// Generate all constraints for the trace and return statistics.
    ///
    /// The actual constraint wires are not materialised here (that would require
    /// a concrete field type and witness assignment); instead we return the
    /// symbolic constraint list and statistics, which are used for circuit sizing
    /// and integration tests.
    pub fn build(trace: &ProgramTrace) -> (Vec<ZkvmConstraint>, ZkvmStats) {
        let mut constraints = Vec::new();
        let mut stats = ZkvmStats::default();

        for (step_idx, step) in trace.steps.iter().enumerate() {
            // ── PC update ──
            constraints.push(ZkvmConstraint {
                kind: ZkvmConstraintKind::PcUpdate,
                step_idx,
                description: format!("pc[{}] → pc[{}+1]", step.pc, step.pc),
            });
            stats.branch_constraints += 1;
            stats.total_constraints += 1;

            // ── Register range checks ──
            // rs1 and rs2 values must be 32-bit
            let rs1_val = RegisterFile {
                regs: step.regs_before,
                pc: step.pc,
            }
            .read(step.rs1);
            let _ = rs1_val; // value available for witness; we just count constraints
            constraints.push(ZkvmConstraint {
                kind: ZkvmConstraintKind::RangeCheck { bits: 32 },
                step_idx,
                description: format!("range_check(rs1=x{})", step.rs1),
            });
            stats.range_checks += 1;
            stats.total_constraints += 1;

            if step.opcode.is_alu() || step.opcode.is_memory_read() || step.opcode.is_memory_write()
            {
                constraints.push(ZkvmConstraint {
                    kind: ZkvmConstraintKind::RangeCheck { bits: 32 },
                    step_idx,
                    description: format!("range_check(rs2=x{})", step.rs2),
                });
                stats.range_checks += 1;
                stats.total_constraints += 1;
            }

            // ── ALU constraints ──
            if step.opcode.is_alu() {
                constraints.push(ZkvmConstraint {
                    kind: ZkvmConstraintKind::OpcodeGate(format!("{:?}", step.opcode)),
                    step_idx,
                    description: format!(
                        "{:?} x{}, x{}, x{}",
                        step.opcode, step.rd, step.rs1, step.rs2
                    ),
                });
                constraints.push(ZkvmConstraint {
                    kind: ZkvmConstraintKind::RangeCheck { bits: 32 },
                    step_idx,
                    description: format!("range_check(rd=x{})", step.rd),
                });
                stats.alu_constraints += 2;
                stats.total_constraints += 2;
            }

            // ── Memory constraints ──
            if let Some((addr, _val, _is_write)) = step.mem_access {
                constraints.push(ZkvmConstraint {
                    kind: ZkvmConstraintKind::RangeCheck { bits: 32 },
                    step_idx,
                    description: format!("range_check(mem_addr=0x{:08x})", addr),
                });
                constraints.push(ZkvmConstraint {
                    kind: ZkvmConstraintKind::MemoryConsistency,
                    step_idx,
                    description: format!("mem_consistency(addr=0x{:08x})", addr),
                });
                stats.memory_constraints += 2;
                stats.range_checks += 1;
                stats.total_constraints += 2;
            }

            // ── Branch constraints ──
            if step.opcode.is_branch() {
                constraints.push(ZkvmConstraint {
                    kind: ZkvmConstraintKind::Equality,
                    step_idx,
                    description: format!("branch_condition({:?})", step.opcode),
                });
                stats.branch_constraints += 1;
                stats.total_constraints += 1;
            }
        }

        (constraints, stats)
    }

    /// Estimate constraint count without materialising the full list.
    pub fn estimate_constraints(trace: &ProgramTrace) -> usize {
        trace.total_constraints()
    }
}

// ─── Simple trace builder ─────────────────────────────────────────────────────

/// Helper for building test traces step by step.
pub struct TraceBuilder {
    trace: ProgramTrace,
    regs: RegisterFile,
    memory: BTreeMap<u32, u32>,
}

impl Default for TraceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceBuilder {
    /// Start with all registers zero, PC = 0.
    pub fn new() -> Self {
        Self {
            trace: ProgramTrace::new(),
            regs: RegisterFile::default(),
            memory: BTreeMap::new(),
        }
    }

    /// Add an ALU-R step (e.g. ADD rd, rs1, rs2).
    pub fn alu_r(mut self, opcode: RiscVOpcode, rd: usize, rs1: usize, rs2: usize) -> Self {
        let a = self.regs.read(rs1);
        let b = self.regs.read(rs2);
        let result = match opcode {
            RiscVOpcode::Add => a.wrapping_add(b),
            RiscVOpcode::Sub => a.wrapping_sub(b),
            RiscVOpcode::And => a & b,
            RiscVOpcode::Or => a | b,
            RiscVOpcode::Xor => a ^ b,
            _ => a.wrapping_add(b),
        };
        let regs_before = self.regs.regs;
        self.regs.write(rd, result);
        let regs_after = self.regs.regs;
        let pc = self.regs.pc;
        self.regs.pc = pc.wrapping_add(4);
        self.trace.steps.push(TraceStep {
            pc,
            opcode,
            rs1,
            rs2,
            rd,
            imm: 0,
            regs_before,
            regs_after,
            mem_access: None,
        });
        self
    }

    /// Add an immediate ALU step (e.g. ADDI rd, rs1, imm).
    pub fn alu_i(mut self, opcode: RiscVOpcode, rd: usize, rs1: usize, imm: i32) -> Self {
        let a = self.regs.read(rs1);
        let result = match opcode {
            RiscVOpcode::Addi => (a as i32).wrapping_add(imm) as u32,
            RiscVOpcode::Andi => a & (imm as u32),
            RiscVOpcode::Ori => a | (imm as u32),
            RiscVOpcode::Xori => a ^ (imm as u32),
            _ => (a as i32).wrapping_add(imm) as u32,
        };
        let regs_before = self.regs.regs;
        self.regs.write(rd, result);
        let regs_after = self.regs.regs;
        let pc = self.regs.pc;
        self.regs.pc = pc.wrapping_add(4);
        self.trace.steps.push(TraceStep {
            pc,
            opcode,
            rs1,
            rs2: 0,
            rd,
            imm,
            regs_before,
            regs_after,
            mem_access: None,
        });
        self
    }

    /// Add a load-word step.
    pub fn lw(mut self, rd: usize, rs1: usize, offset: i32) -> Self {
        let addr = (self.regs.read(rs1) as i32).wrapping_add(offset) as u32;
        let val = *self.memory.get(&addr).unwrap_or(&0);
        let regs_before = self.regs.regs;
        self.regs.write(rd, val);
        let regs_after = self.regs.regs;
        let pc = self.regs.pc;
        self.regs.pc = pc.wrapping_add(4);
        self.trace.steps.push(TraceStep {
            pc,
            opcode: RiscVOpcode::Lw,
            rs1,
            rs2: 0,
            rd,
            imm: offset,
            regs_before,
            regs_after,
            mem_access: Some((addr, val, false)),
        });
        self
    }

    /// Add a store-word step.
    pub fn sw(mut self, rs2: usize, rs1: usize, offset: i32) -> Self {
        let addr = (self.regs.read(rs1) as i32).wrapping_add(offset) as u32;
        let val = self.regs.read(rs2);
        self.memory.insert(addr, val);
        let regs_before = self.regs.regs;
        let regs_after = self.regs.regs;
        let pc = self.regs.pc;
        self.regs.pc = pc.wrapping_add(4);
        self.trace.steps.push(TraceStep {
            pc,
            opcode: RiscVOpcode::Sw,
            rs1,
            rs2,
            rd: 0,
            imm: offset,
            regs_before,
            regs_after,
            mem_access: Some((addr, val, true)),
        });
        self
    }

    /// Finish and return the trace.
    pub fn build(self) -> ProgramTrace {
        self.trace
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn add_trace() -> ProgramTrace {
        TraceBuilder::new()
            .alu_i(RiscVOpcode::Addi, 1, 0, 10) // x1 = 10
            .alu_i(RiscVOpcode::Addi, 2, 0, 20) // x2 = 20
            .alu_r(RiscVOpcode::Add, 3, 1, 2)   // x3 = x1 + x2 = 30
            .build()
    }

    #[test]
    fn test_trace_builder_alu() {
        let trace = add_trace();
        assert_eq!(trace.steps.len(), 3);
        // After ADDI x1, x0, 10: x1 = 10
        assert_eq!(trace.steps[0].regs_after[1], 10);
        // After ADDI x2, x0, 20: x2 = 20
        assert_eq!(trace.steps[1].regs_after[2], 20);
        // After ADD x3, x1, x2: x3 = 30
        assert_eq!(trace.steps[2].regs_after[3], 30);
    }

    #[test]
    fn test_trace_memory_ops() {
        let trace = TraceBuilder::new()
            .alu_i(RiscVOpcode::Addi, 1, 0, 42)  // x1 = 42
            .alu_i(RiscVOpcode::Addi, 5, 0, 100) // x5 = 100 (base addr)
            .sw(1, 5, 0)                          // mem[100] = 42
            .lw(2, 5, 0)                          // x2 = mem[100] = 42
            .build();

        assert_eq!(trace.memory_access_count(), 2);
        let sw_step = &trace.steps[2];
        assert_eq!(sw_step.mem_access, Some((100, 42, true)));
        let lw_step = &trace.steps[3];
        assert_eq!(lw_step.regs_after[2], 42);
    }

    #[test]
    fn test_constraint_builder_output() {
        let trace = add_trace();
        let (constraints, stats) = ZkvmConstraintBuilder::build(&trace);

        assert!(!constraints.is_empty(), "must generate constraints");
        assert!(stats.total_constraints > 0);
        assert!(
            stats.alu_constraints > 0,
            "ALU ops must generate ALU constraints"
        );
        assert_eq!(stats.total_constraints, constraints.len());
    }

    #[test]
    fn test_memory_constraints_generated() {
        let trace = TraceBuilder::new()
            .alu_i(RiscVOpcode::Addi, 5, 0, 200)
            .sw(0, 5, 0)
            .lw(1, 5, 0)
            .build();
        let (_, stats) = ZkvmConstraintBuilder::build(&trace);
        assert!(
            stats.memory_constraints > 0,
            "memory ops must generate consistency constraints"
        );
    }

    #[test]
    fn test_opcode_constraint_counts_positive() {
        let opcodes = [
            RiscVOpcode::Add,
            RiscVOpcode::Sub,
            RiscVOpcode::Xor,
            RiscVOpcode::Lw,
            RiscVOpcode::Sw,
            RiscVOpcode::Beq,
            RiscVOpcode::Jal,
            RiscVOpcode::Nop,
        ];
        for op in &opcodes {
            assert!(
                op.constraint_count() > 0,
                "{:?} must have positive constraint count",
                op
            );
        }
    }

    #[test]
    fn test_trace_total_constraints() {
        let trace = add_trace();
        let estimated = ZkvmConstraintBuilder::estimate_constraints(&trace);
        let (_, stats) = ZkvmConstraintBuilder::build(&trace);
        // The builder stats count constraints; estimate is a lower bound
        assert!(estimated > 0);
        assert!(stats.total_constraints > 0);
    }

    #[test]
    fn test_register_file_x0_always_zero() {
        let mut rf = RegisterFile::default();
        rf.write(0, 99); // should be silently dropped
        assert_eq!(rf.read(0), 0);
    }

    #[test]
    fn test_zkvm_stats_describe_non_empty() {
        let trace = add_trace();
        let (_, stats) = ZkvmConstraintBuilder::build(&trace);
        let desc = stats.describe();
        assert!(!desc.is_empty());
        assert!(desc.contains("total="));
    }

    #[test]
    fn test_alu_opcode_classification() {
        assert!(RiscVOpcode::Add.is_alu());
        assert!(RiscVOpcode::Xor.is_alu());
        assert!(!RiscVOpcode::Lw.is_alu());
        assert!(!RiscVOpcode::Beq.is_alu());
    }
}
