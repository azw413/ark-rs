//! Instruction level representation for Ark bytecode functions.

use std::borrow::Cow;

use crate::types::{FieldId, FunctionId, StringId, TypeDescriptor, TypeId};

/// Zero-based instruction index within a function body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct InstructionIndex(pub u32);

impl InstructionIndex {
    pub const fn new(index: u32) -> Self {
        InstructionIndex(index)
    }
}

/// Virtual register identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Register(pub u16);

impl Register {
    pub const fn new(index: u16) -> Self {
        Register(index)
    }
}

/// Represents the bit-width of a register operand in the encoded instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegisterWidth {
    V4,
    V8,
    V16,
}

/// Represents the bit-width of an immediate operand in the encoded instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImmediateWidth {
    Imm4,
    Imm8,
    Imm16,
    Imm32,
    Imm64,
}

/// Represents the bit-width of identifier operands (constant pool references).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentifierWidth {
    Id16,
}

/// Represents a contiguous range of registers used by an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegisterSpan {
    pub start: Register,
    pub count: u16,
}

impl RegisterSpan {
    pub const fn new(start: Register, count: u16) -> Self {
        RegisterSpan { start, count }
    }
}

/// Register operands annotated with their encoded width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegisterOperand {
    V4(Register),
    V8(Register),
    V16(Register),
    Argument(Register),
    Span(RegisterSpan),
}

/// Immediate operands annotated with their encoded width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImmediateOperand {
    Imm4(u8),
    Imm8(u8),
    Imm16(u16),
    Imm32(u32),
    Imm64(u64),
}

/// Identifier operands as they appear in encoded instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentifierOperand {
    Id16(u16),
}

/// All supported operand categories that may appear on an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperandKind {
    Register(RegisterWidth),
    RegisterSpan,
    Immediate(ImmediateWidth),
    Identifier(IdentifierWidth),
    String,
    Type,
    TypeId,
    Field,
    Function,
    MethodHandle,
    LiteralIndex,
    Label,
    ConditionCode,
    ComparisonKind,
}

/// Operand payload paired with its [`OperandKind`].
#[derive(Debug, Clone, PartialEq)]
pub enum Operand {
    Register(RegisterOperand),
    Immediate(ImmediateOperand),
    Identifier(IdentifierOperand),
    String(StringId),
    Type(TypeDescriptor),
    TypeId(TypeId),
    Field(FieldId),
    Function(FunctionId),
    MethodHandle(u32),
    LiteralIndex(u32),
    Label(u32),
    ConditionCode(ConditionCode),
    Comparison(ComparisonKind),
}

/// Condition codes used by branch instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConditionCode {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    Overflow,
    NoOverflow,
    Carry,
    NoCarry,
    Always,
}

/// Comparison kinds used by typed compare instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComparisonKind {
    Int,
    Uint,
    Long,
    Ulong,
    Float,
    Double,
    Object,
}

/// Encodes the operand layout for a single instruction as defined by the Ark specification.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstructionFormat {
    NONE,
    ID16,
    IMM4_IMM4,
    IMM8,
    IMM8_ID16,
    IMM8_ID16_IMM8,
    IMM8_ID16_V8,
    IMM8_ID16_ID16_IMM16_V8,
    IMM8_IMM8,
    IMM8_IMM8_V8,
    IMM8_IMM16,
    IMM8_IMM16_IMM16,
    IMM8_IMM16_IMM16_V8,
    IMM8_V8,
    IMM8_V8_IMM16,
    IMM8_V8_V8,
    IMM8_V8_V8_V8,
    IMM8_V8_V8_V8_V8,
    IMM16,
    IMM16_ID16,
    IMM16_ID16_IMM8,
    IMM16_ID16_V8,
    IMM16_ID16_ID16_IMM16_V8,
    IMM16_IMM16,
    IMM16_IMM8_V8,
    IMM16_V8,
    IMM16_V8_IMM16,
    IMM16_V8_V8,
    IMM32,
    IMM64,
    PREF_NONE,
    PREF_IMM8,
    PREF_IMM8_V8,
    PREF_IMM8_V8_V8,
    PREF_IMM8_IMM8,
    PREF_IMM8_IMM32_V8,
    PREF_IMM8_IMM16_IMM16_V8,
    PREF_IMM4_IMM4,
    PREF_IMM16,
    PREF_IMM16_V8,
    PREF_IMM16_V8_V8,
    PREF_IMM16_ID16,
    PREF_IMM16_ID16_ID16_IMM16_V8,
    PREF_IMM16_IMM16,
    PREF_IMM32,
    PREF_V8,
    PREF_V8_V8,
    PREF_V8_ID16,
    PREF_V8_IMM32,
    PREF_ID16,
    V4_V4,
    V8,
    V8_IMM8,
    V8_IMM16,
    V8_V8,
    V8_V8_V8,
    V8_V8_V8_V8,
    V16_V16,
}

/// Describes the opcode executed by an instruction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Opcode {
    LdUndefined,
    LdNull,
    LdTrue,
    LdFalse,
    CreateEmptyObject,
    CreateEmptyArray,
    CreateArrayWithBuffer,
    CreateObjectWithBuffer,
    NewObjRange,
    NewLexEnv,
    Add2,
    Sub2,
    Mul2,
    Div2,
    Mod2,
    Eq,
    NotEq,
    Less,
    LessEq,
    Greater,
    GreaterEq,
    Shl2,
    Shr2,
    Ashr2,
    And2,
    Or2,
    Xor2,
    Exp,
    TypeOf,
    ToNumber,
    ToNumeric,
    Neg,
    Not,
    Inc,
    Dec,
    IsTrue,
    IsFalse,
    IsIn,
    InstanceOf,
    StrictNotEq,
    StrictEq,
    CallArg0,
    CallArg1,
    CallArgs2,
    CallArgs3,
    CallThis0,
    CallThis1,
    CallThis2,
    CallThis3,
    CallThisRange,
    SuperCallThisRange,
    DefineFunc,
    DefineMethod,
    DefineClassWithBuffer,
    GetNextPropName,
    LdObjByValue,
    StObjByValue,
    LdSuperByValue,
    LdObjByIndex,
    StObjByIndex,
    LdLexVar,
    StLexVar,
    LdaStr,
    TryLdGlobalByName,
    TryStGlobalByName,
    LdGlobalVar,
    LdObjByName,
    StObjByName,
    MovV4,
    MovV8,
    LdSuperByName,
    StConstToGlobalRecord,
    StToGlobalRecord,
    LdThisByName,
    StThisByName,
    LdThisByValue,
    StThisByValue,
    JmpImm8,
    JmpImm16,
    JEqzImm8,
    JEqzImm16,
    JNezImm8,
    JStrictEqzImm8,
    JNStrictEqzImm8,
    JEqNullImm8,
    JNeNullImm8,
    JStrictEqNullImm8,
    JNStrictEqNullImm8,
    JEqUndefinedImm8,
    JNeUndefinedImm8,
    JStrictEqUndefinedImm8,
    JNStrictEqUndefinedImm8,
    JEqRegImm8,
    JNeRegImm8,
    JStrictEqRegImm8,
    JNStrictEqRegImm8,
    Lda,
    Sta,
    Ldai,
    FLdai,
    Return,
    ReturnUndefined,
    GetPropIterator,
    GetIterator,
    CloseIterator,
    PopLexEnv,
    LdNan,
    LdInfinity,
    GetUnmappedArgs,
    LdGlobal,
    LdNewTarget,
    LdThis,
    LdHole,
    CreateRegExpWithLiteral,
    CreateRegExpWithLiteralWide,
    CallRange,
    DefineFuncWide,
    DefineClassWithBufferWide,
    GetTemplateObject,
    SetObjectWithProto,
    StOwnByValue,
    StOwnByIndex,
    StOwnByName,
    GetModuleNamespace,
    StModuleVar,
    LdLocalModuleVar,
    LdExternalModuleVar,
    StGlobalVar,
    CreateEmptyArrayWide,
    CreateArrayWithBufferWide,
    CreateObjectWithBufferWide,
    NewObjRangeWide,
    TypeOfWide,
    LdObjByValueWide,
    StObjByValueWide,
    LdSuperByValueWide,
    LdObjByIndexWide,
    StObjByIndexWide,
    LdLexVarImm8,
    StLexVarImm8,
    TryLdGlobalByNameWide,
    TryStGlobalByNameWide,
    StOwnByNameWithNameSet,
    MovV16,
    LdObjByNameWide,
    StObjByNameWide,
    LdSuperByNameWide,
    LdThisByNameWide,
    StThisByNameWide,
    LdThisByValueWide,
    StThisByValueWide,
    AsyncGeneratorReject,
    JmpImm32,
    StOwnByValueWithNameSet,
    JEqzImm32,
    JNezImm16,
    JNezImm32,
    JStrictEqzImm16,
    JNStrictEqzImm16,
    JEqNullImm16,
    JNeNullImm16,
    JStrictEqNullImm16,
    JNStrictEqNullImm16,
    JEqUndefinedImm16,
    JNeUndefinedImm16,
    JStrictEqUndefinedImm16,
    JNStrictEqUndefinedImm16,
    JEqRegImm16,
    JNeRegImm16,
    JStrictEqRegImm16,
    JNStrictEqRegImm16,
    GetIteratorWide,
    CloseIteratorWide,
    LdSymbol,
    AsyncFunctionEnter,
    LdFunction,
    Debugger,
    CreateGeneratorObj,
    CreateIterResultObj,
    CreateObjectWithExcludedKeys,
    NewObjApply,
    NewObjApplyWide,
    NewLexEnvWithName,
    CreateAsyncGeneratorObj,
    AsyncGeneratorResolve,
    SuperCallSpread,
    Apply,
    SuperCallArrowRange,
    DefineGetterSetterByValue,
    DynamicImport,
    DefineMethodWide,
    ResumeGenerator,
    GetResumeMode,
    GetTemplateObjectWide,
    DelObjProp,
    SuspendGenerator,
    AsyncFunctionAwaitUncaught,
    CopyDataProperties,
    StArraySpread,
    SetObjectWithProtoWide,
    StOwnByValueWide,
    StSuperByValue,
    StSuperByValueWide,
    StOwnByIndexWide,
    StOwnByNameWide,
    AsyncFunctionResolve,
    AsyncFunctionReject,
    CopyRestArgs,
    StSuperByName,
    StSuperByNameWide,
    StOwnByValueWithNameSetWide,
    LdBigInt,
    StOwnByNameWithNameSetWide,
    Nop,
    SetGeneratorState,
    GetAsyncIterator,
    LdPrivateProperty,
    StPrivateProperty,
    TestIn,
    DefineFieldByName,
    DefinePropertyByName,
    CallRuntimeNotifyConcurrentResult,
    WideCreateObjectWithExcludedKeys,
    Throw,
    CallRuntimeDefineFieldByValue,
    WideNewObjRange,
    ThrowNotExists,
    CallRuntimeDefineFieldByIndex,
    WideNewLexEnv,
    ThrowPatternNonCoercible,
    CallRuntimeToPropertyKey,
    WideNewLexEnvWithName,
    ThrowDeleteSuperProperty,
    CallRuntimeCreatePrivateProperty,
    WideCallRange,
    ThrowConstAssignment,
    CallRuntimeDefinePrivateProperty,
    WideCallThisRange,
    ThrowIfNotObject,
    CallRuntimeCallInit,
    WideSuperCallThisRange,
    ThrowUndefinedIfHole,
    CallRuntimeDefineSendableClass,
    WideSuperCallArrowRange,
    ThrowIfSuperNotCorrectCallImm8,
    CallRuntimeLdSendableClass,
    WideLdObjByIndex,
    ThrowIfSuperNotCorrectCallImm16,
    CallRuntimeLdSendableExternalModuleVar,
    WideStObjByIndex,
    ThrowUndefinedIfHoleWithName,
    CallRuntimeWideLdSendableExternalModuleVar,
    WideStOwnByIndex,
    CallRuntimeNewSendableEnv,
    WideCopyRestArgs,
    CallRuntimeWideNewSendableEnv,
    WideLdLexVar,
    CallRuntimeStSendableVarImm4,
    WideStLexVar,
    CallRuntimeStSendableVarImm8,
    WideGetModuleNamespace,
    CallRuntimeWideStSendableVar,
    WideStModuleVar,
    CallRuntimeLdSendableVarImm4,
    WideLdLocalModuleVar,
    CallRuntimeLdSendableVarImm8,
    WideLdExternalModuleVar,
    CallRuntimeWideLdSendableVar,
    WideLdPatchVar,
    CallRuntimeIsTrue,
    WideStPatchVar,
    CallRuntimeIsFalse,
    CallRuntimeLdLazyModuleVar,
    CallRuntimeWideLdLazyModuleVar,
    CallRuntimeLdLazySendableModuleVar,
    CallRuntimeWideLdLazySendableModuleVar,
    Extended(String),
    Raw(u16),
}

impl Opcode {
    /// Return the canonical mnemonic string for this opcode.
    pub fn mnemonic(&self) -> Cow<'_, str> {
        match self {
            Opcode::MovV4 | Opcode::MovV8 | Opcode::MovV16 => Cow::Borrowed("mov"),
            Opcode::Lda => Cow::Borrowed("lda"),
            Opcode::Sta => Cow::Borrowed("sta"),
            Opcode::Return => Cow::Borrowed("return"),
            Opcode::LdaStr => Cow::Borrowed("lda.str"),
            Opcode::LdObjByName | Opcode::LdObjByNameWide => Cow::Borrowed("ldobjbyname"),
            Opcode::LdLexVar | Opcode::LdLexVarImm8 | Opcode::WideLdLexVar => {
                Cow::Borrowed("ldlexvar")
            }
            Opcode::GetModuleNamespace | Opcode::WideGetModuleNamespace => {
                Cow::Borrowed("getmodulenamespace")
            }
            Opcode::LdExternalModuleVar | Opcode::WideLdExternalModuleVar => {
                Cow::Borrowed("ldexternalmodulevar")
            }
            Opcode::LdLocalModuleVar | Opcode::WideLdLocalModuleVar => {
                Cow::Borrowed("ldlocalmodulevar")
            }
            Opcode::ThrowUndefinedIfHoleWithName | Opcode::StOwnByNameWithNameSetWide => {
                Cow::Borrowed("throw.undefinedifholewithname")
            }
            Opcode::ThrowIfSuperNotCorrectCallImm8 | Opcode::ThrowIfSuperNotCorrectCallImm16 => {
                Cow::Borrowed("throw.ifsupernotcorrectcall")
            }
            Opcode::Extended(name) => Cow::Borrowed(name.as_str()),
            Opcode::Raw(_) => Cow::Borrowed("raw"),
            Opcode::JEqRegImm8 | Opcode::JEqRegImm16 => Cow::Borrowed("jeq"),
            Opcode::JNeRegImm8 | Opcode::JNeRegImm16 => Cow::Borrowed("jne"),
            Opcode::JStrictEqRegImm8 | Opcode::JStrictEqRegImm16 => Cow::Borrowed("jstricteq"),
            Opcode::JNStrictEqRegImm8 | Opcode::JNStrictEqRegImm16 => Cow::Borrowed("jnstricteq"),
            _ => Cow::Owned(self.derive_mnemonic()),
        }
    }

    fn derive_mnemonic(&self) -> String {
        let mut name = format!("{:?}", self);
        if let Some(index) = name.find('(') {
            name.truncate(index);
        }

        let mut lower = String::with_capacity(name.len());
        for ch in name.chars() {
            if ch != '_' {
                lower.push(ch.to_ascii_lowercase());
            }
        }

        let mut result = if let Some(rest) = lower.strip_prefix("throw") {
            let stripped = Self::strip_suffixes(rest);
            if stripped.is_empty() {
                "throw".to_owned()
            } else {
                format!("throw.{}", stripped)
            }
        } else if let Some(rest) = lower.strip_prefix("callruntime") {
            let stripped = Self::strip_suffixes(rest);
            if stripped.is_empty() {
                "callruntime".to_owned()
            } else {
                format!("callruntime.{}", stripped)
            }
        } else if let Some(rest) = lower.strip_prefix("wide") {
            let stripped = Self::strip_suffixes(rest);
            if stripped.is_empty() {
                "wide".to_owned()
            } else {
                format!("wide.{}", stripped)
            }
        } else {
            Self::strip_suffixes(&lower)
        };

        if result.ends_with("reg") {
            result.truncate(result.len().saturating_sub(3));
        }

        if result.is_empty() {
            "unknown".to_owned()
        } else {
            result
        }
    }

    fn strip_suffixes(text: &str) -> String {
        let mut candidate = text;
        for suffix in ["imm64", "imm32", "imm16", "imm8", "imm4", "v16", "v8", "v4"] {
            if let Some(stripped) = candidate.strip_suffix(suffix) {
                candidate = stripped;
                break;
            }
        }
        candidate.to_owned()
    }

    /// Canonical instruction format associated with this opcode.
    pub fn canonical_format(&self) -> InstructionFormat {
        match self {
            Opcode::GetModuleNamespace => InstructionFormat::IMM8,
            Opcode::Ldai => InstructionFormat::IMM32,
            Opcode::StModuleVar => InstructionFormat::IMM8,
            Opcode::LdExternalModuleVar => InstructionFormat::IMM8,
            Opcode::Sta => InstructionFormat::V8,
            Opcode::ThrowUndefinedIfHoleWithName => InstructionFormat::PREF_ID16,
            Opcode::Lda => InstructionFormat::V8,
            Opcode::Add2 => InstructionFormat::IMM8_V8,
            Opcode::LdLocalModuleVar => InstructionFormat::IMM8,
            _ => InstructionFormat::NONE,
        }
    }
}

/// A single Ark bytecode instruction with decoded operands.
#[derive(Debug, Clone, PartialEq)]
pub struct Instruction {
    pub index: InstructionIndex,
    pub opcode: Opcode,
    pub format: InstructionFormat,
    pub operands: Vec<Operand>,
    pub flags: InstructionFlags,
    pub comment: Option<String>,
}

impl Instruction {
    pub fn new(index: InstructionIndex, opcode: Opcode) -> Self {
        let format = opcode.canonical_format();
        Instruction {
            index,
            opcode,
            format,
            operands: Vec::new(),
            flags: InstructionFlags::NONE,
            comment: None,
        }
    }

    pub fn with_format(index: InstructionIndex, opcode: Opcode, format: InstructionFormat) -> Self {
        let mut instruction = Instruction::new(index, opcode);
        instruction.format = format;
        instruction
    }
}

/// Additional instruction-level flags used by Ark bytecode encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstructionFlags(pub u8);

impl InstructionFlags {
    pub const NONE: InstructionFlags = InstructionFlags(0);
    pub const VOLATILE: InstructionFlags = InstructionFlags(1 << 0);
    pub const DEBUG_BREAKPOINT: InstructionFlags = InstructionFlags(1 << 1);
    pub const SUSPEND_CHECK: InstructionFlags = InstructionFlags(1 << 2);

    pub const fn contains(self, other: InstructionFlags) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn union(self, other: InstructionFlags) -> InstructionFlags {
        InstructionFlags(self.0 | other.0)
    }
}
