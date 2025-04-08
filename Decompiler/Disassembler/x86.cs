using System;
using System.IO;
using Decompiler.Disassembler.x86AAC;
using Decompiler.Files;

namespace Decompiler.Disassembler
{
    public enum Registers : int
    {
        EAX,
        ECX,
        EDX,
        EBX,
        ESP,
        EBP,
        ESI,
        EDI,
        MODR,
        AL,
        AX,
        ES,
        CS,
        SS,
        DS,
        CL,
        DL,
        BL,
        AH,
        CH,
        DH,
        BH,
        DX,
    }

    enum Instructions : int
    {
        ADD,
        SUB,
        PUSH,
        POP,
        MOV,
        LEA,
        REP,
        RETN,
        CALL,
        SBB,
        AND,
        XOR,
        CMP,
        JNZ,
        JZ,
        JL,
        JG,
        JBE,
        JGE,
        JLE,
        JMP,
        MOVZX,
        TEST,
        SETZ,
        OR,
        ADC,
        INC,
        DEC,
        PUSHA,
        POPA,
        BOUND,
        ARPL,
        IMUL,
        INSB,
        INSW,
        OUTSB,
        OUTSW,
        JO,
        JNO,
        JB,
        JNB,
        JA,
        JS,
        JNS,
        JP,
        JNP,
        JNL,
        XCHG,
        NOP,
        PUSHF,
        POPF,
        SAHF,
        LAHF,
        MOVSB,
        MOVSW,
        CMPSB,
        CMPSW,
        STOSB,
        STOSW,
        LODSB,
        LODSW,
        SCASB,
        SCASW,
        LES,
        ENTER,
        LEAVE,
        INT3,
        INT,
        INTO,
        IRET,
        AAM,
        AAD,
        SALC,
        XALC,
        ESC,
        LOOPNZ,
        LOOPZ,
        LOOP,
        JCXZ,
        IN,
        OUT,
        INT1,
        HLT,
        CMD,
        CLC,
        STC,
        CLI,
        STI,
        CLD,
        STD,
    }

    enum Prefixes : int
    {
        None = 0,
        FS,
        GS,
        ES,
        AAA,
        CS,
        DAS,
        SS,
        DAA,
        DS,
        AAS,
        OPSIZE,
        ADSIZE,
    }

    /// <summary>
    /// This disassembler is responsible for the x86 instruction set
    /// </summary>
    public class x86 : IDisassembler
    {
        public Section DisassembleSection(Stream binaryStream, SectionHeader sectionHeader, ulong imageBase)
        {
            binaryStream.Seek(sectionHeader.PointerToRawData, SeekOrigin.Begin);

            var section = new Section()
            {
                Header = sectionHeader,
                Name = new string(sectionHeader.Name).Replace("\0", ""),
                Address = imageBase + sectionHeader.VirtualAddress + ((ulong)binaryStream.Position - sectionHeader.PointerToRawData)
            };

            if (sectionHeader.Characteristics.HasFlag(SectionCharacteristics.Code))
                dumpCode(ref section, binaryStream, sectionHeader, imageBase);
            else
                dumpData(ref section, binaryStream, sectionHeader, imageBase);

            return section;
        }

        #region Private Types
        private struct PaddingInfo
        {
            /// <summary>
            /// The number of times this mnemonic was encountered
            /// </summary>
            public int Count;
            /// <summary>
            /// The mnemonic itself
            /// </summary>
            public int Mnemonic;

            /// <summary>
            /// Returns if we've encountered padding bytes before
            /// </summary>
            /// <returns></returns>
            public bool HasPadding()
            {
                return Count > 0;
            }
        }
        #endregion

        #region Private Fields
        /// <summary>
        /// The current 
        /// </summary>
        private ulong BaseAddress { get; set; } = 0;

        /// <summary>
        /// Encountered padding bytes in a row
        /// </summary>
        private PaddingInfo paddingInfo = new PaddingInfo();
        #endregion

        #region Mnemonic Parser
        private void WriteInstruction(LineList lineList, Instructions i, Registers r)
        {
            lineList.Append(i.ToString());
            if (r != Registers.MODR)
            {
                lineList.Append(string.Format(" {0}", r.ToString()));
            }
        }

        private void DumpCall(Stream binaryStream, LineList lineList, ulong memoryPos)
        {
            WriteInstruction(lineList, Instructions.CALL, Registers.MODR);
            byte[] buffer = new byte[4];
            binaryStream.Read(buffer, 0, 4);
            ulong relativePosition = (ulong)BitConverter.ToInt32(buffer, 0);
            ulong pos = memoryPos + relativePosition + 5; //+5, da das CALL 00000000 mitgerechnet werden muss

            ulong funcPos = memoryPos + 5 + relativePosition;
            //callAddresses.Add(funcPos); // private List<long> callAddresses = new List<long>();

            lineList.Append(string.Format(" {0:X}h", pos));
        }

        private void DumpJump(Stream binaryStream, LineList lineList, ulong memoryPos, Instructions instruction = Instructions.JMP)
        {
            ulong location = (ulong)binaryStream.ReadByte();
            ulong pos = memoryPos + location + 2; // +2, since JMP 00 must be added
            lineList.Append(string.Format("{1} {0:X}h", pos, instruction.ToString()));
        }

        private void WriteRegister(LineList lineList, Registers r, bool comma = true)
        {
            if (comma)
                lineList.Append(",");
            lineList.Append(string.Format(" {0}", r.ToString()));
        }

        private void DumpPrefix(LineList lineList, Prefixes prefix)
        {
            if (prefix != Prefixes.None)
                lineList.Append(prefix.ToString() + ":");
        }

        private void dumpMnemonic(int mnemonic, ulong memoryPositon, Stream binaryStream, LineList lineList, Prefixes prefix = Prefixes.None)
        {
            switch (mnemonic)
            {
                case 0x00: WriteInstruction(lineList, Instructions.ADD, Registers.MODR); E.Dump(binaryStream, lineList, new b()); break;
                case 0x01: WriteInstruction(lineList, Instructions.ADD, Registers.MODR); E.Dump(binaryStream, lineList, new v()); break;
                case 0x02: WriteInstruction(lineList, Instructions.ADD, Registers.MODR); G.Dump(binaryStream, lineList, new b()); break;
                case 0x03: WriteInstruction(lineList, Instructions.ADD, Registers.MODR); G.Dump(binaryStream, lineList, new v()); break;
                case 0x04: WriteInstruction(lineList, Instructions.ADD, Registers.AL); I.Dump(binaryStream, lineList, new b()); break;
                case 0x05: WriteInstruction(lineList, Instructions.ADD, Registers.AX); I.Dump(binaryStream, lineList, new w()); break;
                case 0x06: WriteInstruction(lineList, Instructions.PUSH, Registers.ES); break;
                case 0x07: WriteInstruction(lineList, Instructions.POP, Registers.ES); break;

                case 0x08: WriteInstruction(lineList, Instructions.OR, Registers.MODR); E.Dump(binaryStream, lineList, new b()); break;
                case 0x09: WriteInstruction(lineList, Instructions.OR, Registers.MODR); E.Dump(binaryStream, lineList, new v()); break;
                case 0x0A: WriteInstruction(lineList, Instructions.OR, Registers.MODR); G.Dump(binaryStream, lineList, new b()); break;
                case 0x0B: WriteInstruction(lineList, Instructions.OR, Registers.MODR); G.Dump(binaryStream, lineList, new v()); break;
                case 0x0C: WriteInstruction(lineList, Instructions.OR, Registers.AL); I.Dump(binaryStream, lineList, new b()); break;
                case 0x0D: WriteInstruction(lineList, Instructions.OR, Registers.EAX); I.Dump(binaryStream, lineList, new v()); break;
                case 0x0E: WriteInstruction(lineList, Instructions.PUSH, Registers.CS); E.Dump(binaryStream, lineList, new b()); break;
                case 0x0F: DumpTwoByte(binaryStream, lineList, binaryStream.ReadByte(), memoryPositon + 1); break;

                case 0x10: WriteInstruction(lineList, Instructions.ADC, Registers.MODR); E.Dump(binaryStream, lineList, new b()); break;
                case 0x11: WriteInstruction(lineList, Instructions.ADC, Registers.MODR); E.Dump(binaryStream, lineList, new v()); break;
                case 0x12: WriteInstruction(lineList, Instructions.ADC, Registers.MODR); G.Dump(binaryStream, lineList, new b()); break;
                case 0x13: WriteInstruction(lineList, Instructions.ADC, Registers.MODR); G.Dump(binaryStream, lineList, new v()); break;
                case 0x14: WriteInstruction(lineList, Instructions.ADC, Registers.AL); I.Dump(binaryStream, lineList, new b()); break;
                case 0x15: WriteInstruction(lineList, Instructions.ADC, Registers.EAX); I.Dump(binaryStream, lineList, new b()); break;
                case 0x16: WriteInstruction(lineList, Instructions.PUSH, Registers.SS); break;
                case 0x17: WriteInstruction(lineList, Instructions.PUSH, Registers.SS); break;

                case 0x18: WriteInstruction(lineList, Instructions.SBB, Registers.MODR); E.Dump(binaryStream, lineList, new b()); break;
                case 0x19: WriteInstruction(lineList, Instructions.SBB, Registers.MODR); E.Dump(binaryStream, lineList, new v()); break;
                case 0x1A: WriteInstruction(lineList, Instructions.SBB, Registers.MODR); G.Dump(binaryStream, lineList, new b()); break;
                case 0x1B: WriteInstruction(lineList, Instructions.SBB, Registers.MODR); G.Dump(binaryStream, lineList, new v()); break;
                case 0x1C: WriteInstruction(lineList, Instructions.SBB, Registers.AL); I.Dump(binaryStream, lineList, new b()); break;
                case 0x1D: WriteInstruction(lineList, Instructions.SBB, Registers.EAX); I.Dump(binaryStream, lineList, new v()); break;
                case 0x1E: WriteInstruction(lineList, Instructions.PUSH, Registers.DS); break;
                case 0x1F: WriteInstruction(lineList, Instructions.PUSH, Registers.DS); break;

                case 0x20: WriteInstruction(lineList, Instructions.AND, Registers.MODR); E.Dump(binaryStream, lineList, new b()); break;
                case 0x21: WriteInstruction(lineList, Instructions.AND, Registers.MODR); E.Dump(binaryStream, lineList, new v()); break;
                case 0x22: WriteInstruction(lineList, Instructions.AND, Registers.MODR); G.Dump(binaryStream, lineList, new b()); break;
                case 0x23: WriteInstruction(lineList, Instructions.AND, Registers.MODR); G.Dump(binaryStream, lineList, new v()); break;
                case 0x24: WriteInstruction(lineList, Instructions.AND, Registers.AL); I.Dump(binaryStream, lineList, new b()); break;
                case 0x25: WriteInstruction(lineList, Instructions.AND, Registers.EAX); I.Dump(binaryStream, lineList, new v()); break;
                case 0x26: byte es = (byte)binaryStream.ReadByte(); dumpMnemonic((int)es, memoryPositon, binaryStream, lineList, Prefixes.ES); break;
                //case 0x27: break;

                case 0x28: WriteInstruction(lineList, Instructions.SUB, Registers.MODR); E.Dump(binaryStream, lineList, new b()); break;
                case 0x29: WriteInstruction(lineList, Instructions.SUB, Registers.MODR); E.Dump(binaryStream, lineList, new v()); break;
                case 0x2A: WriteInstruction(lineList, Instructions.SUB, Registers.MODR); G.Dump(binaryStream, lineList, new b()); break;
                case 0x2B: WriteInstruction(lineList, Instructions.SUB, Registers.MODR); G.Dump(binaryStream, lineList, new v()); break;
                case 0x2C: WriteInstruction(lineList, Instructions.SUB, Registers.AL); I.Dump(binaryStream, lineList, new b()); break;
                case 0x2D: WriteInstruction(lineList, Instructions.SUB, Registers.EAX); I.Dump(binaryStream, lineList, new v()); break;
                case 0x2E: byte cs = (byte)binaryStream.ReadByte(); dumpMnemonic((int)cs, memoryPositon, binaryStream, lineList, Prefixes.CS); break;
                //case 0x2F: break;

                case 0x30: WriteInstruction(lineList, Instructions.XOR, Registers.MODR); E.Dump(binaryStream, lineList, new b()); break;
                case 0x31: WriteInstruction(lineList, Instructions.XOR, Registers.MODR); E.Dump(binaryStream, lineList, new v()); break;
                case 0x32: WriteInstruction(lineList, Instructions.XOR, Registers.MODR); G.Dump(binaryStream, lineList, new b()); break;
                case 0x33: WriteInstruction(lineList, Instructions.XOR, Registers.MODR); G.Dump(binaryStream, lineList, new v()); break;
                case 0x34: WriteInstruction(lineList, Instructions.XOR, Registers.AL); I.Dump(binaryStream, lineList, new b()); break;
                case 0x35: WriteInstruction(lineList, Instructions.XOR, Registers.EAX); I.Dump(binaryStream, lineList, new v()); break;
                case 0x36: byte ss = (byte)binaryStream.ReadByte(); dumpMnemonic((int)ss, memoryPositon, binaryStream, lineList, Prefixes.SS); break;
                //case 0x37: break;

                case 0x38: WriteInstruction(lineList, Instructions.CMP, Registers.MODR); E.Dump(binaryStream, lineList, new b()); break;
                case 0x39: WriteInstruction(lineList, Instructions.CMP, Registers.MODR); E.Dump(binaryStream, lineList, new v()); break;
                case 0x3A: WriteInstruction(lineList, Instructions.CMP, Registers.MODR); G.Dump(binaryStream, lineList, new b()); break;
                case 0x3B: WriteInstruction(lineList, Instructions.CMP, Registers.MODR); G.Dump(binaryStream, lineList, new v()); break;
                case 0x3C: WriteInstruction(lineList, Instructions.CMP, Registers.AL); I.Dump(binaryStream, lineList, new b()); break;
                case 0x3D: WriteInstruction(lineList, Instructions.CMP, Registers.EAX); I.Dump(binaryStream, lineList, new v()); break;
                case 0x3E: byte ds = (byte)binaryStream.ReadByte(); dumpMnemonic((int)ds, memoryPositon, binaryStream, lineList, Prefixes.DS); break;
                //case 0x3F: break;

                case 0x40: WriteInstruction(lineList, Instructions.INC, Registers.EAX); break;
                case 0x41: WriteInstruction(lineList, Instructions.INC, Registers.ECX); break;
                case 0x42: WriteInstruction(lineList, Instructions.INC, Registers.EDX); break;
                case 0x43: WriteInstruction(lineList, Instructions.INC, Registers.EBX); break;
                case 0x44: WriteInstruction(lineList, Instructions.INC, Registers.ESP); break;
                case 0x45: WriteInstruction(lineList, Instructions.INC, Registers.EBP); break;
                case 0x46: WriteInstruction(lineList, Instructions.INC, Registers.ESI); break;
                case 0x47: WriteInstruction(lineList, Instructions.INC, Registers.EDI); break;

                case 0x48: WriteInstruction(lineList, Instructions.DEC, Registers.EAX); break;
                case 0x49: WriteInstruction(lineList, Instructions.DEC, Registers.ECX); break;
                case 0x4A: WriteInstruction(lineList, Instructions.DEC, Registers.EDX); break;
                case 0x4B: WriteInstruction(lineList, Instructions.DEC, Registers.EBX); break;
                case 0x4C: WriteInstruction(lineList, Instructions.DEC, Registers.ESP); break;
                case 0x4D: WriteInstruction(lineList, Instructions.DEC, Registers.EBP); break;
                case 0x4E: WriteInstruction(lineList, Instructions.DEC, Registers.ESI); break;
                case 0x4F: WriteInstruction(lineList, Instructions.DEC, Registers.EDI); break;

                case 0x50: WriteInstruction(lineList, Instructions.PUSH, Registers.EAX); break;
                case 0x51: WriteInstruction(lineList, Instructions.PUSH, Registers.ECX); break;
                case 0x52: WriteInstruction(lineList, Instructions.PUSH, Registers.EDX); break;
                case 0x53: WriteInstruction(lineList, Instructions.PUSH, Registers.EBX); break;
                case 0x54: WriteInstruction(lineList, Instructions.PUSH, Registers.ESP); break;
                case 0x55: WriteInstruction(lineList, Instructions.PUSH, Registers.EBP); break;
                case 0x56: WriteInstruction(lineList, Instructions.PUSH, Registers.ESI); break;
                case 0x57: WriteInstruction(lineList, Instructions.PUSH, Registers.EDI); break;

                case 0x58: WriteInstruction(lineList, Instructions.POP, Registers.EAX); break;
                case 0x59: WriteInstruction(lineList, Instructions.POP, Registers.ECX); break;
                case 0x5A: WriteInstruction(lineList, Instructions.POP, Registers.EDX); break;
                case 0x5B: WriteInstruction(lineList, Instructions.POP, Registers.EBX); break;
                case 0x5C: WriteInstruction(lineList, Instructions.POP, Registers.ESP); break;
                case 0x5D: WriteInstruction(lineList, Instructions.POP, Registers.EBP); break;
                case 0x5E: WriteInstruction(lineList, Instructions.POP, Registers.ESI); break;
                case 0x5F: WriteInstruction(lineList, Instructions.POP, Registers.EDI); break;

                case 0x60: WriteInstruction(lineList, Instructions.PUSHA, Registers.MODR); break;
                case 0x61: WriteInstruction(lineList, Instructions.POPA, Registers.MODR); break;
                case 0x62: WriteInstruction(lineList, Instructions.BOUND, Registers.MODR); G.Dump(binaryStream, lineList, new v()); break;
                case 0x63: WriteInstruction(lineList, Instructions.ARPL, Registers.MODR); E.Dump(binaryStream, lineList, new w()); break;
                case 0x64: byte sb = (byte)binaryStream.ReadByte(); dumpMnemonic((int)sb, memoryPositon, binaryStream, lineList, Prefixes.FS); break;
                case 0x65: byte gs = (byte)binaryStream.ReadByte(); dumpMnemonic((int)gs, memoryPositon, binaryStream, lineList, Prefixes.GS); break;
                //case 0x66: byte os = (byte)binaryStream.ReadByte(); dumpMnemonic((int)os, memoryPositon, binaryStream, Prefixes.OPSIZE); break;
                //case 0x67: break;

                case 0x68: WriteInstruction(lineList, Instructions.PUSH, Registers.MODR); I.DumpNoComma(binaryStream, lineList, new v()); break;
                case 0x69: WriteInstruction(lineList, Instructions.IMUL, Registers.MODR); G.Dump(binaryStream, lineList, new v(), false); I.Dump(binaryStream, lineList, new v()); break;
                case 0x6A: WriteInstruction(lineList, Instructions.PUSH, Registers.MODR); I.DumpNoComma(binaryStream, lineList, new b()); break;
                case 0x6B: WriteInstruction(lineList, Instructions.IMUL, Registers.MODR); G.Dump(binaryStream, lineList, new v(), false); I.Dump(binaryStream, lineList, new b()); break;
                //case 0x6C: WriteInstruction(lineList, Instructions.INSB, Registers.MODR); break;   //ToDo: investigate
                //case 0x6D: WriteInstruction(lineList, Instructions.INSW, Registers.MODR); break;   //ToDo: investigate
                //case 0x6E: WriteInstruction(lineList, Instructions.OUTSB, Registers.MODR); break;   //ToDo: investigate
                //case 0x6F: WriteInstruction(lineList, Instructions.OUTSW, Registers.MODR); break;   //ToDo: investigate

                case 0x70: DumpJump(binaryStream, lineList, memoryPositon, Instructions.JO); break;
                case 0x71: DumpJump(binaryStream, lineList, memoryPositon, Instructions.JNO); break;
                case 0x72: DumpJump(binaryStream, lineList, memoryPositon, Instructions.JB); break;
                case 0x73: DumpJump(binaryStream, lineList, memoryPositon, Instructions.JNB); break;
                case 0x74: DumpJump(binaryStream, lineList, memoryPositon, Instructions.JZ); break;
                case 0x75: DumpJump(binaryStream, lineList, memoryPositon, Instructions.JNZ); break;
                case 0x76: DumpJump(binaryStream, lineList, memoryPositon, Instructions.JBE); break;
                case 0x77: DumpJump(binaryStream, lineList, memoryPositon, Instructions.JA); break;
                case 0x78: DumpJump(binaryStream, lineList, memoryPositon, Instructions.JS); break;
                case 0x79: DumpJump(binaryStream, lineList, memoryPositon, Instructions.JNS); break;
                case 0x7A: DumpJump(binaryStream, lineList, memoryPositon, Instructions.JP); break;
                case 0x7B: DumpJump(binaryStream, lineList, memoryPositon, Instructions.JNP); break;
                case 0x7C: DumpJump(binaryStream, lineList, memoryPositon, Instructions.JL); break;
                case 0x7D: DumpJump(binaryStream, lineList, memoryPositon, Instructions.JGE); break;
                case 0x7E: DumpJump(binaryStream, lineList, memoryPositon, Instructions.JLE); break;
                case 0x7F: DumpJump(binaryStream, lineList, memoryPositon, Instructions.JG); break;

                case 0x80: Group1.Dump(binaryStream, lineList, new b()); break;
                case 0x81: Group1.Dump(binaryStream, lineList, new p()); break;
                case 0x82: Group1.Dump(binaryStream, lineList, new b()); break;
                case 0x83: Group1.Dump(binaryStream, lineList, new b()); break;

                case 0x84: WriteInstruction(lineList, Instructions.TEST, Registers.MODR); E.Dump(binaryStream, lineList, new b()); break;
                case 0x85: WriteInstruction(lineList, Instructions.TEST, Registers.MODR); E.Dump(binaryStream, lineList, new v()); break;
                case 0x86: WriteInstruction(lineList, Instructions.XCHG, Registers.MODR); E.Dump(binaryStream, lineList, new b()); break;
                case 0x87: WriteInstruction(lineList, Instructions.XCHG, Registers.MODR); E.Dump(binaryStream, lineList, new v()); break;

                case 0x88: WriteInstruction(lineList, Instructions.MOV, Registers.MODR); E.Dump(binaryStream, lineList, new b()); break;
                case 0x89: WriteInstruction(lineList, Instructions.MOV, Registers.MODR); E.Dump(binaryStream, lineList, new v()); break;
                case 0x8A: WriteInstruction(lineList, Instructions.MOV, Registers.MODR); G.Dump(binaryStream, lineList, new b()); break;
                case 0x8B: WriteInstruction(lineList, Instructions.MOV, Registers.MODR); G.Dump(binaryStream, lineList, new v()); break;
                case 0x8C: WriteInstruction(lineList, Instructions.MOV, Registers.MODR); E.Dump(binaryStream, lineList, new w()); break;
                case 0x8D: WriteInstruction(lineList, Instructions.LEA, Registers.MODR); G.Dump(binaryStream, lineList, new b()); break;
                case 0x8E: WriteInstruction(lineList, Instructions.MOV, Registers.MODR); E.Dump(binaryStream, lineList, new w()); break;
                case 0x8F: WriteInstruction(lineList, Instructions.POP, Registers.MODR); E.Dump(binaryStream, lineList, new v(), false); break;

                case 0x90: WriteInstruction(lineList, Instructions.NOP, Registers.MODR); break;
                case 0x91: WriteInstruction(lineList, Instructions.XCHG, Registers.EAX); WriteRegister(lineList, Registers.ECX); break;
                case 0x92: WriteInstruction(lineList, Instructions.XCHG, Registers.EAX); WriteRegister(lineList, Registers.EDX); break;
                case 0x93: WriteInstruction(lineList, Instructions.XCHG, Registers.EAX); WriteRegister(lineList, Registers.EBX); break;
                case 0x94: WriteInstruction(lineList, Instructions.XCHG, Registers.EAX); WriteRegister(lineList, Registers.ESP); break;
                case 0x95: WriteInstruction(lineList, Instructions.XCHG, Registers.EAX); WriteRegister(lineList, Registers.EBP); break;
                case 0x96: WriteInstruction(lineList, Instructions.XCHG, Registers.EAX); WriteRegister(lineList, Registers.ESI); break;
                case 0x97: WriteInstruction(lineList, Instructions.XCHG, Registers.EAX); WriteRegister(lineList, Registers.EDI); break;
                //case 0x98: break;
                //case 0x99: break;
                case 0x9A: WriteInstruction(lineList, Instructions.CALL, Registers.MODR); I.DumpNoComma(binaryStream, lineList, new p()); break;
                //case 0x9B: break;
                case 0x9C: WriteInstruction(lineList, Instructions.PUSHF, Registers.MODR); break;
                case 0x9D: WriteInstruction(lineList, Instructions.POPF, Registers.MODR); break;
                case 0x9E: WriteInstruction(lineList, Instructions.SAHF, Registers.MODR); break;
                case 0x9F: WriteInstruction(lineList, Instructions.LAHF, Registers.MODR); break;

                case 0xA0: WriteInstruction(lineList, Instructions.MOV, Registers.AL); I.Dump(binaryStream, lineList, new b()); break;
                case 0xA1: WriteInstruction(lineList, Instructions.MOV, Registers.EAX); I.Dump(binaryStream, lineList, new v()); break;
                case 0xA2: lineList.Append("MOV "); I.DumpNoComma(binaryStream, lineList, new v()); lineList.Append(", AL"); break;
                case 0xA3: lineList.Append("MOV "); I.DumpNoComma(binaryStream, lineList, new v()); lineList.Append(", EAX"); break;
                case 0xA4: WriteInstruction(lineList, Instructions.MOVSB, Registers.MODR); break;
                case 0xA5: WriteInstruction(lineList, Instructions.MOVSW, Registers.MODR); break;
                case 0xA6: WriteInstruction(lineList, Instructions.CMPSB, Registers.MODR); break;
                case 0xA7: WriteInstruction(lineList, Instructions.CMPSW, Registers.MODR); break;

                case 0xA8: WriteInstruction(lineList, Instructions.TEST, Registers.AL); I.Dump(binaryStream, lineList, new b()); break;
                case 0xA9: WriteInstruction(lineList, Instructions.TEST, Registers.EAX); I.Dump(binaryStream, lineList, new v()); break;
                case 0xAA: WriteInstruction(lineList, Instructions.STOSB, Registers.MODR); break;
                case 0xAB: WriteInstruction(lineList, Instructions.STOSW, Registers.MODR); break;
                case 0xAC: WriteInstruction(lineList, Instructions.LODSB, Registers.MODR); break;
                case 0xAD: WriteInstruction(lineList, Instructions.LODSW, Registers.MODR); break;
                case 0xAE: WriteInstruction(lineList, Instructions.SCASB, Registers.MODR); break;
                case 0xAF: WriteInstruction(lineList, Instructions.SCASW, Registers.MODR); break;

                case 0xB0: WriteInstruction(lineList, Instructions.MOV, Registers.AL); I.Dump(binaryStream, lineList, new b()); break;
                case 0xB1: WriteInstruction(lineList, Instructions.MOV, Registers.CL); I.Dump(binaryStream, lineList, new b()); break;
                case 0xB2: WriteInstruction(lineList, Instructions.MOV, Registers.DL); I.Dump(binaryStream, lineList, new b()); break;
                case 0xB3: WriteInstruction(lineList, Instructions.MOV, Registers.BL); I.Dump(binaryStream, lineList, new b()); break;
                case 0xB4: WriteInstruction(lineList, Instructions.MOV, Registers.AH); I.Dump(binaryStream, lineList, new b()); break;
                case 0xB5: WriteInstruction(lineList, Instructions.MOV, Registers.CH); I.Dump(binaryStream, lineList, new b()); break;
                case 0xB6: WriteInstruction(lineList, Instructions.MOV, Registers.DH); I.Dump(binaryStream, lineList, new b()); break;
                case 0xB7: WriteInstruction(lineList, Instructions.MOV, Registers.BH); I.Dump(binaryStream, lineList, new b()); break;
                case 0xB8: WriteInstruction(lineList, Instructions.MOV, Registers.EAX); I.Dump(binaryStream, lineList, new v()); break;
                case 0xB9: WriteInstruction(lineList, Instructions.MOV, Registers.ECX); I.Dump(binaryStream, lineList, new v()); break;
                case 0xBA: WriteInstruction(lineList, Instructions.MOV, Registers.EDX); I.Dump(binaryStream, lineList, new v()); break;
                case 0xBB: WriteInstruction(lineList, Instructions.MOV, Registers.EBX); I.Dump(binaryStream, lineList, new v()); break;
                case 0xBC: WriteInstruction(lineList, Instructions.MOV, Registers.ESP); I.Dump(binaryStream, lineList, new v()); break;
                case 0xBD: WriteInstruction(lineList, Instructions.MOV, Registers.EBP); I.Dump(binaryStream, lineList, new v()); break;
                case 0xBE: WriteInstruction(lineList, Instructions.MOV, Registers.ESI); I.Dump(binaryStream, lineList, new v()); break;
                case 0xBF: WriteInstruction(lineList, Instructions.MOV, Registers.EDI); I.Dump(binaryStream, lineList, new v()); break;

                case 0xC0: Group2.Dump(binaryStream, lineList, new b()); break;
                case 0xC1: Group2.Dump(binaryStream, lineList, new v()); break;
                case 0xC2: WriteInstruction(lineList, Instructions.RETN, Registers.MODR); I.DumpNoComma(binaryStream, lineList, new w()); break;
                case 0xC3: WriteInstruction(lineList, Instructions.RETN, Registers.MODR); lineList.AddLine("", (ulong)memoryPositon); lineList.AddLine("", (ulong)memoryPositon); break;
                case 0xC4: WriteInstruction(lineList, Instructions.LES, Registers.MODR); G.Dump(binaryStream, lineList, new v()); break;
                case 0xC5: WriteInstruction(lineList, Instructions.LODSB, Registers.MODR); G.Dump(binaryStream, lineList, new v()); break;
                case 0xC6: WriteInstruction(lineList, Instructions.MOV, Registers.MODR); I.Dump(binaryStream, lineList, new b(), true); break;
                case 0xC7: WriteInstruction(lineList, Instructions.MOV, Registers.MODR); I.Dump(binaryStream, lineList, new p(), true); break;
                case 0xC8: WriteInstruction(lineList, Instructions.ENTER, Registers.MODR); I.DumpNoComma(binaryStream, lineList, new w()); break;
                case 0xC9: WriteInstruction(lineList, Instructions.LEAVE, Registers.MODR); break;
                case 0xCA: WriteInstruction(lineList, Instructions.RETN, Registers.MODR); lineList.Append(" FAR"); I.DumpNoComma(binaryStream, lineList, new w()); break;
                case 0xCB: WriteInstruction(lineList, Instructions.RETN, Registers.MODR); lineList.Append(" FAR"); break;
                case 0xCC: WriteInstruction(lineList, Instructions.INT3, Registers.MODR); break;
                case 0xCD: WriteInstruction(lineList, Instructions.INT, Registers.MODR); I.DumpNoComma(binaryStream, lineList, new b()); break;
                case 0xCE: WriteInstruction(lineList, Instructions.INTO, Registers.MODR); break;
                case 0xCF: WriteInstruction(lineList, Instructions.IRET, Registers.MODR); break;

                case 0xD0: Group2.Dump(binaryStream, lineList, new b()); break;
                case 0xD1: Group2.Dump(binaryStream, lineList, new v()); break;
                case 0xD2: Group2.DumpCL(binaryStream, lineList, new b()); break;
                case 0xD3: Group2.DumpCL(binaryStream, lineList, new b()); break;
                case 0xD4: WriteInstruction(lineList, Instructions.AAM, Registers.MODR); break;
                case 0xD5: WriteInstruction(lineList, Instructions.AAD, Registers.MODR); break;
                case 0xD6: WriteInstruction(lineList, Instructions.SALC, Registers.MODR); break;
                case 0xD7: WriteInstruction(lineList, Instructions.XALC, Registers.MODR); break;

                case 0xD8: WriteInstruction(lineList, Instructions.ESC, Registers.MODR); lineList.Append("0"); break;
                case 0xD9: WriteInstruction(lineList, Instructions.ESC, Registers.MODR); lineList.Append("1"); break;
                case 0xDA: WriteInstruction(lineList, Instructions.ESC, Registers.MODR); lineList.Append("2"); break;
                case 0xDB: WriteInstruction(lineList, Instructions.ESC, Registers.MODR); lineList.Append("3"); break;
                case 0xDC: WriteInstruction(lineList, Instructions.ESC, Registers.MODR); lineList.Append("4"); break;
                case 0xDD: WriteInstruction(lineList, Instructions.ESC, Registers.MODR); lineList.Append("5"); break;
                case 0xDE: WriteInstruction(lineList, Instructions.ESC, Registers.MODR); lineList.Append("6"); break;
                case 0xDF: WriteInstruction(lineList, Instructions.ESC, Registers.MODR); lineList.Append("7"); break;

                case 0xE0: WriteInstruction(lineList, Instructions.LOOPNZ, Registers.MODR); J.Dump(binaryStream, lineList, memoryPositon); break;
                case 0xE1: WriteInstruction(lineList, Instructions.LOOPZ, Registers.MODR); J.Dump(binaryStream, lineList, memoryPositon); break;
                case 0xE2: WriteInstruction(lineList, Instructions.LOOP, Registers.MODR); J.Dump(binaryStream, lineList, memoryPositon); break;
                case 0xE3: WriteInstruction(lineList, Instructions.JCXZ, Registers.MODR); J.Dump(binaryStream, lineList, memoryPositon); break;
                case 0xE4: WriteInstruction(lineList, Instructions.IN, Registers.AL); I.Dump(binaryStream, lineList, new b()); break;
                case 0xE5: WriteInstruction(lineList, Instructions.IN, Registers.EAX); I.Dump(binaryStream, lineList, new b()); break;
                case 0xE6: lineList.Append("OUT "); I.DumpNoComma(binaryStream, lineList, new b()); WriteRegister(lineList, Registers.AL); break;
                case 0xE7: lineList.Append("OUT "); I.DumpNoComma(binaryStream, lineList, new b()); WriteRegister(lineList, Registers.EAX); break;
                case 0xE8: DumpCall(binaryStream, lineList, memoryPositon); break;
                case 0xE9: DumpJump(binaryStream, lineList, memoryPositon); break;
                case 0xEA: WriteInstruction(lineList, Instructions.JMP, Registers.MODR); A.Dump(binaryStream, lineList, new p()); break;
                case 0xEB: WriteInstruction(lineList, Instructions.JMP, Registers.MODR); J.Dump(binaryStream, lineList, memoryPositon); break;
                case 0xEC: WriteInstruction(lineList, Instructions.IN, Registers.AL); WriteRegister(lineList, Registers.DX); break;
                case 0xED: WriteInstruction(lineList, Instructions.IN, Registers.EAX); WriteRegister(lineList, Registers.DX); break;
                case 0xEE: lineList.Append("OUT "); WriteRegister(lineList, Registers.DX, false); WriteRegister(lineList, Registers.AL); break;
                case 0xEF: lineList.Append("OUT "); WriteRegister(lineList, Registers.DX, false); WriteRegister(lineList, Registers.EAX); break;

                //case 0xF0: break;
                case 0xF1: WriteInstruction(lineList, Instructions.INT1, Registers.MODR); break;
                //case 0xF2: break;
                case 0xF3: WriteInstruction(lineList, Instructions.REP, Registers.MODR); R.Dump(binaryStream, lineList); break;
                case 0xF4: WriteInstruction(lineList, Instructions.HLT, Registers.MODR); break;
                case 0xF5: WriteInstruction(lineList, Instructions.CMD, Registers.MODR); break;
                case 0xF6: Group3.Dump(binaryStream, lineList, new b()); break;
                case 0xF7: Group3.Dump(binaryStream, lineList, new v()); break;
                case 0xF8: WriteInstruction(lineList, Instructions.CLC, Registers.MODR); break;
                case 0xF9: WriteInstruction(lineList, Instructions.STC, Registers.MODR); break;
                case 0xFA: WriteInstruction(lineList, Instructions.CLI, Registers.MODR); break;
                case 0xFB: WriteInstruction(lineList, Instructions.STI, Registers.MODR); break;
                case 0xFC: WriteInstruction(lineList, Instructions.CLD, Registers.MODR); break;
                case 0xFD: WriteInstruction(lineList, Instructions.STD, Registers.MODR); break;
                case 0xFE: Group4.Dump(binaryStream, lineList, new b()); break;
                case 0xFF: Group5.Dump(binaryStream, lineList, new v()); break;
                default:
                    lineList.Append(string.Format(" {0:X2}", mnemonic));
                    break;
            }
        }

        private void DumpTwoByte(Stream binaryStream, LineList lineList, int mnemonic, ulong memoryPositon, Prefixes prefix = Prefixes.None)
        {
            switch (mnemonic)
            {
                case 0x84: DumpJump(binaryStream, lineList, memoryPositon, Instructions.JZ); break;
                case 0x85: DumpJump(binaryStream, lineList, memoryPositon, Instructions.JNZ); break;
                case 0x86: DumpJump(binaryStream, lineList, memoryPositon, Instructions.JBE); break;
                case 0x8C: DumpJump(binaryStream, lineList, memoryPositon, Instructions.JL); break;
                case 0xB6: WriteInstruction(lineList, Instructions.MOVZX, Registers.MODR); G.Dump(binaryStream, lineList, new v()); break;
                case 0x94: WriteInstruction(lineList, Instructions.SETZ, Registers.MODR); E.Dump(binaryStream, lineList, new b(), false); break;
            }
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Treats the section as code
        /// </summary>
        private void dumpCode(ref Section section, Stream binaryStream, SectionHeader sectionHeader, ulong imageBase)
        {
            ulong position = 0;
            ulong sectionStart = imageBase + sectionHeader.VirtualAddress;
            ulong sectionEnd = sectionStart + sectionHeader.SizeOfRawData;

            LineList lineList = section.Lines;

            while (position < sectionEnd)
            {
                position = sectionStart + (ulong)binaryStream.Position - sectionHeader.PointerToRawData;

                int cmd = binaryStream.ReadByte();

                if (isPadding(cmd))
                {
                    updatePaddingInfo(cmd);
                    continue;
                }

                if (paddingInfo.HasPadding())
                    dumpPadding(ref section, position);

                lineList.AddLine(string.Format("{0:X8}{1}:\t", position, section.Name), position);
                dumpMnemonic(cmd, position, binaryStream, lineList);
                //lineList.AddLine("", position);
            }
        }

        private void updatePaddingInfo(int mnemonic)
        {
            if (mnemonic == paddingInfo.Mnemonic)
                ++paddingInfo.Count;
            else
            {
                paddingInfo.Mnemonic = mnemonic;
                paddingInfo.Count = 1;
            }
        }

        private void dumpPadding(ref Section section, ulong position)
        {
            var line = string.Format("DB {0:X}h DUP({1:X})\r\n", paddingInfo.Count, paddingInfo.Mnemonic);
            section.Lines.AddLine(line, position);
            paddingInfo.Mnemonic = paddingInfo.Count = 0;
        }

        /// <summary>
        /// Returns if the given mnemonic is used for padding
        /// </summary>
        private bool isPadding(int mnemonic)
        {
            return mnemonic == 0xCC;
        }

        /// <summary>
        /// Treats the section as data
        /// </summary>
        private void dumpData(ref Section section, Stream binaryStream, SectionHeader sectionHeader, ulong imageBase)
        {
        }
        #endregion
    }
}
