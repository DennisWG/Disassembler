using System;
using System.IO;
using System.Collections.Specialized;

namespace Decompiler.Disassembler.x86AAC
{
    public struct ModRM
    {
        public ushort Mod { get; set; }
        public ushort RM { get; set; }
        public ushort Value { get; set; }
        public ushort RMValue { get; set; }
    }

    public enum ArgumentOperandCodes
    {
        Zero, //Byte argument. Unusual in that arguments of this type are suppressed in ASM output when they have the default value of 10 (0xA). Applicable, e.g., to AAM and AAD.
        b, //Byte argument.
        p, //32-bit segment:offset pointer.
        w, //Word argument.
        v //Word argument. (The 'v' code has a more complex meaning in later x86 opcode maps, from which this was derived, but here it's just a synonym for the 'w' code.)
    }

    public interface IArgumentOperandCode
    {
        string GetText(Stream inFile);
        ModRM GetModRM(Stream inFile);
    }

    public class Zero : IArgumentOperandCode {
        public string GetText(Stream inFile)
        {
            int b = 0;
            b = inFile.ReadByte();
            return string.Format("{0:X}h", b);
        }
        public ModRM GetModRM(Stream inFile)
        {
            ModRM rm = new ModRM();
            BitVector32 bv = new BitVector32(inFile.ReadByte());
            BitVector32.Section modS = BitVector32.CreateSection(2);
            BitVector32.Section rmValueS = BitVector32.CreateSection(6);
            BitVector32.Section rmS = BitVector32.CreateSection(3, modS);
            BitVector32.Section valS = BitVector32.CreateSection(3, rmS);
            rm.Mod = (byte)bv[modS];
            rm.RM = (ushort)bv[modS];
            rm.Value = (ushort)bv[valS];
            rm.RMValue = (ushort)bv[rmValueS];
            return rm;
        }
    }

    public class b : IArgumentOperandCode {
        public string GetText(Stream inFile)
        {
            int b = 0;
            b = inFile.ReadByte();
            return string.Format("{0:X}h", b);
        }
        public ModRM GetModRM(Stream inFile)
        {
            ModRM rm = new ModRM();

            BitVector32 bv = new BitVector32(inFile.ReadByte());
            BitVector32.Section valS = BitVector32.CreateSection(7);
            BitVector32.Section rmValueS = BitVector32.CreateSection(6);
            BitVector32.Section rmS = BitVector32.CreateSection(7, valS);
            BitVector32.Section modS = BitVector32.CreateSection(3, rmS);
            rm.Mod = (ushort)bv[modS];
            rm.RM = (ushort)bv[rmS];
            rm.Value = (ushort)bv[valS];
            rm.RMValue = (ushort)bv[rmValueS];
            return rm;
        }
    }

    public class p : IArgumentOperandCode {
        public string GetText(Stream inFile)
        {
            byte[] b = new byte[4];
            inFile.Read(b, 0, 4);
            return string.Format("{0:X}h", BitConverter.ToInt32(b, 0));
        }
        public ModRM GetModRM(Stream inFile)
        {
            ModRM rm = new ModRM();

            BitVector32 bv = new BitVector32(inFile.ReadByte());
            BitVector32.Section valS = BitVector32.CreateSection(7);
            BitVector32.Section rmValueS = BitVector32.CreateSection(6);
            BitVector32.Section rmS = BitVector32.CreateSection(7, valS);
            BitVector32.Section modS = BitVector32.CreateSection(3, rmS);
            rm.Mod = (ushort)bv[modS];
            rm.RM = (ushort)bv[rmS];
            rm.Value = (ushort)bv[valS];
            rm.RMValue = (ushort)bv[rmValueS];
            return rm;
        }
    }

    public class w : IArgumentOperandCode {
        public string GetText(Stream inFile)
        {
            byte[] b = new byte[2];
            inFile.Read(b, 0, 2);
            return string.Format("{0:X}h", BitConverter.ToInt16(b, 0));
        }
        public ModRM GetModRM(Stream inFile) { return new ModRM(); }
    }

    public class v : IArgumentOperandCode {
        public string GetText(Stream inFile)
        {
            byte[] b = new byte[4];
            inFile.Read(b, 0, 4);
            return string.Format("{0:X}h", BitConverter.ToInt32(b, 0));
        }
        public ModRM GetModRM(Stream inFile)
        {
            ModRM rm = new ModRM();

            BitVector32 bv = new BitVector32(inFile.ReadByte());
            BitVector32.Section valS = BitVector32.CreateSection(7);
            BitVector32.Section rmValueS = BitVector32.CreateSection(6);
            BitVector32.Section rmS = BitVector32.CreateSection(7, valS);
            BitVector32.Section modS = BitVector32.CreateSection(3, rmS);
            rm.Mod = (ushort)bv[modS];
            rm.RM = (ushort)bv[rmS];
            rm.Value = (ushort)bv[valS];
            rm.RMValue = (ushort)bv[rmValueS];
            return rm;
        }
    }

    public class IArgumentAddressingCode
    {
        static void Dump(Stream inFile, LineList outList, IArgumentOperandCode op) { }
        static protected int Read(Stream inFile, int numBytes)
        {
            byte[] b = new byte[numBytes];
            inFile.Read(b, 0, numBytes);
            if (numBytes == 1)
                return b[0];
            else if (numBytes == 4)
                return BitConverter.ToInt32(b, 0);
            else
                return 0;
        }

        static protected void WriteReg(LineList outList, Registers r, bool brackets = false, bool komma = false)
        {
            outList.Append(" ");
            if (brackets) outList.Append("[");
            outList.Append(r.ToString());
            if (brackets) outList.Append("]");
            if (komma) outList.Append(",");
            else
                outList.Append(" ");
        }

        static protected void WriteDisplacementReg(LineList outList, Registers r, string disp, bool komma = false)
        {
            if (disp[0] != '+' && disp[0] != '-')
            {
                if (Convert.ToInt32(disp) > 0)
                    disp = string.Format("+{0}", disp);
                else
                    disp = string.Format("-{0}", disp);
            }
            outList.Append(string.Format(" [{0}{1}h]", r.ToString(), disp));
            if (komma) outList.Append(",");
            else
                outList.Append(" ");
        }

        static protected void DumpSIB(Stream inFile, LineList outList, IArgumentOperandCode op)
        {
            ModRM sib = op.GetModRM(inFile);
            string functor = "";
            
            if(sib.Mod == 1)
                functor = "*2";
            else if(sib.Mod == 1)
                functor = "*4";
            else if(sib.Mod == 1)
                functor = "*8";

                outList.Append(string.Format("[{0}{1}+", (Registers)sib.Value, functor));
                outList.Append(string.Format("{0}]", (Registers)sib.RM));
        }

        static protected string GetDisplacement(Stream inFile, int numBytes)
        {
            int disp = 0;
            if (numBytes == 1)
            {
                sbyte _disp = (sbyte)Read(inFile, numBytes);
                disp = _disp;
            }
            else
                disp = Read(inFile, numBytes);
            return ToHex(disp);
        }

        static protected string ToHex(int disp)
        {
            string ret = "";
            if (disp < 0)
                ret = string.Format("-{0:X}", (uint)disp);
            else
                ret = string.Format("+{0:X}", disp);

            return ret;
        }
    }

    /// <summary>
    /// Direct address. The instruction has no ModR/M byte;
    /// the address of the operand is encoded in the instruction.
    /// Applicable, e.g., to far JMP (opcode EA).
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class A : IArgumentAddressingCode
    {
        public static void Dump(Stream inFile, LineList outList, IArgumentOperandCode op)
        {
            string pos = op.GetText(inFile);
            outList.Append(" " + pos);
        }
    }

    public class E: IArgumentAddressingCode
    {
        public static void Dump(Stream inFile, LineList outList, IArgumentOperandCode op, bool twoRegisters = true)
        {
            ModRM modRM = op.GetModRM(inFile);

            string disp = "0";
            if (modRM.Mod == 1)
            {
                disp = GetDisplacement(inFile, 1);
                //sbyte b = new BinaryReader(inFile).ReadSByte();
                WriteDisplacementReg(outList, (Registers)modRM.Value, disp, twoRegisters);
            }
            else if (modRM.Mod == 2)
            {
                disp = GetDisplacement(inFile, 4);
                WriteDisplacementReg(outList, (Registers)modRM.Value, disp.ToString(), twoRegisters);
            }
            else if (modRM.Mod == 3)
                WriteReg(outList, (Registers)modRM.Value, false, twoRegisters);
            else
            {
                if (modRM.Value == 5)
                {
                    byte[] buffer = new byte[4];
                    inFile.Read(buffer, 0, 4);
                    int i = BitConverter.ToInt32(buffer, 0);
                    outList.Append(", " + i);
                    //outList.Append(op.GetText(inFile));
                }
                else
                    WriteReg(outList, (Registers)modRM.Value, true, twoRegisters);
            }

            if(twoRegisters)
                WriteReg(outList, (Registers)modRM.RM, false, false);
        }
    }

    public class G : IArgumentAddressingCode
    {
        public static void Dump(Stream inFile, LineList outList, IArgumentOperandCode op, bool twoRegisters = true)
        {
            ModRM modRM = op.GetModRM(inFile);

            WriteReg(outList, (Registers)modRM.RM, false, true);

            if (twoRegisters == false)
                return;

            string disp = "0";
            if (modRM.Mod == 1)
            {
                disp = GetDisplacement(inFile, 1);
            }
            else if (modRM.Mod == 2)
                disp = GetDisplacement(inFile, 4);

            if (disp == "0")
            {
                if (modRM.Mod == 3)
                {
                    WriteReg(outList, (Registers)modRM.RMValue);
                }
                else
                {
                    switch (modRM.Value)
                    {
                        case 0: outList.Append(string.Format("[EAX]")); break;
                        case 1: outList.Append(string.Format("[ECX]")); break;
                        case 2: outList.Append(string.Format("[EDX]")); break;
                        case 3: outList.Append(string.Format("[EBX]")); break;
                        case 4: 
                            if (modRM.Mod == 0)
                            { 
                                ModRM sib = op.GetModRM(inFile);
                            }
                            else { throw new NotImplementedException(); } break;
                        case 5:
                            if (modRM.Mod != 0) outList.Append(string.Format("[EBP]"));
                            else outList.Append(new p().GetText(inFile));
                            break;
                        case 6: outList.Append(string.Format("[ESI]")); break;
                        case 7: outList.Append(string.Format("[EDI]")); break;
                    }
                }
            }
            else
            {
                WriteDisplacementReg(outList, (Registers)modRM.Value, disp);
            }
        }
    }

    public class I : IArgumentAddressingCode
    {
        public static void Dump(Stream inFile, LineList outList, IArgumentOperandCode op)
        {
            string opt = op.GetText(inFile);
            outList.Append(", " + opt);
        }

        public static void DumpNoComma(Stream inFile, LineList outList, IArgumentOperandCode op)
        {
            string opt = op.GetText(inFile);
            outList.Append(" " + opt);
        }

        public static void Dump(Stream inFile, LineList outList, IArgumentOperandCode op, bool modRMPresent)
        {
            ModRM modRM = new ModRM();
            if (modRMPresent)
            {
                modRM = op.GetModRM(inFile);
                if (modRM.Mod == 1)
                    WriteDisplacementReg(outList, (Registers)modRM.Value, GetDisplacement(inFile, 1), true);
                else if (modRM.Mod == 2)
                    WriteDisplacementReg(outList, (Registers)modRM.Value, GetDisplacement(inFile, 4), true);
                else if (modRM.Mod == 3)
                    WriteReg(outList, (Registers)modRM.Value, false, true);
                else
                {
                    if (modRM.Value == 5)
                    {
                        byte[] buffer = new byte[4];
                        inFile.Read(buffer, 0, 4);

                        string line = string.Format(" byte_{0:X}, ", BitConverter.ToInt32(buffer, 0));

                        outList.Append(line);
                        outList.Append(op.GetText(inFile));
                        return;
                    }
                    else
                        WriteReg(outList, (Registers)modRM.Value, true, true);
                }

                outList.Append(op.GetText(inFile));
            }
            else
                outList.Append(" " + op.GetText(inFile));
        }
    }

    public class J : IArgumentAddressingCode
    {

        public static void Dump(Stream inFile, LineList outList, ulong memoryPosition)
        {
            byte[] b = new byte[1];
            inFile.Read(b, 0, 1);
            outList.Append(string.Format(" {0:X}h", (memoryPosition + b[0] + 2)));
            string.Format("", (memoryPosition + b[0] + 2));
        }
    }

    public class R : IArgumentAddressingCode
    {
        public static void Dump(Stream inFile, LineList outList)
        {
            int b = inFile.ReadByte();
            if (b == 0xAB) outList.Append(" STOSD");
            else outList.Append(string.Format("UNK: {0:X}h", b));
        }
    }

    public class Group1 : IArgumentAddressingCode
    {
        public static void Dump(Stream inFile, LineList outList, IArgumentOperandCode op)
        {
            ModRM modRM = op.GetModRM(inFile);

            switch (modRM.RM)
            {
                case 0: outList.Append("ADD"); break;
                case 1: outList.Append("OR"); break;
                case 2: outList.Append("ADC"); break;
                case 3: outList.Append("SBB"); break;
                case 4: outList.Append("AND"); break;
                case 5: outList.Append("SUB"); break;
                case 6: outList.Append("XOR"); break;
                case 7: outList.Append("CMP"); break;
            }

            string disp = "0";
            if (modRM.Mod == 1)
            {
                disp = GetDisplacement(inFile, 1);
                WriteDisplacementReg(outList, (Registers)modRM.Value, disp.ToString(), true);
            }
            else if (modRM.Mod == 2)
            {
                disp = GetDisplacement(inFile, 4);
                WriteDisplacementReg(outList, (Registers)modRM.Value, disp.ToString(), true);
            }
            else if (modRM.Mod == 3)
                WriteReg(outList, (Registers)modRM.Value, false, true);
            else
            {
                if (modRM.Value == 5)
                {
                    byte[] buffer = new byte[4];
                    inFile.Read(buffer, 0, 4);

                    string line = string.Format("byte_{0:X}, ", BitConverter.ToInt32(buffer, 0));

                    outList.Append(line);
                    outList.Append(op.GetText(inFile));
                    return;
                }
                else
                    WriteReg(outList, (Registers)modRM.Value, true, true);
            }

            //WriteReg(outList, (Registers)modRM.Value, false, true);

            outList.Append(op.GetText(inFile));
        }
    }

    public class Group3 : IArgumentAddressingCode
    {
        public static void Dump(Stream inFile, LineList outList, IArgumentOperandCode op)
        {
        }
    }

    public class Group2 : IArgumentAddressingCode
    {
        public static void Dump(Stream inFile, LineList outList, IArgumentOperandCode op)
        {
            ModRM modRM = op.GetModRM(inFile);

            switch (modRM.RM)
            {
                case 0: outList.Append("ROL "); break;
                case 1: outList.Append("ROR "); break;
                case 2: outList.Append("RCL "); break;
                case 3: outList.Append("RCR "); break;
                case 4: outList.Append("SHL "); break;
                case 5: outList.Append("SHR "); break;
                case 6: outList.Append("UNK_Group2_6 "); break;
                case 7: outList.Append("SAR "); break;
            }

            WriteReg(outList, (Registers)modRM.Value, false, true);

            outList.Append("1");
        }

        public static void DumpCL(Stream inFile, LineList outList, IArgumentOperandCode op)
        {
            ModRM modRM = op.GetModRM(inFile);

            switch (modRM.RM)
            {
                case 0: outList.Append("ROL "); break;
                case 1: outList.Append("ROR "); break;
                case 2: outList.Append("RCL "); break;
                case 3: outList.Append("RCR "); break;
                case 4: outList.Append("SHL "); break;
                case 5: outList.Append("SHR "); break;
                case 6: outList.Append("UNK_Group2_6 "); break;
                case 7: outList.Append("SAR "); break;
            }

            WriteReg(outList, (Registers)modRM.Value, false, true);

            outList.Append("CL");
        }
    }

    public class Group4 : IArgumentAddressingCode
    {
        public static void Dump(Stream inFile, LineList outList, IArgumentOperandCode op)
        {
            ModRM modRM = op.GetModRM(inFile);

            switch (modRM.RM)
            {
                case 0: outList.Append("INC "); break;
                case 1: outList.Append("DEC "); break;
                case 2: outList.Append("UNK_Group4_2 "); break;
                case 3: outList.Append("UNK_Group4_3 "); break;
                case 4: outList.Append("UNK_Group4_4 "); break;
                case 5: outList.Append("UNK_Group4_5 "); break;
                case 6: outList.Append("UNK_Group4_6 "); break;
                case 7: outList.Append("UNK_Group4_7 "); break;
            }

            outList.Append(op.GetText(inFile));
        }
    }

    public class Group5 : IArgumentAddressingCode
    {
        public static void Dump(Stream inFile, LineList outList, IArgumentOperandCode op)
        {
            ModRM modRM = op.GetModRM(inFile);

            switch (modRM.RM)
            {
                case 0: outList.Append("INC "); break;
                case 1: outList.Append("DEC "); break;
                case 2: outList.Append("CALL "); break;
                case 3: outList.Append("CALL "); break;
                case 4: outList.Append("JMP "); break;
                case 5: outList.Append("JMP "); break;
                case 6: outList.Append("PUSH "); break;
                case 7: outList.Append("UNK_Group5_7 "); break;
            }

            outList.Append(op.GetText(inFile));
        }
    }
}
