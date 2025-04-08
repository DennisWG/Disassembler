using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Decompiler.Files
{
    public struct IMAGE_DOS_HEADER
    {
        public ushort magic;
        public ushort cblp;
        public ushort cp;
        public ushort crlc;
        public ushort cparhdr;
        public ushort minalloc;
        public ushort maxalloc;
        public ushort ss;
        public ushort sp;
        public ushort csum;
        public ushort ip;
        public ushort cs;
        public ushort lfarlc;
        public ushort ovno;
        public ushort res0;
        public ushort res1;
        public ushort res2;
        public ushort res3;
        public ushort oemid;
        public ushort oeminfo;
        public ushort res2_0;
        public ushort res2_1;
        public ushort res2_2;
        public ushort res2_3;
        public ushort res2_4;
        public ushort res2_5;
        public ushort res2_6;
        public ushort res2_7;
        public ushort res2_8;
        public ushort res2_9;
        public uint lfanew;
    }

    #region PE_Header
    public enum MachineTypes : ushort
    {
        Unknown = 0x0,
        AM33 = 0x1D3,
        AMD64 = 0x8664,
        ARM = 0x1C0,
        ARMV7 = 0x1C4,
        EBC = 0xEBC,
        I386 = 0x14C,
        IA64 = 0x200,
        M32R = 0x9041,
        MIPS16 = 0x266,
        MIPSFPU = 0x366,
        MIPSFPU16 = 0x466,
        POWERPC = 0x1F0,
        POWERPCFP = 0x1F1,
        R4000 = 0x166,
        SH3 = 0x1A2,
        SH3DSP = 0x1A3,
        SH4 = 0x1A6,
        SH5 = 0x1A8,
        THUMB = 0x1C2,
        WCEMIPSV2 = 0x169
    }

    [Flags]
    public enum Characteristics : ushort
    {
        RelocsStripped = 0x1,
        ExecutableImage = 0x2,
        LineNumsStripped = 0x4,
        LocalSymsStripped = 0x8,
        AggressiveWsTrim = 0x10,
        LargeAddressAware = 0x20,
        Reserved = 0x40,
        BytesReversedLo = 0x80,
        Machine32Bit = 0x100,
        DebugStripped = 0x200,
        RemovableRunFromSwap = 0x400,
        NetRunFromSwap = 0x800,
        System = 0x1000,
        Dll = 0x2000,
        UpSystemOnly = 0x4000,
        BytesReversedHi = 0x8000,
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_FILE_HEADER
    {
        public MachineTypes Machine;
        public ushort NumberOfSection;
        public uint TimeDataStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public Characteristics Characteristic;
    }
    #endregion PE_Header

    #region Optional Header
    public enum ImageStates : ushort
    {
        Executable = 0x10B,
        ROM = 0x107,
        PE32Plus = 0x20B,
    }

    public enum WindowsSubsystem : ushort
    {
        Unknown = 0,
        Native = 1,
        WindowsGUI = 2,
        WindowsCUI = 3,
        POSIXCUI = 7,
        WindowsCEGUI = 9,
        EFIApplication = 10,
        EFIBootServiceDriver = 11,
        EFIRuntimeDriver = 12,
        EFIROM = 13,
        XBOX = 14
    }

    [Flags]
    public enum DLLCharacteristics : ushort
    {
        Reserved1 = 0x1,
        Reserved2 = 0x2,
        Reserved3 = 0x4,
        Reserved4 = 0x8,
        DynamicBase = 0x40,
        ForceIntegrity = 0x80,
        NXCompatible = 0x100,
        NoIsolation = 0x200,
        NoSEHandler = 0x400,
        NoBind = 0x800,
        Reserved5 = 0x1000,
        WDMDriver = 0x2000,
        TerminalServerAware = 0x8000
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER32
    {
        public ImageStates ImageState;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public uint BaseOfData;
        public uint ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public WindowsSubsystem MajorOperatingSystemVersion;
        public WindowsSubsystem MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public DLLCharacteristics DllCharacteristics;
        public uint SizeOfStackReserve;
        public uint SizeOfStackCommit;
        public uint SizeOfHeapReserve;
        public uint SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        public ulong ExportTable;
        public ulong ImportTable;
        public ulong ResourceTable;
        public ulong ExceptionTable;
        public ulong CertificateTable;
        public ulong BaseRelocationTable;
        public ulong Debug;
        public ulong Architecture;
        public ulong GlobalPtr;
        public ulong TLSTable;
        public ulong LoadConfigTable;
        public ulong BoundImport;
        public ulong ImportAddressTable;
        public ulong DelayImportDescriptor;
        public ulong CLRHeader;
        public ulong Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        public ImageStates ImageState;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public WindowsSubsystem MajorOperatingSystemVersion;
        public WindowsSubsystem MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public DLLCharacteristics DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        public ulong ExportTable;
        public ulong ImportTable;
        public ulong ResourceTable;
        public ulong ExceptionTable;
        public ulong CertificateTable;
        public ulong BaseRelocationTable;
        public ulong Debug;
        public ulong Architecture;
        public ulong GlobalPtr;
        public ulong TLSTable;
        public ulong LoadConfigTable;
        public ulong BoundImport;
        public ulong ImportAddressTable;
        public ulong DelayImportDescriptor;
        public ulong CLRHeader;
        public ulong Reserved;
    }

    #endregion Optional Header

    #region Section Header

    [Flags]
    public enum SectionCharacteristics : uint
    {
        Reserved1 = 0x0,
        Reserved2 = 0x1,
        Reserved3 = 0x2,
        Reserved4 = 0x4,
        NoPadding = 0x8,
        Reserved5 = 0x10,
        Code = 0x20,
        InitializedData = 0x40,
        UninitializedData = 0x80,
        LinkOther = 0x100,
        LinkInfo = 0x200,
        Reserved6 = 0x400,
        LinkRemove = 0x800,
        LinkComdat = 0x1000,
        GPREL = 0x8000,
        Purgeable = 0x20000,
        Mem16Bit = 0x20000,
        MemLocked = 0x40000,
        MemPreload = 0x80000,
        Align1Bytes = 0x100000,
        Align2Bytes = 0x200000,
        Align4Bytes = 0x300000,
        Align8Bytes = 0x400000,
        Align16Bytes = 0x500000,
        Align128Bytes = 0x800000,
        Align256Bytes = 0x900000,
        Align512Bytes = 0xA00000,
        Align1024Bytes = 0xB00000,
        Align2048Bytes = 0xC00000,
        Align4096Bytes = 0xd00000,
        Align8192Bytes = 0xE00000,
        LinkNRelocOVFL = 0x1000000,
        MemDiscardable = 0x2000000,
        MemNotCached = 0x4000000,
        MemNotPaged = 0x8000000,
        MemNotShared = 0x10000000,
        MemExecute = 0x20000000,
        MemRead = 0x40000000,
        MemWrite = 0x80000000
    }

    public struct SectionHeader
    {
        public char[] Name;
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public SectionCharacteristics Characteristics;
    }

    #endregion

    /// <summary>
    /// Describes a Portable Executable as found on the Windows operating systems
    /// </summary>
    public class PortableExecutable
    {
        public DateTime TimeStamp
        {
            get
            {
                DateTime returnValue = new DateTime(1970, 1, 1, 0, 0, 0);
                returnValue = returnValue.AddSeconds(FileHeader.TimeDataStamp);
                returnValue += TimeZone.CurrentTimeZone.GetUtcOffset(returnValue);
                return returnValue;
            }
        }

        public IMAGE_DOS_HEADER DosHeader { get; set; }
        public IMAGE_FILE_HEADER FileHeader { get; set; }
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader32 { get; set; }
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader64 { get; set; }
        public List<SectionHeader> SectionHeader { get; set; }
    }
}
