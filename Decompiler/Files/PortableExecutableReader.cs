using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Collections.Generic;

namespace Decompiler.Files
{
    /// <summary>
    /// Provides functionality for reading Portable Executables
    /// </summary>
    public class PortableExecutableReader
    {
        /// <summary>
        /// Reads a Portable Executable from the given filePath
        /// </summary>
        /// <param name="filePath">The filePath to the Portable Executable</param>
        /// <returns>The read PortableExecutable</returns>
        public static PortableExecutable ReadFile(string filePath)
        {
            var pe = new PortableExecutable();
            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                ReadDosAndPEHeader(stream, pe);
                pe.SectionHeader = new List<SectionHeader>(pe.FileHeader.NumberOfSection);
                ReadSectionHeader(stream, pe);
                stream.Close();
            }

            return pe;
        }

        #region private methods

        private static void ReadDosAndPEHeader(FileStream stream, PortableExecutable pe)
        {
            BinaryReader reader = new BinaryReader(stream);
            pe.DosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

            stream.Seek(pe.DosHeader.lfanew, SeekOrigin.Begin);

            uint ntHeaderSignature = reader.ReadUInt32();
            if (ntHeaderSignature != 0x00004550)
                throw new Exception("Selected file is not a portable executable!");

            pe.FileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
            if (pe.FileHeader.Characteristic.HasFlag(Characteristics.Machine32Bit))
                pe.OptionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
            else
                pe.OptionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
        }

        private static void ReadSectionHeader(FileStream stream, PortableExecutable pe)
        {
            BinaryReader reader = new BinaryReader(stream);

            for (int i = 0; i < pe.FileHeader.NumberOfSection; ++i)
            {
                SectionHeader header = new SectionHeader();
                header.Name = reader.ReadChars(8);
                header.VirtualSize = reader.ReadUInt32();
                header.VirtualAddress = reader.ReadUInt32();
                header.SizeOfRawData = reader.ReadUInt32();
                header.PointerToRawData = reader.ReadUInt32();
                header.PointerToRelocations = reader.ReadUInt32();
                header.PointerToLinenumbers = reader.ReadUInt32();
                header.NumberOfRelocations = reader.ReadUInt16();
                header.NumberOfLinenumbers = reader.ReadUInt16();
                header.Characteristics = (SectionCharacteristics)reader.ReadUInt32();
                pe.SectionHeader.Add(header);
            }
        }

        private static T FromBinaryReader<T>(BinaryReader reader)
        {
            byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return theStructure;
        }

        #endregion private methods
    }
}