using Decompiler.Files;
using System.IO;

namespace Decompiler.Disassembler
{
    /// <summary>
    /// A common interface for all kinds of disassebmlers
    /// </summary>
    public interface IDisassembler
    {
        /// <summary>
        /// Disassembles the given section of the given binary stream with the given image base address
        /// </summary>
        /// <param name="binaryStream">The stream to read from</param>
        /// <param name="sectionHeader">The section's header</param>
        /// <param name="imageBase">The image's base address</param>
        /// <returns>The disassembled section</returns>
        Section DisassembleSection(Stream binaryStream, SectionHeader sectionHeader, ulong imageBase);
    }

    /// <summary>
    /// Contains information about a disassembled section
    /// </summary>
    public class Section
    {
        /// <summary>
        /// The section's header
        /// </summary>
        public SectionHeader Header { get; set; }

        /// <summary>
        /// The section's name
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// The section's starting address
        /// </summary>
        public ulong Address { get; set; } = 0;

        /// <summary>
        /// The disassembled lines
        /// </summary>
        public LineList Lines { get; set; } = new LineList();
    }
}
