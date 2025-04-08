using Decompiler.Files;
using System;
using System.IO;
using System.Windows.Forms;

namespace Decompiler
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        public void AddASMLine(string line)
        {
            richTextBox1.AppendText(line);
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                var pe = PortableExecutableReader.ReadFile(openFileDialog1.FileName);

                if (pe.FileHeader.Machine == MachineTypes.I386)
                {
                    var stream = File.Open(openFileDialog1.FileName, FileMode.Open);
                    var disassembler = new Disassembler.x86();

                    foreach (var header in pe.SectionHeader)
                    {
                        var section = disassembler.DisassembleSection(stream, header, pe.OptionalHeader32.ImageBase);

                        AddASMLine(section.Lines.GetString());
                        break;
                    }
                }
            }
        }
    }
}
