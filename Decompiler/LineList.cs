using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Decompiler
{
    public class LineList
    {
        private Dictionary<ulong, LinkedList<string>> dic = new Dictionary<ulong, LinkedList<string>>();

        private ulong currentPosition;

        public LineList() { }

        public void AddLine(string line, ulong position)
        {
            this.currentPosition = position;

            if (dic.ContainsKey(position) == false)
            {
                LinkedList<string> list = new LinkedList<string>();
                list.AddLast(line);
                dic.Add(position, list);
            }
            else
            {
                dic[position].AddLast(line);
            }
        }

        public void Append(string str)
        {
            dic[currentPosition].Last.Value += str;
        }

        public void ModifyLine(string line, string newValue)
        {
            LinkedListNode<string> listNode2 = dic[currentPosition].Find(line);
            listNode2.Value = newValue;
        }

        public void AddLineAfter(string newLine, string oldLine)
        {
            LinkedListNode<string> listNode2 = dic[currentPosition].Find(oldLine);
            dic[currentPosition].AddAfter(listNode2, newLine);
        }

        public string GetString()
        {
            StringBuilder builder = new StringBuilder();

            foreach (var i in dic)
            {
                foreach (var listItem in i.Value)
                    builder.AppendLine(listItem);
            }

            return builder.ToString();
        }
    }
}
