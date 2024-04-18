using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            string result = string.Empty;
            foreach (char ch in plainText)
            {

                if (!char.IsLetter(ch))
                {

                    result += ch;
                }
                //Ascii-code A=65 || a=97
                char d = char.IsUpper(ch) ? 'A' : 'a';
                result += (char)((((ch + key) - d) % 26) + d);
            }
            return result;
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            return Encrypt(cipherText, 26 - key);
        }

        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            int key;
            string ct = cipherText.ToUpper();
            string pt = plainText.ToUpper();
            char ch = ct[0];
            char ch2 = pt[0];
            key = (ch - ch2);
            if (key < 0)
            {
                return (key + 26);
            }
            else
            {
                return key;
            }

        }
    }
}
