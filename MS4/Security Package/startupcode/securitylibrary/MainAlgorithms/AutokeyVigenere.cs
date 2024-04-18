using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToUpper();
            plainText = plainText.ToUpper();
            int clength = cipherText.Length;
            string key = "";
            string temp = "";
            for (int i = 0; i < clength; i++)
            {
                int x = (cipherText[i] - plainText[i] + 26) % 26;
                x += 'A';
                key += (char)(x);
            }
            temp += key[0];
            int klength = key.Length;
            for (int i = 1; i < klength; i++)
            {
                if (cipherText.Equals(Encrypt(plainText, temp)))
                {
                    return temp.ToUpper();
                }
                temp = temp + key[i];
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            string c = cipherText.ToUpper();
            string k = key.ToUpper();
            for (int i = 0; ; i++)
            {
                if (c.Length == i)
                    i = 0;
                if (k.Length == c.Length + 1)
                    break;
                int x = (c[i] - k[i] + 26) % 26;
                x += 'A';
                k += (char)(x);
            }
            string text = "";
            for (int i = 0; i < c.Length && i < k.Length; i++)
            {
                int x = (c[i] - k[i] + 26) % 26;
                x += 'A';
                text += (char)(x);
            }
            return text;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string p = plainText.ToUpper();
            string k = key.ToUpper();
            for (int i = 0; ; i++)
            {
                if (k.Length == p.Length)
                    break;
                k += p[i];
            }
            string cipher_text = "";
            for (int j = 0; j < p.Length; j++)
            {
                int y = (p[j] + k[j]) % 26;
                y += 'A';
                cipher_text += (char)(y);
            }
            return cipher_text;
        }
    }
}
