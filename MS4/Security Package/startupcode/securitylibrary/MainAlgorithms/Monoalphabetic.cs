using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections;


namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            string ciphertext = cipherText.ToLower();
            string plaintext = plainText.ToLower();
            char[] key = new char[26];

            string alphabet = "abcdefghijklmnopqrstuvwxyz";

            ArrayList CipherLetters = new ArrayList();

            for (int i = 0; i < 26; i++)
            {

                for (int j = 0; j < plaintext.Length; j++)
                {
                    if (!plaintext.Contains(alphabet[i]))
                    {
                        key[i] = ' ';
                        break;

                    }
                    if (plaintext[j] == alphabet[i])
                    {
                        key[i] = ciphertext[j];                        
                        CipherLetters.Add(ciphertext[j]);
                        break;
                    }
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (key[i] == ' ')
                {
                    for (int j = 0; j < 26; j++)
                    {
                        if (!CipherLetters.Contains(alphabet[j]))
                        {
                            key[i] = alphabet[j];
                            CipherLetters.Add(key[i]);
                            break;
                        }
                    }
                }
            }
            string str = new string(key);

            return str;


        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            char[] cp = new char[cipherText.Length];
            for (int i = 0; i < cipherText.Length; i++)
            {
                int k = key.ToUpper().IndexOf(cipherText[i]) + 97;  //104
                cp[i] = (char)k;

            }
            return new String(cp);
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            char[] pl = new char[plainText.Length];
            for (int i = 0; i < plainText.Length; i++)
            {
                int k = plainText[i] - 97;
                pl[i] = key[k];

            }
            return new String(pl);
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            //throw new NotImplementedException();

            string freq = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();
            cipher = cipher.ToLower();

            //count all number of all letters that are in cipher test
            Dictionary<char, int> d1 = new Dictionary<char, int>();
            for (int i = 97; i < 123; i++)
            {
                int c = 0;

                for (int j = 0; j < cipher.Length; j++)
                {
                    if (cipher[j] == (char)i)
                    {
                        c++;
                    }
                }
                d1.Add((char)i, c);
            }

            //sorting letters descedingly by its value
            int counterr = 0;
            char[] letters = new char[26]; //array of sorted letters
            Dictionary<char, int> d2 = new Dictionary<char, int>();

            foreach (KeyValuePair<char, int> letter in d1.OrderByDescending(key => key.Value))
            {
                d2.Add(letter.Key, letter.Value);
                letters[counterr] = letter.Key;
                counterr++;
            }

            //putting sorted letters with its freq in dictionary
            char[] keyy = new char[cipher.Length];
            Dictionary<char, char> d3 = new Dictionary<char, char>();
            for (int i = 0; i < 26; i++)
            {
                d3.Add(letters[i], freq[i]);
            }

            //convert cipher to plain text

            for (int i = 0; i < cipher.Length; i++)
            {
                foreach (KeyValuePair<char, char> letter in d3)
                {
                    if (letter.Key == cipher[i])
                    {
                        keyy[i] = letter.Value;
                    }
                }
            }
            return new string(keyy);
        }
        
    }
}
