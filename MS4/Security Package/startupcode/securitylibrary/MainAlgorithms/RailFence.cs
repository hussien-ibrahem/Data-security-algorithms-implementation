using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {

            cipherText = cipherText.ToLower();
            int key = 2;
            for (int i = 0; i < plainText.Length / 2; i++)
            {
                if (plainText[i] != cipherText[i])
                {
                    plainText = plainText.Remove(i, 1);
                    key++;
                }
                if (plainText[i] == cipherText[i])
                    plainText = plainText.Remove(i + 1, 1);
                if (plainText[0] == cipherText[0] && plainText[1] == cipherText[1])
                    break;
            }
            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            String.Join(cipherText, cipherText.Split(' '));
            int col = (int)Math.Ceiling((double)cipherText.Length / key);
            char[,] arr = new char[key, col];
            int counter = 0;
            string plaintext = "";
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    arr[i, j] = cipherText[counter];
                    counter++;
                    if (counter == cipherText.Length)
                    { break; }
                }
            }
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    plaintext += arr[j, i];
                }
            }
            return plaintext;
        }



        public string Encrypt(string plainText, int key)
        {

            String.Join(plainText, plainText.Split(' '));
            int sizePlain = plainText.Length;
            int sizeeee = (int)Math.Ceiling((double)plainText.Length / key);


            plainText = plainText.ToLower();
            char[,] array = new char[key, sizePlain];
            int count = 0;
            for (int i = 0; i < sizeeee; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    array[j, i] = plainText[count];
                    count++;
                    if (count == plainText.Length)
                    { break; }
                }
            }
            string cipher = "";
            Console.WriteLine("after loop ");
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < sizeeee; j++)
                {

                    cipher += array[i, j];

                }
            }
            return cipher.ToUpper();

        }
    }
}
