using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections;


namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            key = key.ToLower();
            string ciphertext = cipherText.ToLower();

            char[,] Matrix = CreateMatrix(key);

            //DECRYPTION
            int firstchar_row = 0, firstchar_col = 0, secondchar_row = 0, secondchar_col = 0;
            int Dfirstchar_row = 0, Dfirstchar_col = 0, Dsecondchar_row = 0, Dsecondchar_col = 0;
            string plaintext = "";

            for (int i = 0; i < ciphertext.Length; i += 2)
            {
                
                for (int row = 0; row < 5; row++)
                {
                    for (int col = 0; col < 5; col++)
                    {
                        if (ciphertext[i] == Matrix[row, col])
                        {
                            firstchar_row = row;
                            firstchar_col = col;
                        }
                        else if (ciphertext[i + 1] == Matrix[row, col])
                        {
                            secondchar_row = row;
                            secondchar_col = col;
                        }
                    }
                }

                if (firstchar_col == secondchar_col) //the 2 chars in the same column
                {
                    Dfirstchar_col = firstchar_col;
                    Dsecondchar_col = secondchar_col;

                    Dfirstchar_row = (firstchar_row - 1 + 5) % 5;
                    Dsecondchar_row = (secondchar_row - 1 + 5) % 5;

                }
                else if (firstchar_row == secondchar_row) //the 2 chars in the same row
                {
                    Dfirstchar_row = firstchar_row;
                    Dsecondchar_row = secondchar_row;

                    Dfirstchar_col = (firstchar_col - 1 + 5) % 5;
                    Dsecondchar_col = (secondchar_col - 1 + 5) % 5;

                }
                else
                {
                    Dfirstchar_row = firstchar_row;
                    Dfirstchar_col = secondchar_col;

                    Dsecondchar_row = secondchar_row;
                    Dsecondchar_col = firstchar_col;
                }
                
                    
                
                plaintext = plaintext + Matrix[Dfirstchar_row, Dfirstchar_col];
                plaintext = plaintext + Matrix[Dsecondchar_row, Dsecondchar_col];
                

            }
            if (plaintext[plaintext.Length - 1] == 'x')
            {
                plaintext = plaintext.Substring(0, plaintext.Length - 1);
            }
            for (int i = 0; i < plaintext.Length - 1; i += 2)
            {
                if (plaintext[i + 1] == 'x' && plaintext[i] == plaintext[i + 2])
                {
                    plaintext = plaintext.Substring(0, i + 1) + plaintext.Substring(i + 2);
                    i--;
                }

            }

            return plaintext;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();

            key = key.ToLower();
            string plaintext = plainText.ToLower();

            //CREATING MATRIX
            char[,] Matrix = CreateMatrix(key);
            

            
            //ENCRYPTION
            int firstchar_row = 0, firstchar_col = 0, secondchar_row = 0, secondchar_col = 0;
            int Efirstchar_row = 0, Efirstchar_col = 0, Esecondchar_row = 0, Esecondchar_col = 0;            
            string encrypted = "";

            for (int i = 0; i < plaintext.Length; i += 2)
            {
                if (i == plaintext.Length - 1)
                {
                    plaintext = plaintext + 'x';
                }
                else if (plaintext[i] == plaintext[i + 1])
                {
                    plaintext = plaintext.Substring(0, i + 1) + 'x' + plaintext.Substring(i + 1);
                }
                for (int row = 0; row < 5; row++)
                {
                    for (int col = 0; col < 5; col++)
                    {
                        if (plaintext[i] == Matrix[row, col])
                        {
                            firstchar_row = row;
                            firstchar_col = col;
                        }
                        else if (plaintext[i + 1] == Matrix[row, col])
                        {
                            secondchar_row = row;
                            secondchar_col = col;
                        }
                    }
                }
                
                if (firstchar_col == secondchar_col) //the 2 chars in the same column
                {
                    Efirstchar_col = firstchar_col;
                    Esecondchar_col = secondchar_col;

                    Efirstchar_row = (firstchar_row + 1) % 5;
                    Esecondchar_row = (secondchar_row + 1) % 5;

                }
                else if (firstchar_row == secondchar_row) //the 2 chars in the same row
                {
                    Efirstchar_row = firstchar_row;
                    Esecondchar_row = secondchar_row;

                    Efirstchar_col = (firstchar_col + 1) % 5;
                    Esecondchar_col = (secondchar_col + 1) % 5;

                }
                else
                {
                    Efirstchar_row = firstchar_row;
                    Efirstchar_col = secondchar_col;

                    Esecondchar_row = secondchar_row;
                    Esecondchar_col = firstchar_col;
                }
                encrypted = encrypted + Matrix[Efirstchar_row, Efirstchar_col];
                encrypted = encrypted + Matrix[Esecondchar_row, Esecondchar_col];
            }
            return encrypted.ToUpper();
        }
        public char[,] CreateMatrix(string key)
        {
            char[,] Matrix = new char[5, 5];

            string alphabet = "abcdefghijklmnopqrstuvwxyz";

            string letters = key + alphabet;
            ArrayList UniqueLetters = new ArrayList();

            for (int i = 0; i < letters.Length; i++)
            {
                if (!UniqueLetters.Contains(letters[i]))
                {
                    if ((letters[i] == 'i' && !UniqueLetters.Contains('j')) || (letters[i] == 'j' && !UniqueLetters.Contains('i')) ||
                        (letters[i] != 'i' && letters[i] != 'j'))
                    {

                        UniqueLetters.Add(letters[i]);

                    }
                }

            }

            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    Matrix[i, j] = (char)UniqueLetters[i * 5 + j];

                }

            }
            return Matrix;

        }
    }
}
