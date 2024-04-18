using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MathNet.Numerics.LinearAlgebra;
using MathNet.Numerics.LinearAlgebra.Double;


namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        
        public Matrix<double> MinorCofactor(Matrix<double> keyMatrix, int det)
        {
            Matrix<double> matrix = DenseMatrix.Create(3, 3, 0);
            int b = det;
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    
                    int x = i == 0 ? 1 : 0, y = j == 0 ? 1 : 0, x1 = i == 2 ? 1 : 2, y1 = j == 2 ? 1 : 2;
                    
                    double result = ( b * (keyMatrix[x, y] * keyMatrix[x1, y1] - keyMatrix[x, y1] 
                                       * keyMatrix[x1, y]) * Math.Pow(-1, i + j)) % 26;

                    matrix[i, j] = result >= 0 ? result : result + 26;
                }
            }
            return matrix;
        }
        public static int det(Matrix<double> key)
        {
            int result = (int)(key[0, 0] * (key[1, 1] * key[2, 2] - key[1, 2] * key[2, 1]) -
                         key[0, 1] * (key[1, 0] * key[2, 2] - key[1, 2] * key[2, 0]) +
                         key[0, 2] * (key[1, 0] * key[2, 1] - key[1, 1] * key[2, 0]));
            
            
            int det = result % 26 >= 0 ? result % 26 : result % 26 + 26;

            
            //Check that there is exists a +ve integer b < 26 & (b * det(k)) mod 26 = 1
            for (int i = 0; i < 26; i++)
            {
                if ((det * i) % 26 == 1)
                {
                    return i; //returns b
                }
            }

            return -1;

        }
        
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            //throw new NotImplementedException();
            List<int> keyy = new List<int> { 0, 0, 0, 0 };
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {
                            keyy[3] = l;
                            List<int> result = Encrypt(plainText, keyy);
                            if (result.SequenceEqual(cipherText))
                            {
                                return keyy;
                            }


                        }
                        keyy[2] = k;
                        List<int> result1 = Encrypt(plainText, keyy);
                        if (keyy.SequenceEqual(cipherText))
                        {
                            return keyy;
                        }

                    }
                    keyy[1] = j;

                    List<int> result2 = Encrypt(plainText, keyy);
                    if (keyy.SequenceEqual(cipherText))
                    {
                        return keyy;
                    }
                }
                keyy[0] = i;

                List<int> result3 = Encrypt(plainText, keyy);

                if (keyy.SequenceEqual(cipherText))
                {
                    return keyy;
                }


            }
            //return keyy;
            throw new InvalidAnlysisException();


        }

        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();

            plainText = plainText.ToUpper();
            List<char> plain_char = plainText.ToList();

            List<int> plain_list = new List<int>();

            for (int i = 0; i < plain_char.Count; i++)
            {
                plain_list[i] = (int)plain_char[i] - 65;
            }


            cipherText = cipherText.ToUpper();
            List<char> cipher_char = cipherText.ToList();

            List<int> cipher_list = new List<int>();

            for (int i = 0; i < cipher_char.Count; i++)
            {
                cipher_list[i] = (int)cipher_char[i] - 65;
            }

            List<char> key_char = new List<char>();

            List<int> key_list = Analyse(plain_list, cipher_list);

            for (int i = 0; i < key_list.Count; i++)
            {
                key_char[i] = (char)(key_list[i] + 65);
            }
            string key = key_char.ToString();
            return key;
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            //throw new NotImplementedException();

            List<double> keyD = key.ConvertAll(x => (double)x);
            List<double> cipherD = cipherText.ConvertAll(x => (double)x);

            int m = (int) Math.Sqrt(key.Count); // m is number of rows

            Matrix<double> keyMatrix = DenseMatrix.OfColumnMajor(m, key.Count / m, keyD.AsEnumerable());
            Matrix<double> CipherMatrix = DenseMatrix.OfColumnMajor(m, cipherText.Count / m, cipherD.AsEnumerable());
            
            
            List<int> finalResult = new List<int>();
            if (m == 3)
            {
                int b = det(keyMatrix); // it returns the inverse of the determinant
                if (b == -1) 
                {
                    throw new SystemException();
                }
                keyMatrix = MinorCofactor(keyMatrix, b);
                keyMatrix = keyMatrix.Transpose();
    
            }
            else // m = 2
            {
                int d = (int) (keyMatrix[0, 0] * keyMatrix[1, 1] - keyMatrix[0, 1] * keyMatrix[1, 0]);
                d = d % 26 >= 0 ? d % 26 : d % 26 + 26;
                int b = -1;
                
                for (int i = 0; i < 26; i++)
                {
                    if ((d * i) % 26 == 1)
                    {
                        b = i;
                        break;
                    }
                }
                if (b == -1)
                {
                    throw new SystemException();
                }
                double temp;
                temp = keyMatrix[0,0];
                keyMatrix[0, 0] = keyMatrix[1, 1];
                keyMatrix[1, 1] = temp;
                keyMatrix[0, 1] = -keyMatrix[0, 1];
                keyMatrix[1, 0] = -keyMatrix[1, 0];
                keyMatrix = b * keyMatrix;
                //keyMatrix = keyMatrix.Inverse(); //get inverse of a matrix

            }

            for (int i = 0; i < CipherMatrix.ColumnCount; i++)
            {
                List<double> Result = new List<double>();
                Result = (((CipherMatrix.Column(i)).ToRowMatrix()*(keyMatrix) % 26).Enumerate().ToList());
                
                for (int j = 0; j < Result.Count; j++)
                {
                    int x = (int)Result[j] >= 0 ? (int)Result[j] : (int)Result[j] + 26;
                    finalResult.Add(x);
                }
            }
            
            return finalResult;
            
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
             
            cipherText = cipherText.ToUpper();
            List<char> cipher_char = cipherText.ToList();

            List<int> cipher_list = new List<int>();

            for (int i = 0; i < cipher_char.Count; i++)
            {
                cipher_list[i] = (int)cipher_char[i] - 65;
            }

 
            key = key.ToUpper();

            List<char> key_char = key.ToList();
            List<int> key_list = new List<int>();

            for (int i = 0; i < key_char.Count; i++)
            {
                key_list[i] = (int)key_char[i] - 65;
            }

                         
            List<int> plain_list = Decrypt(cipher_list, key_list);
            List<char> plain_char = new List<char>();

            for (int i = 0; i < plain_list.Count; i++)
            {
                plain_char[i] = (char)(plain_list[i] + 65);
            }
            string plain = plain_char.ToString();
            return plain;
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            //throw new NotImplementedException();
            string key1 = "";
            for (int i = 0; i < key.Count; i++)
            {
                key1 += (char)(('A' + key[i]));
            }
            string plainText1 = "";
            for (int i = 0; i < plainText.Count; i++)
            {
                plainText1 += (char)('A' + plainText[i]);
            }
            string cipher_text = Encrypt(plainText1, key1);

            List<int> cipher1 = new List<int>();
            for (int i = 0; i < cipher_text.Length; i++)
            {
                int x = cipher_text[i] - 65;
                cipher1.Add(x);
            }
            return cipher1;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            String key1 = key;
            StringBuilder tmp_key = new StringBuilder(key1.ToUpper());
            int Key_size = (int)Math.Sqrt(key1.Length);


            // insery key to matrix
            int[,] matrix = new int[Key_size, Key_size];
            for (int row_count = 0; row_count < Key_size; row_count++)
            {
                for (int col_count = 0; col_count < Key_size; col_count++)
                {
                    matrix[row_count, col_count] = tmp_key[(row_count * Key_size) + col_count] - 65;
                }
            }

            //insert paintext to matrix
            String plainText1 = plainText;
            StringBuilder tmp_str = new StringBuilder(plainText.ToUpper());
            int[,] matrix2 = new int[Key_size, (tmp_str.Length / Key_size)];


            for (int col_count = 0; col_count < Key_size; col_count++)
            {
                for (int row_count = 0; row_count < tmp_str.Length / Key_size; row_count++)
                {
                    matrix2[col_count, row_count] = tmp_str[(row_count * Key_size) + col_count] - 65;
                }
            }

            //calculate cipher text
            string cipher = "";
            int[,] c = new int[Key_size, tmp_str.Length / Key_size];
            for (int i = 0; i < tmp_str.Length / Key_size; i++)
            {
                for (int j = 0; j < Key_size; j++)
                {
                    c[j, i] = 0;
                    for (int k = 0; k < Key_size; k++)
                    {
                        c[j, i] += matrix2[k, i] * matrix[j, k];
                    }
                    c[j, i] = c[j, i] % 26;
                    cipher += Convert.ToChar(c[j, i] + 65);

                }
            }

            return cipher;


        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            //throw new NotImplementedException();
            List<double> plainD = plain3.ConvertAll(x => (double)x);
            List<double> cipherD = cipher3.ConvertAll(x => (double)x);

            int m = 3; // m is number of rows

            Matrix<double> plainMatrix = DenseMatrix.OfColumnMajor(m, plain3.Count / m, plainD.AsEnumerable());
            Matrix<double> cipherMatrix = DenseMatrix.OfColumnMajor(m, cipher3.Count / m, cipherD.AsEnumerable());

            //get inverse of plainMatrix
            plainMatrix = MinorCofactor(plainMatrix, det(plainMatrix));
            plainMatrix = plainMatrix.Transpose();

            Matrix<double> keyMatrix = DenseMatrix.Create(3, 3, 0);
            keyMatrix = cipherMatrix * plainMatrix;

            List<int> Key = new List<int>();
            
            Key = keyMatrix.Transpose().Enumerate().Select(i => (int)i % 26).ToList();
            
            return Key;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            //throw new NotImplementedException();
            
            plain3 = plain3.ToUpper();
            List<char> plain_char = plain3.ToList();

            List<int> plain_list = new List<int>();

            for (int i = 0; i< plain_char.Count; i++)
            {
                plain_list[i] = (int)plain_char[i] - 65;
            }

            
            cipher3 = cipher3.ToUpper();
            List<char>  cipher_char = cipher3.ToList();

            List<int> cipher_list = new List<int>();

            for (int i = 0; i < cipher_char.Count; i++)
            {
                cipher_list[i] = (int)cipher_char[i] - 65;
            }

            List<int>  key_list = Analyse3By3Key(plain_list, cipher_list);
            List<char> key_char = new List<char>();

            for (int i = 0; i < key_list.Count; i++)
            {
                key_char[i] = (char)(key_list[i] + 65);
            }
            string key = key_char.ToString();
            return key;
        }
    }
}
