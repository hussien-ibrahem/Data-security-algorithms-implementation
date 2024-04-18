using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToUpper();
            int pt_len = plainText.Length;
            cipherText = cipherText.ToUpper();
            int ct_len = cipherText.Length;
            int columm = 1;
            for (int i = 0; i < pt_len; i++)
            {
                for (int j = 0; j < ct_len; j++)
                {
                    int ct = cipherText[i];
                    int pt = plainText[j];

                    if (ct == pt)
                    {
                        for (int k = j + 1; k < ct_len; k++)
                        {

                            int new_i = i + 1;
                            int p = plainText[k];
                            if (p == cipherText[new_i])
                            {
                                break;
                            }
                            else
                            {

                                columm += 1;
                            }

                        }
                    }
                    if (columm <= 1) continue;
                    else break;
                }
                if (columm <= 1) continue;
                else break;
            }
            //////////////////
            int dif = -1;
            int row = ct_len / columm;
            if (ct_len % columm != 0)
            {
                int ct_temp = ct_len;
                row++;
                do
                {
                    if (ct_temp % columm != 0)
                    {
                        dif++;
                        ct_temp++;
                    }


                } while (ct_temp % columm != 0);
            }

            ///////////////////////////////
            List<int> indx = new List<int>();
            int idx = 1;
            for (int i = 0; i < ct_len; i += row)
            {
                bool flag = false;
                for (int j = 0; j < columm; j++)
                {

                    int ct = cipherText[i];
                    int pt = plainText[j];
                    if (pt == ct && i < ct_len - 1)
                    {
                        if (plainText[j + columm] == cipherText[i + 1] && !indx.Contains(j))
                        {
                            flag = true;
                            indx.Add(j);
                            idx++;
                            break;
                        }
                    }
                    else if (plainText[j + columm] == ct && !indx.Contains(j))
                    {
                        if (i > 0 && pt == cipherText[i - 1])
                        {
                            flag = true;
                            indx.Add(j);
                            idx++;
                            break;
                        }
                    }
                }

                if (!flag)
                {
                    for (int j = 0; j < columm; j++)
                    {
                        int p = plainText[j];
                        if (cipherText[i - dif] == p && !indx.Contains(j))
                        {
                            if (plainText[j + columm] == cipherText[i - dif + 1])
                            {
                                indx.Add(j);
                                idx++;
                                if (flag == true) break;
                                else continue;
                            }
                        }
                    }
                }
            }


            List<int> keys = new List<int>();

            for (int i = 0; i < columm; i++)
            {
                for (int j = 0; j < columm; j++)
                {
                    if (indx[j] != i)
                    {

                        continue;
                    }
                    else
                    {
                        keys.Add(j + 1);
                        break;
                    }

                }
            }
            return keys;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            //throw new NotImplementedException();
            string pt = "";
            int index = 0;
            int temp = 0;
            int ct_len = cipherText.Length;

            if (ct_len % key.Count != 0)
            {
                ct_len += key.Count;
            }
            int col = ct_len / key.Count;
            char[,] d_arr = new char[col, key.Count];
            for (int i = 0; i < key.Count; i++)
            {
                index = key.IndexOf(i + 1);

                for (int j = 0; j < col && temp < cipherText.Length; j++)
                {

                    d_arr[j, index] = cipherText[temp];
                    temp++;

                }
            }
            // combine plain text 
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {
                    pt = pt + d_arr[i, j];
                }
            }


            return pt;

        }

        public string Encrypt(string plainText, List<int> key)
        {
            //throw new NotImplementedException();
            string ct = "";
            int col = key.Count;
            int pt_len = plainText.Length;
            int rows = plainText.Length / col;
            List<List<char>> mtrx = new List<List<char>>();

            // put x in free spaces 
            if (pt_len != rows * col)
            {
                rows = rows + 1;
                int x = (rows * col) - plainText.Length;
                string add_x = new string('x', x);
                plainText += add_x;
            }



            for (int i = 0; i < rows; i++)
            {
                mtrx.Add(new List<char>());
            }

            //add plain text to matrix 
            int c = 0;
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if (c < plainText.Length)
                    {
                        mtrx[i].Add(plainText[c]);
                        c++;
                    }
                }
            }
            //characters in column for each key
            Dictionary<int, string> cip = new Dictionary<int, string>();
            for (int i = 0; i < col; i++)
            {
                string temp = "";
                for (int j = 0; j < rows; j++)
                {
                    temp += mtrx[j][i];
                    cip[key[i]] = temp;
                }
            }
            //combine cipher text
            for (int i = 1; i <= cip.Count; i++)
            {
                ct += cip[i];
            }

            return ct;

        }
    }
}
