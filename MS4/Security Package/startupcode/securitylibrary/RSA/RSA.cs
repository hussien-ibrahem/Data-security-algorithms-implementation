using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.AES;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int pow(int a, int b, int c)
        {
            int res = 1;
            for (int i = 0; i < b; i++)
            {
                res = (res * a) % c; 
            }
            return res;
        }

        public int Encrypt(int p, int q, int M, int e)
        {
            //throw new NotImplementedException();

            int n = p * q;
            int C = pow(M,e,n);

            return C;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            //throw new NotImplementedException();

            int n = p * q;
            int Euler = (p - 1) * (q - 1);
             AES.ExtendedEuclid extEuc = new AES.ExtendedEuclid();
            int d = extEuc.GetMultiplicativeInverse(e, Euler);
            int M = pow(C,d,n);

            return M;
        }
    }
}
