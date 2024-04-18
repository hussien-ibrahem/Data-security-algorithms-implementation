using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
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
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            //throw new NotImplementedException();
            List<int> Keys = new List<int>();

            //User A key generation
            //calculate public ya
            int ya = pow(alpha, xa, q);

            //User B key generation
            //calculate public yb
            int yb = pow(alpha, xb, q);

            //calculation of secret key by user A
            int k1 = pow(yb, xa, q);

            //calculation of secret key by user B
            int k2 = pow(ya, xb, q);

            Keys.Add(k1);
            Keys.Add(k2);

            return Keys;
        }
    }
}
