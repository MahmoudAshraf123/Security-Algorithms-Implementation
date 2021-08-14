using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {

            int[,] EeTable = new int[200, 7];
            EeTable[0,0] = -1;
            EeTable[0, 1] = 1;
            EeTable[0, 2] = 0;
            EeTable[0, 3] = baseN;
            EeTable[0, 4] = 0;
            EeTable[0, 5] = 1;
            EeTable[0, 6] = number;

            int i = 1;
            while(true)
            {
                EeTable[i, 0] = EeTable[i - 1, 3] / EeTable[i - 1, 6];

                EeTable[i, 1] = EeTable[i - 1, 4];
                EeTable[i, 2] = EeTable[i - 1, 5];
                EeTable[i, 3] = EeTable[i - 1, 6];

                EeTable[i, 4] = EeTable[i - 1, 1] - (EeTable[i, 0] * EeTable[i - 1, 4]);
                EeTable[i, 5] = EeTable[i - 1, 2] - (EeTable[i, 0] * EeTable[i - 1, 5]);
                EeTable[i, 6] = EeTable[i - 1, 3] - (EeTable[i, 0] * EeTable[i - 1, 6]);

                if(EeTable[i,6] ==0)
                {
                    return -1;
                }
                else if(EeTable[i,6]==1)
                {
                    return getMInverse(EeTable[i, 5], baseN);
                }
                i++;
            }
        }
        private int getMInverse(int a, int b)
        {
            if (a < 0)
            {
                while(a<0)
                {
                    a += b;
                }
                return a;
            }
            else
            {
                return a % b;
            }
        }
    }

}
