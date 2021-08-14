using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        List<string> perm = new List<string>();
        private void permute(String str, int start, int end)
        {
            if (start == end)
            {
                perm.Add(str);
            }
            else
            {
                for (int i = start; i <= end; i++)
                {
                    str = swap(str, start, i);
                    permute(str, start + 1, end);
                    str = swap(str, start, i);
                }
            }
        }
        public String swap(String a, int i, int j)
        {
            char t;
            char[] charArray = a.ToCharArray();
            t = charArray[i];
            charArray[i] = charArray[j];
            charArray[j] = t;
            string q = new string(charArray);
            return q;
        }
        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();
            // { 1, 2 }; 2 
            // { 1, 2, 3 }; 6
            // { 1, 2, 3, 4 }; 24
            // { 1, 2, 3, 4, 5 }; 120
            string resault = "";
            permute("12", 0, 1);
            for (int i = 0; i < 2; i++)
            {
                var s = perm[i].Select(x => Convert.ToInt32(x.ToString())).ToList();
                resault = Decrypt(cipherText, s);
                if (resault.Equals(plainText))
                {
                    return s;
                }
                else
                {
                    continue;
                }
            }
            resault = "";
            perm.Clear();
            permute("123", 0, 2);
            for (int i = 0; i < 6; i++)
            {
                var s = perm[i].Select(x => Convert.ToInt32(x.ToString())).ToList();
                resault = Decrypt(cipherText, s);
                if (resault.Equals(plainText))
                {
                    return s;
                }
                else
                {
                    continue;
                }
            }
            perm.Clear();
            resault = "";
            permute("1234", 0, 3);
            for (int i = 0; i < 24; i++)
            {
                var s = perm[i].Select(x => Convert.ToInt32(x.ToString())).ToList();
                resault = Decrypt(cipherText, s);

                if (resault.Equals(plainText))
                {
                    return s;
                }
                else
                {
                    continue;
                }
            }
            perm.Clear();
            resault = "";
            permute("12345", 0, 4);
            for (int i = 0; i < 120; i++)
            {
                var s = perm[i].Select(x => Convert.ToInt32(x.ToString())).ToList();
                resault = Decrypt(cipherText, s);
                if (resault.Equals(plainText))
                {
                    return s;
                }
                else
                {
                    continue;
                }
            }
            perm.Clear();
            resault = "";
            permute("123456", 0, 5);
            for (int i = 0; i < 720; i++)
            {
                var s = perm[i].Select(x => Convert.ToInt32(x.ToString())).ToList();
                resault = Decrypt(cipherText, s);
                if (resault.Equals(plainText))
                {
                    return s;
                }
                else
                {
                    continue;
                }
            }
            perm.Clear();
            resault = "";
            permute("1234567", 0, 6);
            for (int i = 0; i < 5040; i++)
            {
                var s = perm[i].Select(x => Convert.ToInt32(x.ToString())).ToList();
                resault = Decrypt(cipherText, s);
                if (resault.Equals(plainText))
                {
                    return s;
                }
                else
                {
                    continue;
                }
            }
            List<int> r = new List<int>() { 1, 1, 1, 1, 1, 1, 1, 1, 1 };
            return r;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int rows;
            int columns = key.Count;
            string resault = "";
            double t = cipherText.Length / Convert.ToDouble(columns);
            rows = cipherText.Length / columns;
            if (t != rows)
                rows++;
            char[,] array = new char[rows, columns];
            int x = 0, start, end;
            int count = 0;
            for (int i = 0, c = 0; c < columns; i++, c++)
            {
                start = (key[count] * rows) - rows;
                end = key[count] * rows;
                for (int a = start, I = 0; a < end; a++, I++)
                {
                    if (a >= cipherText.Length)
                        array[I, i] = '-';
                    else
                    {
                        array[I, i] = cipherText[a];
                        x++;
                    }
                }
                count++;
            }
            for (int i = 0; i < rows; i++)
            {
                for (int a = 0; a < columns; a++)
                {
                    resault += array[i, a];
                }
            }
            return resault;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int rows;
            int columns = key.Count;
            double t = plainText.Length / Convert.ToDouble(columns);
            rows = plainText.Length / columns;
            if (t != rows)
                rows++;
            char[,] array = new char[rows, columns];
            int x = 0;
            for (int i = 0; i < rows; i++)
            {
                for (int a = 0; a < columns; a++)
                {
                    if (x >= plainText.Length)
                        array[i, a] = '-';
                    else
                    {
                        array[i, a] = plainText[x];
                        x++;
                    }
                }
            }
            string resault = "";
            int count = 0;
            int index = 1;
            for (int i = 0; i < columns; i++)
            {

                key.IndexOf(index);
                for (int a = 0; a < rows; a++)
                {
                    if (array[a, key.IndexOf(index)] == '-')
                    {
                        continue;
                    }
                    else
                    {
                        resault += array[a, key.IndexOf(index)];
                        count++;
                    }
                }
                index++;
            }
            return resault;
        }
    }
}
