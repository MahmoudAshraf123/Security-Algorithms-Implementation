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
            string PlainText = plainText.ToUpper();
            string CipherText = cipherText.ToUpper();
            int key = 1;

            while (true)
            {
                if (key == 7)
                    return 0;
                string resault = "";
                for (int i = 0; i < key; i++)
                {
                    for (int a = i; a < PlainText.Length; a = a + key)
                    {
                        resault += PlainText[a];
                    }
                }
                if (resault.Equals(CipherText))
                {
                    return key;
                }
                else
                {
                    key++;

                    continue;
                }

            }


        }

        public string Decrypt(string cipherText, int key)
        {
            int iterat = cipherText.Length / key;
            double test = cipherText.Length / Convert.ToDouble(key);
            if (iterat != test)
                iterat += 1;
            string resault = "";
            for (int i = 0; i < iterat; i++)
            {
                for (int a = i; a < cipherText.Length; a = a + iterat)
                {
                    resault += cipherText[a];
                }
            }
            return resault;
        }

        public string Encrypt(string plainText, int key)
        {
            string resault = "";
            for (int i = 0; i < key; i++)
            {
                for (int a = i; a < plainText.Length; a = a + key)
                {
                    resault += plainText[a];
                }
            }
            return resault;
        }
    }
}
