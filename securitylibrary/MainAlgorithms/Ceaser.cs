using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {

        string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        //C = (index of P + key) mod 26
        public string Encrypt(string plainText, int key)
        {
            string plain = plainText.ToUpper();
            string cipherText = "";

            for (int i = 0; i < plainText.Length; i++)
            {
                char p = plain[i];
                int pIndex = alphabet.IndexOf(p);
                int cIndex = (pIndex + key) % 26;
                cipherText += alphabet[cIndex];
            }

            return cipherText;
        }

        //P = (index of C - key) mod 26
        public string Decrypt(string cipherText, int key)
        {
            string cipher = cipherText.ToUpper();
            string plainText = "";

            for (int i = 0; i < cipherText.Length; i++)
            {
                char c = cipher[i];
                int cIndex = alphabet.IndexOf(c);
                int pIndex = 0;

                if(cIndex < key)
                    pIndex = (cIndex - key + 26) % 26;
                else
                    pIndex = (cIndex - key) % 26;

                plainText += alphabet[pIndex];
            }

            return plainText.ToLower();
        }

        //Key = index of C - index of P
        public int Analyse(string plainText, string cipherText)
        {
            int key = 0;
            string plain = plainText.ToUpper();
            string cipher = cipherText.ToUpper();

            char p = plain[0];
            char c = cipher[0];
            int pIndex = alphabet.IndexOf(p);
            int cIndex = alphabet.IndexOf(c);

            if (cIndex < pIndex)
                key = cIndex - pIndex + 26;
            else
                key = cIndex - pIndex;
            
            return key;
        }
    }
}
