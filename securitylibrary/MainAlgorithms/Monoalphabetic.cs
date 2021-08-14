using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        public string Analyse(string plainText, string cipherText)
        {
            List<char> keyList = new List<char>();

            //init the keyList
            for (int i = 0; i < alphabet.Length; i++)
            {
                keyList.Add('0');
            }

            string plain = plainText.ToUpper();
            string cipher = cipherText.ToUpper();

            //fill the keyList from cipherText
            for (int i = 0; i < alphabet.Length; i++)
            {
                char currentChar = alphabet[i];
                int currentCharIndex = plain.IndexOf(currentChar);

                if (currentCharIndex != -1)
                    keyList[i] = cipher[currentCharIndex];
                else
                    continue;
            }

            //check if there are remaining letters not included in keyList
            for (int i = 0; i < alphabet.Length; i++)
            {
                if (!keyList.Contains(alphabet[i]))
                {
                    keyList[keyList.IndexOf('0')] = alphabet[i];
                }
            }

            string key = new string(keyList.ToArray());

            return key.ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            string cipher = cipherText.ToUpper();
            string k = key.ToUpper();

            for (int i = 0; i < cipherText.Length; i++)
            {
                char c = cipher[i];
                int cIndex = k.IndexOf(c);
                plainText += alphabet[cIndex];
            }

            return plainText.ToLower();
        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            string plain = plainText.ToUpper();

            for (int i = 0; i < plainText.Length; i++)
            {
                char p = plain[i];
                int pIndex = alphabet.IndexOf(p);
                cipherText += key[pIndex];
            }

            return cipherText.ToUpper();
        }

        
        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string plainText = "";
            string cipherCap = cipher.ToUpper();
            string alphabetFrequncyOrder = "ETAOINSRHLDCUMFPGWYBVKXJQZ";

            Dictionary<char, int> frequncyList = new Dictionary<char, int>();

            //count Frequncy for each letter in cipher text
            for (int i = 0; i < alphabet.Length; i++)
            {
                frequncyList.Add(alphabet[i], cipherCap.Count(letter => letter == alphabet[i]));
            }

            //sort the dictionary
            var orderedFrequncyList = frequncyList.OrderByDescending(f => f.Value);

            string cipherFrequncyOrder = "";
            for (int i = 0; i < orderedFrequncyList.Count(); i++)
            {
                cipherFrequncyOrder += orderedFrequncyList.ElementAt(i).Key;
            }

            //fill plainText
            for (int i = 0; i < cipherCap.Length; i++)
            {
                char c = cipherCap[i];
                int cIndex = cipherFrequncyOrder.IndexOf(c);
                plainText += alphabetFrequncyOrder[cIndex];
            }

            return plainText.ToLower();
        }

    }
}
