using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        string[] alphapet = { "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "BCDEFGHIJKLMNOPQRSTUVWXYZA", "CDEFGHIJKLMNOPQRSTUVWXYZAB", "DEFGHIJKLMNOPQRSTUVWXYZABC"
            ,"EFGHIJKLMNOPQRSTUVWXYZABCD","FGHIJKLMNOPQRSTUVWXYZABCDE","GHIJKLMNOPQRSTUVWXYZABCDEF",
            "HIJKLMNOPQRSTUVWXYZABCDEFG","IJKLMNOPQRSTUVWXYZABCDEFGH","JKLMNOPQRSTUVWXYZABCDEFGHI","KLMNOPQRSTUVWXYZABCDEFGHIJ",
            "LMNOPQRSTUVWXYZABCDEFGHIJK","MNOPQRSTUVWXYZABCDEFGHIJKL","NOPQRSTUVWXYZABCDEFGHIJKLM","OPQRSTUVWXYZABCDEFGHIJKLMN",
            "PQRSTUVWXYZABCDEFGHIJKLMNO","QRSTUVWXYZABCDEFGHIJKLMNOP","RSTUVWXYZABCDEFGHIJKLMNOPQ","STUVWXYZABCDEFGHIJKLMNOPQR",
            "TUVWXYZABCDEFGHIJKLMNOPQRS","UVWXYZABCDEFGHIJKLMNOPQRST","VWXYZABCDEFGHIJKLMNOPQRSTU","WXYZABCDEFGHIJKLMNOPQRSTUV",
            "XYZABCDEFGHIJKLMNOPQRSTUVW","YZABCDEFGHIJKLMNOPQRSTUVWX","ZABCDEFGHIJKLMNOPQRSTUVWXY"};
        public string Analyse(string plainText, string cipherText)
        {
            string cipher = cipherText.ToUpper();
            string plain = plainText.ToUpper();
            string key = "";
            string key_stream = "";

            //for mapping with table
            string s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            int[] arr = new int[cipherText.Length];
            int[] arr2 = new int[plainText.Length];

            // for plain text
            for (int i = 0; i < plainText.Length; i++)
            {

                char p = plain[i];
                int index_p = s.IndexOf(p);
                arr2[i] = index_p;
            }

            // for cipher  text
            string[] index_op_cihper = new string[cipherText.Length];
            for (int i = 0; i < arr2.Length; i++)
            {
                index_op_cihper[i] = alphapet.ElementAt(arr2[i]);
            }

            for (int i = 0; i < index_op_cihper.Length; i++)
            {
                for (int j = 0; j < index_op_cihper[i].Length; j++)
                {

                    if (cipher[i] == index_op_cihper[i][j])
                    {
                        arr[i] = j;

                    }
                }
            }

            //for keystream
            for (int i = 0; i < arr.Length; i++)
            {
                key_stream += s[arr[i]];
            }
            string temp = "";
            temp += plain[0]; temp += plain[1];  temp += plain[2];
            for (int i = 0; i < key_stream.Length; i++)
            {
                if (key_stream[i] == temp[0] && key_stream[i + 1] == temp[1]&&key_stream[i+2]==temp[2])
                    break;
                else
                    key += key_stream[i];
            }
            return key.ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            string key_stream = key;
            string cipher = cipherText.ToUpper();
            int x = 0;
            string df = "";

            while (key_stream.Length <= cipherText.Length)
            {
                //for key 
                df = key_stream;
                //for mapping with table
                string s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                int[] arr = new int[key_stream.Length];
                int[] arr2 = new int[key_stream.Length];

                // for key_stream
                for (int i = 0; i < key_stream.Length; i++)
                {
                    string key_stream_upper = key_stream.ToUpper();
                    char p = key_stream_upper[i];
                    int index_k = s.IndexOf(p);
                    arr2[i] = index_k;
                }

                // for cipher  text
                string[] index_op_cihper = new string[key_stream.Length];
                for (int i = 0; i < arr2.Length; i++)
                {
                    index_op_cihper[i] = alphapet.ElementAt(arr2[i]);
                }

                for (int i = 0; i < index_op_cihper.Length; i++)
                {
                    for (int j = 0; j < index_op_cihper[i].Length; j++)
                    {

                        if (cipher[i] == index_op_cihper[i][j])
                        {
                            arr[i] = j;

                        }
                    }
                }

                //for plain text
                for (int i = 0; i < arr.Length; i++)
                {
                    plainText += s[arr[i]];
                }

                //this to get key stream
                for (int i = x; i < (cipherText.Length - key.Length); i++)
                {

                    if (i == plainText.Length)
                        break;

                    key_stream += plainText[i];
                    x++;
                }

                if (df.Length == cipherText.Length)
                    break;
                plainText = "";
            }
            return plainText.ToLower();
        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            string plain = plainText.ToUpper();
            string key_stream = key;

            // for key stream 
            if (key.Length < plainText.Length)
            {
                int j = 0;
                for (int i = 0; i < (plainText.Length - key.Length); i++)
                {
                    key_stream += plainText[j];
                    j++;
                    

                }
            }
            //for mapping with table
            string s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            int[] arr = new int[plainText.Length];
            int[] arr2 = new int[key_stream.Length];

            for (int i = 0; i < plainText.Length; i++)
            {
                char p = plain[i];
                int index_plain = s.IndexOf(p);
                arr[i] = index_plain;
            }
            // for key_stream
            for (int i = 0; i < key_stream.Length; i++)
            {
                string key_stream_upper = key_stream.ToUpper();
                char p = key_stream_upper[i];
                int index_k = s.IndexOf(p);
                arr2[i] = index_k;
            }

            // get cipher 
            for (int i = 0; i < arr.Length; i++)
            {
                cipherText += alphapet[arr[i]][arr2[i]];
            }
            return cipherText.ToUpper();
        }
    }
}
