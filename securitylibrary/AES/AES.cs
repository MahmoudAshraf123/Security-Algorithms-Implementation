using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {

        int[] matrix ={2,3,1,1,
                       1,2,3,1,
                       1,1,2,3,
                       3,1,1,2};
        int[] inv_matrix ={14,11,13,9,
                       9,14,11,13,
                       13,9,14,11,
                       11,13,9,14};
        //s_BoxData used in subByte step
        string[,] inverse_s_Box = {  { "52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb" },
                             { "7c", "e3" ,"39", "82", "9b" ,"2f", "ff" ,"87", "34" ,"8e", "43", "44" ,"c4", "de" ,"e9" ,"cb" },
                             { "54", "7b" ,"94", "32", "a6" ,"c2" ,"23" ,"3d", "ee" ,"4c" ,"95", "0b", "42", "fa", "c3", "4e" },
                             { "08", "2e", "a1", "66", "28", "d9", "24", "b2" ,"76" ,"5b" ,"a2", "49", "6d" ,"8b" ,"d1" ,"25" },
                             { "72", "f8", "f6", "64", "86" ,"68", "98", "16", "d4", "a4", "5c" ,"cc" ,"5d" ,"65" ,"b6" ,"92" },
                             { "6c", "70", "48", "50", "fd" ,"ed" ,"b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84" },
                             { "90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06" },
                             { "d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b" },
                             { "3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73" },
                             { "96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e" },
                             { "47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b" },
                             { "fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4" },
                             { "1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f" },
                             { "60", "51", "7f" ,"a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef" },
                             { "a0", "e0", "3b" ,"4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb" ,"3c", "83", "53", "99", "61" },
                             { "17", "2b", "04" ,"7e", "ba", "77", "d6", "26", "e1", "69", "14" ,"63", "55", "21", "0c", "7d"}};

        string[,] s_Box = { {"63", "7c", "77", "7b", "f2" ,"6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76" },
                            {"ca" ,"82" ,"c9", "7d", "fa" ,"59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0"  },
                            {"b7" ,"fd", "93", "26", "36" ,"3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15" },
                            {"04" ,"c7", "23", "c3", "18" ,"96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75" },
                            {"09" ,"83", "2c", "1a", "1b" ,"6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84" },
                            {"53" ,"d1", "00", "ed", "20" ,"fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf" },
                            {"d0" ,"ef", "aa", "fb", "43" ,"4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8" },
                            {"51" ,"a3", "40", "8f", "92" ,"9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2" },
                            {"cd" ,"0c", "13", "ec", "5f" ,"97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73" },
                            {"60" ,"81", "4f", "dc", "22" ,"2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db" },
                            {"e0" ,"32", "3a", "0a", "49" ,"06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79" },
                            {"e7" ,"c8", "37", "6d", "8d" ,"d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08" },
                            {"ba" ,"78", "25", "2e", "1c" ,"a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a" },
                            {"70" ,"3e", "b5", "66", "48" ,"03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e" },
                            {"e1" ,"f8", "98", "11", "69" ,"d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df" },
                            {"8c" ,"a1", "89", "0d", "bf" ,"e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16" }};

        string[] Rcon = { "01", "02", "04", "08", "10", "20", "40", "80", "1b", "36" };
        public override string Decrypt(string cipherText, string key)
        {
            string a = key;
            string s = cipherText;
            bool ishexatext = false, ishexakey = false;

            if (key[0] == '0' && key[1] == 'x')
            {
                a = key.Substring(2);
                ishexakey = true;
            }
            if (cipherText[0] == '0' && cipherText[1] == 'x')
            {
                s = cipherText.Substring(2);
                ishexatext = true;
            }
            //change the key and text to array of string
            string[] CypherText = convertStringtoArray(s);
            string[] Key = convertStringtoArray(a);
            List<string[]> AllKeys = new List<string[]>();
            //get all Round Keys
            AllKeys = getRoundKeyStep(Key);

            //Add Round Key
            string[] Cypher = addRoundKey(CypherText, AllKeys[10]);

            for (int round = 10; round >0; round--)
            {
                if (round != 10)
                { 
                    //mix Column Step
                    List<string> r = new List<string>();
                    r = inVmixColumnxStep(Cypher[0], Cypher[1], Cypher[2], Cypher[3]);
                    Cypher[0] = r[0]; Cypher[1] = r[1]; Cypher[2] = r[2]; Cypher[3] = r[3];
                    r = inVmixColumnxStep(Cypher[4], Cypher[5], Cypher[6], Cypher[7]);
                    Cypher[4] = r[0]; Cypher[5] = r[1]; Cypher[6] = r[2]; Cypher[7] = r[3];
                    r = inVmixColumnxStep(Cypher[8], Cypher[9], Cypher[10], Cypher[11]);
                    Cypher[8] = r[0]; Cypher[9] = r[1]; Cypher[10] = r[2]; Cypher[11] = r[3];
                    r = inVmixColumnxStep(Cypher[12], Cypher[13], Cypher[14], Cypher[15]);
                    Cypher[12] = r[0]; Cypher[13] = r[1]; Cypher[14] = r[2]; Cypher[15] = r[3];
                }
                //shift rows step
                string[] cypher = shiftRows(Cypher, 3, 7, 11, 15);
                cypher = shiftRows(cypher, 2, 6, 10, 14);
                cypher = shiftRows(cypher, 2, 6, 10, 14);
                cypher = shiftRows(cypher, 1, 5, 9, 13);
                cypher = shiftRows(cypher, 1, 5, 9, 13);
                cypher = shiftRows(cypher, 1, 5, 9, 13);
                //SubBytes Step:
                for (int i = 0; i < cypher.Length; i++)
                {
                    cypher[i] = getDataFromSbox(cypher[i], inverse_s_Box);
                }             
                //rounddddddddddddd Key operation
                Cypher = addRoundKey(cypher, AllKeys[round-1]);
            }
            string resault = string.Join("", Cypher);
            resault = resault.Trim(new Char[] { ',' });
            if(ishexatext==true)
                resault = "0x" + resault;
            return resault;
        }

        public override string Encrypt(string plainText, string key)
        {
            string a = key;
            string s = plainText;
            bool ishexatext = false, ishexakey = false;
            if (key[0] == '0' && key[1] == 'x')
            {
                a = key.Substring(2);
                ishexakey = true;
            }
            if (plainText[0] == '0' && plainText[1] == 'x')
            {
                s = plainText.Substring(2);
                ishexatext = true;
            }
            //change the key and text to array of string
            string[] PlainText = convertStringtoArray(s);
            string[] Key = convertStringtoArray(a);
            List<string[]> AllKeys = new List<string[]>();
            //get all Round Keys
            AllKeys = getRoundKeyStep(Key);


            //Add Round Key
            string[] plain1 = addRoundKey(PlainText, Key);


            for (int round = 0; round < 10; round++)
            {
                //SubBytes Step:
                for (int i = 0; i < plain1.Length; i++)
                {
                    plain1[i] = getDataFromSbox(plain1[i], s_Box);
                }
                //shift rows step
                string[] plain2 = shiftRows(plain1, 1, 5, 9, 13);
                plain2 = shiftRows(plain2, 2, 6, 10, 14);
                plain2 = shiftRows(plain2, 2, 6, 10, 14);
                plain2 = shiftRows(plain2, 3, 7, 11, 15);
                plain2 = shiftRows(plain2, 3, 7, 11, 15);
                plain2 = shiftRows(plain2, 3, 7, 11, 15);
                if(round==9)
                {
                    plain1 = addRoundKey(plain2, AllKeys[round + 1]);
                    break;

                }
                //mix Column Step
                List<string> r = new List<string>();
                r = mixColumnxStep(plain2[0], plain2[1], plain2[2], plain2[3]);
                plain2[0] = r[0]; plain2[1] = r[1]; plain2[2] = r[2]; plain2[3] = r[3];
                r = mixColumnxStep(plain2[4], plain2[5], plain2[6], plain2[7]);
                plain2[4] = r[0]; plain2[5] = r[1]; plain2[6] = r[2]; plain2[7] = r[3];
                r = mixColumnxStep(plain2[8], plain2[9], plain2[10], plain2[11]);
                plain2[8] = r[0]; plain2[9] = r[1]; plain2[10] = r[2]; plain2[11] = r[3];
                r = mixColumnxStep(plain2[12], plain2[13], plain2[14], plain2[15]);
                plain2[12] = r[0]; plain2[13] = r[1]; plain2[14] = r[2]; plain2[15] = r[3];
                //rounddddddddddddd Key operation
                plain1 = addRoundKey(plain2, AllKeys[round + 1]);
            }

            string resault = string.Join("", plain1);
            resault =  resault.Trim(new Char[] { ',' });
            if (ishexatext == true)
                resault = "0x" + resault;
            return resault;
        }
        private string[] convertStringtoArray(string s)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < s.Length; i++)
            {
                if (i % 2 == 0 && i != 0)
                    sb.Append(',');
                sb.Append(s[i]);
            }
            string formatted = sb.ToString();
            string[] resault = formatted.Split(',');
            return resault;
        }
        private int mulhexa(int key,string value)
        {
            int r;
            int intValue = int.Parse(value, System.Globalization.NumberStyles.HexNumber);
            if(key==1)
                return intValue;
            if (key == 2)
            {
                r =(int)(intValue << 1);
                if (r > 0xFF)
                    r =(int) (r ^ 0x11b);
                return r;
            }
            else
            {
                r = (int)(intValue << 1);
                if (r > 0xFF)
                    r =(int)(r ^ 0x11b);
                r = (int)(r ^ intValue);
                return r;
            }
        }
        private int invMulHexa(int key, string value)
        {
            int initialVal = int.Parse(value, System.Globalization.NumberStyles.HexNumber);           
            int r = int.Parse(value, System.Globalization.NumberStyles.HexNumber);
            if (key == 9)
            {
                for (int i = 0; i < 3; i++)
                {
                    r = (int)(r << 1);
                    if (r > 0xFF)
                        r = (int)(r ^ 0x11b);
                }
                return r ^ initialVal;
            }
            else if (key == 11)
            {
                for (int i = 0; i < 2; i++)
                {
                    r = (int)(r << 1);
                    if (r > 0xFF)
                        r = (int)(r ^ 0x11b);
                }
                r = r ^ initialVal;
                r = (int)(r << 1);
                if (r > 0xFF)
                    r = (int)(r ^ 0x11b);
                return r ^ initialVal;
            }
            else if (key == 13)
            {
                r = (int)(r << 1);
                if (r > 0xFF)
                    r = (int)(r ^ 0x11b);
                r = r ^ initialVal;
                for (int i = 0; i < 2; i++)
                {
                    r = (int)(r << 1);
                    if (r > 0xFF)
                        r = (int)(r ^ 0x11b);
                }
                return r ^ initialVal;
            }
            else if (key == 14)
            {
                r = (int)(r << 1);
                if (r > 0xFF)
                    r = (int)(r ^ 0x11b);
                r = r ^ initialVal;
                r = (int)(r << 1);
                if (r > 0xFF)
                    r = (int)(r ^ 0x11b);
                r = r ^ initialVal;
                r = (int)(r << 1);
                if (r > 0xFF)
                    r = (int)(r ^ 0x11b);
                return r;
            }
            else
                return -1;

        }
        private string mulGfRow(int a, int b, int c, int d)
        {
            int resault =  a ^ b ^ c ^ d;
            return resault.ToString("x");
        }
        //return lsit of string as the resault of mix column steps { 1 column }
        private List<string> mixColumnxStep(string s1,string s2,string s3,string s4){
            int indexOfMatrix = 0;
            List<String> l = new List<string>();
            for (int i = 0; i < 4; i++)
            {
                int r1 = mulhexa(matrix[indexOfMatrix], s1);
                int r2 = mulhexa(matrix[indexOfMatrix+1], s2);
                int r3 = mulhexa(matrix[indexOfMatrix+2], s3);
                int r4 = mulhexa(matrix[indexOfMatrix+3] , s4);
                string resault = mulGfRow(r1, r2, r3, r4);
                if (resault.Length == 1)
                    resault = "0" + resault;
                l.Add(resault);
                indexOfMatrix += 4;
            }
            return l;
        }
        //inverse Mix Column Step
        private List<string> inVmixColumnxStep(string s1, string s2, string s3, string s4)
        {
            int indexOfMatrix = 0;
            List<String> l = new List<string>();
            for (int i = 0; i < 4; i++)
            {
                int r1 = invMulHexa(inv_matrix[indexOfMatrix], s1);
                int r2 = invMulHexa(inv_matrix[indexOfMatrix + 1], s2);
                int r3 = invMulHexa(inv_matrix[indexOfMatrix + 2], s3);
                int r4 = invMulHexa(inv_matrix[indexOfMatrix + 3], s4);
                string resault = mulGfRow(r1, r2, r3, r4);
                if (resault.Length == 1)
                    resault = "0" + resault;
                l.Add(resault);
                indexOfMatrix += 4;
            }
            return l;
        }
        //for subbytes step
        private string getDataFromSbox(string s1,string[,] box)
        {
         
            int row, col;
            row = getsingleHexaVal(s1[0]);
            col = getsingleHexaVal(s1[1]);
            string resault =box[row, col];
            return resault;
        }
        private int getsingleHexaVal(char v)
        {
            int num = (int)char.GetNumericValue(v);

            if (num < 10 && num !=-1)
                return num;
            else if ((char)v == 'a' || (char)v == 'A')
                return 10;
            else if ((char)v == 'b' || (char)v == 'B')
                return 11;
            else if ((char)v == 'c' || (char)v == 'C')
                return 12;
            else if ((char)v == 'd' || (char)v == 'D')
                return 13;
            else if ((char)v == 'e' || (char)v == 'E')
                return 14;
            else if ((char)v == 'f' || (char)v == 'F')
                return 15;
            else
                return -1;
        }
        //Add roundKey step
        private string[] addRoundKey(string[] s1, string[] key)
        {
            List<string> r = new List<string>();
            for(int i=0;i<s1.Length;i++)
            {
                int intValue = int.Parse(s1[i], System.Globalization.NumberStyles.HexNumber);
                int keyval = int.Parse(key[i], System.Globalization.NumberStyles.HexNumber);
                int XoRval = intValue ^ keyval;
                string s = XoRval.ToString("x");
                if (s.Length == 1)
                    s = "0" + s;
                r.Add(s);

            }
            string[] resault = r.ToArray();
            return resault;
        }
        //shift rows step
        private string[] shiftRows(string[] s,int i1,int i2,int i3,int i4)
        {
            string temp = s[1];
            //1
            temp = s[i1];
            s[i1] = s[i2];         
            s[i2] = s[i3];
            s[i3] = s[i4];
            s[i4] = temp;   
            return s;
        }
        private List<string[]> getRoundKeyStep(string[] lastKey)
        {
            List<string[]> AllKeys = new List<string[]>();
            AllKeys.Add(lastKey);
            int counter = 0;
            int rConIndex=0;
            string[] resault = new string[16];
            int listIndes=0;
            string[] col = new string[4];

            for (int i = 0; i < 100;i = i+4 )
            {
              
                if (counter == 0)
                {
                    string[] firstCol = { AllKeys[listIndes][i], AllKeys[listIndes][i + 1], AllKeys[listIndes][i + 2], AllKeys[listIndes][i + 3] };
                    string[] lastCol ;
                    if (i == 0)
                        lastCol = new string[] { AllKeys[listIndes][i + 12], AllKeys[listIndes][i + 13], AllKeys[listIndes][i + 14], AllKeys[listIndes][i + 15] };
                    else
                        lastCol = new string[] { resault[i - 4], resault[i - 3], resault[i - 2], resault[i - 1] };
                    string[] c = getFirstCol(firstCol, lastCol, rConIndex);
                    resault[i] = c[0];
                    resault[i+1] = c[1];
                    resault[i+2] = c[2];
                    resault[i+3] = c[3];
                    counter++;
                    rConIndex++;
                    continue;
                }
                else
                {
                    string[] firstCol = { AllKeys[listIndes][i], AllKeys[listIndes][i + 1], AllKeys[listIndes][i + 2], AllKeys[listIndes][i + 3] };
                    string[] lastCol = { resault[i - 4], resault[i - 3], resault[i - 2], resault[i - 1] };
                    string[] newCol = addRoundKey(firstCol, lastCol);
                    resault[i] = newCol[0];
                    resault[i + 1] = newCol[1];
                    resault[i + 2] = newCol[2];
                    resault[i + 3] = newCol[3];
                    if(i==12)
                    {
                        i = -4;
                        counter = 0;
                        listIndes++;
                        AllKeys.Add( resault);
                        resault = new string[16];

                        if (AllKeys.Count == 11)
                            break;
                    }
                }           
            }
            return AllKeys;
        }
        //getFirstColKey
        private string[] getFirstCol(string[] firstCol, string[] lastCol,int rConIndex)
        {

            lastCol = shiftRows(lastCol, 0, 1, 2, 3);
            lastCol[0] = getDataFromSbox(lastCol[0],s_Box);
            lastCol[1] = getDataFromSbox(lastCol[1], s_Box);
            lastCol[2] = getDataFromSbox(lastCol[2], s_Box);
            lastCol[3] = getDataFromSbox(lastCol[3], s_Box);
            //xor op
            string[] resault = addRoundKey(firstCol, lastCol);
            int intValue = int.Parse(resault[0], System.Globalization.NumberStyles.HexNumber);
            int keyval = int.Parse(Rcon[rConIndex], System.Globalization.NumberStyles.HexNumber);
            int XoRval = intValue ^ keyval;
            string s = XoRval.ToString("x");
            if (s.Length == 1)
                s = "0" + s;
            resault[0] = s;
            return resault;

        }
    }
}
