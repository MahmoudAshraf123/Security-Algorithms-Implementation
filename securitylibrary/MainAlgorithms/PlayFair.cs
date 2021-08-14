using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        //string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        string alphabetWithoutJ = "ABCDEFGHIKLMNOPQRSTUVWXYZ";

        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            char[,] keyMatrix = constructKeyMatrix(key);

            string cipher = cipherText.ToUpper();
            cipher = cipher.Replace('J', 'I');

            for (int i = 0; i < cipher.Length; i += 2)
            {
                string block = cipher.Substring(i, 2);
                plainText += translateBlock(block, keyMatrix, "dec");
            }

            string plain = plainText.Substring(0, 2);

            //check for block with the same letters
            for (int k = 2, j = 0; k < plainText.Length; k += 2, j += 2)
            {
                string oldBlock = plain.Substring(j, 2);
                string newBlock = plainText.Substring(k, 2);

                if (oldBlock[0] == newBlock[0] && oldBlock[1] == 'X')
                {
                    plain = plain.Remove(j + 1);
                    j--;
                }

                plain += newBlock;
            }

            if ((plain[plain.Length - 1] == 'X'))
            {
                plain = plain.Remove(plain.Length - 1, 1);
            }

            return plain.ToLower();
        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            char[,] keyMatrix = constructKeyMatrix(key);

            string plain = plainText.ToUpper();
            plain = plain.Replace('J', 'I');

            //check for block with the same letters
            for (int i = 0; i < plain.Length; i += 2)
            {
                if (i + 1 != plain.Length && plain[i] == plain[i + 1])
                {
                    plain = plain.Insert(i + 1, "X");
                }
            }

            //if the plainText length is odd
            if (plain.Length % 2 != 0) 
            {
                plain += 'X';
            }

            for (int i = 0; i < plain.Length; i += 2)
            {
                string block = plain.Substring(i, 2);
                cipherText += translateBlock(block, keyMatrix, "enc");
            }

            return cipherText.ToUpper();
        }

        //helper functions
        private string translateBlock(string block, char[,] keyMatrix, string type)
        {
            string newblock = "";
            int firstLetterRow = 0, firstLetterCol = 0, secondLetterRow = 0, secondLetterCol = 0;

            //search for the block letters in key matrix
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (block[0] == keyMatrix[i, j]) 
                    {
                        firstLetterRow = i;
                        firstLetterCol = j;
                    }
                    else if (block[1] == keyMatrix[i, j])
                    {
                        secondLetterRow = i;
                        secondLetterCol = j;
                    }
                }
            }
            
            //substitute
            if (firstLetterRow == secondLetterRow) //letters in the same row
            {
                if (type.Equals("enc"))
                {
                    newblock += keyMatrix[firstLetterRow, (firstLetterCol + 1) % 5];
                    newblock += keyMatrix[secondLetterRow, (secondLetterCol + 1) % 5];
                }
                else if (type.Equals("dec"))
                {
                    if (firstLetterCol != 0)
                        newblock += keyMatrix[firstLetterRow, (firstLetterCol - 1)];
                    else
                        newblock += keyMatrix[firstLetterRow, 4];

                    if (secondLetterCol !=0)
                        newblock += keyMatrix[secondLetterRow, (secondLetterCol - 1)];
                    else
                        newblock += keyMatrix[secondLetterRow, 4];
                }
                
            }
            else if (firstLetterCol == secondLetterCol) //letters in the same column
            {
                if (type.Equals("enc"))
                {
                    newblock += keyMatrix[(firstLetterRow + 1) % 5, firstLetterCol];
                    newblock += keyMatrix[(secondLetterRow + 1) % 5, secondLetterCol];
                }
                else if (type.Equals("dec"))
                {
                    if (firstLetterRow != 0)
                        newblock += keyMatrix[(firstLetterRow - 1), firstLetterCol];
                    else
                        newblock += keyMatrix[4, firstLetterCol];

                    if (secondLetterRow !=0)
                        newblock += keyMatrix[(secondLetterRow - 1), secondLetterCol];
                    else
                        newblock += keyMatrix[4, secondLetterCol];
                }
            }
            else // letters in the diagonal
            {
                newblock += keyMatrix[firstLetterRow, secondLetterCol];
                newblock += keyMatrix[secondLetterRow, firstLetterCol];
            }

            return newblock;
        }
        
        private char[,] constructKeyMatrix(string inputKey)
        {
            inputKey = inputKey.ToUpper();
            string key = new string(inputKey.Distinct().ToArray()); //remove duplicate letters
            
            //remove J if exist
            if (key.Contains('J') && key.Contains('I'))
                key.Remove('J');
            else if (key.Contains('J') && !key.Contains('I'))
                key = key.Replace('J', 'I');  

            //fill key with the remaining letters
            if (key.Length < 25)
            {
                for (int i = 0; i < alphabetWithoutJ.Length; i++)
                {
                    char letter = alphabetWithoutJ[i];
                    if (!key.Contains(letter))
                    {
                        key += letter;
                    }
                }
            }

            //convert key to 2D matrix
            char[,] matrix = new char[5, 5];
            int k = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    matrix[i, j] = key[k];
                    k++;
                }
            }

            return matrix;
        }

    }
}
