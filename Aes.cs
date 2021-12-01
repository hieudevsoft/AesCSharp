using System.Text;

namespace Aes_Bin_Tam
{
    public class Aes
    {
        private int currentRound;
        private static int Nb = 4;
        private int Nr;
        private int Nk;
        private int[][][] state;
        private int[] w;
        private int[] key;
        private byte[] iv;

        public Aes(byte[] key)
        {
            initWithoutIv(key);
        }

        public Aes(byte[] key, byte[] iv)
        {
            initWithIv(key, iv);
        }


        private void initWithIv(byte[] key, byte[] iv)
        {
            this.iv = iv;
            this.key = new int[key.Length];
            initElements(key);
        }

        private void initWithoutIv(byte[] key)
        {
            this.key = new int[key.Length];
            initElements(key);
        }

        private void initElements(byte[] key)
        {
            for (int i = 0; i < key.Length; i++)
            {
                this.key[i] = key[i];
            }
            Nb = 4;
            switch (key.Length)
            {
                case 16:
                    {
                        Nr = 10;
                        Nk = 4;
                        break;
                    }
                case 24:
                    {
                        Nr = 12;
                        Nk = 6;
                        break;
                    }
                case 32:
                    {
                        Nr = 14;
                        Nk = 8;
                        break;
                    }
                default: throw new FormatException("Chỉ hỗ trợ 128, 192 and 256 bit keys!");
            }
            state = new int[2][][];
            for (int i = 0; i < state.Length; i++)
            {
                state[i] = new int[4][];
                for (int j = 0; j < state[i].Length; j++)
                {
                    state[i][j] = new int[Nb];
                }
            }
            w = new int[Nb * (Nr + 1)];
            expandKey();
        }
        private int[][] addRoundKey(int[][] s, int round)
        {
            for (int c = 0; c < Nb; c++)
            {
                for (int r = 0; r < 4; r++)
                {
                    var temp = (int)(w[round * Nb + c] << (r * 8));
                    s[r][c] = (int)(s[r][c] ^ ((uint)temp >> 24));
                }
            }
            return s;
        }
        private int[][] cipher(int[][] input, int[][] output)
        {
            for (int i = 0; i < input.Length; i++)
            {
                for (int j = 0; j < input.Length; j++)
                {
                    output[i][j] = input[i][j];
                }
            }
            currentRound = 0;
            addRoundKey(output, currentRound);
            for (currentRound = 1; currentRound < Nr; currentRound++)
            {
                subBytes(output);
                shiftRows(output);
                mixColumns(output);
                addRoundKey(output, currentRound);
            }
            subBytes(output);
            shiftRows(output);
            addRoundKey(output, currentRound);
            return output;
        }

        public string ToMatrixString(int[][] matrix, string delimiter = "\t")
        {
            var s = new StringBuilder();

            for (var i = 0; i < matrix.Length; i++)
            {
                for (var j = 0; j < matrix[i].Length; j++)
                {
                    s.Append(matrix[i][j]).Append(delimiter);
                }

                s.AppendLine();
            }

            return s.ToString();
        }

        private int[][] decipher(int[][] input, int[][] output)
        {
            for (int i = 0; i < input.Length; i++)
            {
                for (int j = 0; j < input.Length; j++)
                {
                    output[i][j] = input[i][j];
                }
            }
            currentRound = Nr;
            addRoundKey(output, currentRound);
            for (currentRound = Nr - 1; currentRound > 0; currentRound -= 1)
            {
                invShiftRows(output);
                invSubBytes(output);
                addRoundKey(output, currentRound);
                invMixColumns(output);
            }
            invShiftRows(output);
            invSubBytes(output);
            addRoundKey(output, currentRound);

            return output;
        }

        private byte[] encrypt(byte[] text)
        {
            if (text.Length != 16)
            {
                throw new FormatException("Chỉ 16-bytes block mới được phép mã hóa");
            }
            byte[] output = new byte[text.Length];
            for (int i = 0; i < Nb; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    state[0][j][i] = text[i * Nb + j] & 0xff;
                }
            }
            cipher(state[0], state[1]);
            for (int i = 0; i < Nb; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    output[i * Nb + j] = (byte)(state[1][j][i] & 0xff);
                }
            }
            return output;
        }

        private byte[] decrypt(byte[] text)
        {
            if (text.Length != 16)
            {
                throw new FormatException("Chỉ 16-bytes block mới được phép giải mã");
            }
            byte[] output = new byte[text.Length];
            for (int i = 0; i < Nb; i++)
            { // columns
                for (int j = 0; j < 4; j++)
                { // rows
                    state[0][j][i] = text[i * Nb + j] & 0xff;
                }
            }
            decipher(state[0], state[1]);
            // for (int i = 0; i < state[1].Length; i++)
            // { // columns
            //     for (int j = 0; j < state[1].Length; j++)
            //     { // rows
            //         Console.Write(state[1][i][j]+", ");
            //     }
            // }

            for (int i = 0; i < Nb; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    output[i * Nb + j] = (byte)(state[1][j][i] & 0xff);
                }
            }

            return output;
        }

        private void show3Darray(int[][][] foos)
        {
            for (int x = 0; x < foos.Length; x++)
            {
                for (int y = 0; y < foos[x].Length; y++)
                {
                    for (int z = 0; z < foos[x][y].Length; z++)
                    {
                        Console.WriteLine(foos[x][y][z]);
                    }
                }
            }
        }

        private int[][] invMixColumns(int[][] state)
        {
            int temp0, temp1, temp2, temp3;
            for (int c = 0; c < Nb; c++)
            {
                temp0 = mult(0x0e, state[0][c]) ^ mult(0x0b, state[1][c]) ^ mult(0x0d, state[2][c]) ^ mult(0x09, state[3][c]);
                temp1 = mult(0x09, state[0][c]) ^ mult(0x0e, state[1][c]) ^ mult(0x0b, state[2][c]) ^ mult(0x0d, state[3][c]);
                temp2 = mult(0x0d, state[0][c]) ^ mult(0x09, state[1][c]) ^ mult(0x0e, state[2][c]) ^ mult(0x0b, state[3][c]);
                temp3 = mult(0x0b, state[0][c]) ^ mult(0x0d, state[1][c]) ^ mult(0x09, state[2][c]) ^ mult(0x0e, state[3][c]);

                state[0][c] = temp0;
                state[1][c] = temp1;
                state[2][c] = temp2;
                state[3][c] = temp3;
            }
            return state;
        }
        private int[][] invShiftRows(int[][] state)
        {
            int temp1, temp2, temp3, i;

            temp1 = state[1][Nb - 1];
            for (i = Nb - 1; i > 0; i--)
            {
                state[1][i] = state[1][(i - 1) % Nb];
            }
            state[1][0] = temp1;

            temp1 = state[2][Nb - 1];
            temp2 = state[2][Nb - 2];
            for (i = Nb - 1; i > 1; i--)
            {
                state[2][i] = state[2][(i - 2) % Nb];
            }
            state[2][1] = temp1;
            state[2][0] = temp2;

            temp1 = state[3][Nb - 3];
            temp2 = state[3][Nb - 2];
            temp3 = state[3][Nb - 1];
            for (i = Nb - 1; i > 2; i--)
            {
                state[3][i] = state[3][(i - 3) % Nb];
            }
            state[3][0] = temp1;
            state[3][1] = temp2;
            state[3][2] = temp3;

            return state;
        }

        private int[][] invSubBytes(int[][] state)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < Nb; j++)
                {
                    state[i][j] = invSubWord(state[i][j]) & 0xFF;
                }
            }
            return state;
        }

        private static int invSubWord(int word)
        {
            int subWord = 0;
            for (int i = 24; i >= 0; i -= 8)
            {
                var temp = word << i;
                int input = (int)(((uint)(word << i)) >> 24);
                subWord |= AesHelper.rsBox[input] << (24 - i);
            }
            return subWord;
        }

        public static void PrintByteArray(byte[] bytes)
        {
            var sb = new StringBuilder("new byte[] { ");
            foreach (var b in bytes)
            {
                sb.Append(b + ", ");
            }
            sb.Append("}");
            Console.WriteLine(sb.ToString());
        }

        public static void PrintIntArray(int[] bytes)
        {
            var sb = new StringBuilder("new byte[] { ");
            foreach (var b in bytes)
            {
                sb.Append(b + ", ");
            }
            sb.Append("}");
            Console.WriteLine(sb.ToString());
        }
        private int[] expandKey()
        {
            int i = 0;
            var temp = 0;
            Console.WriteLine("Nk: " + Nk);
            Console.WriteLine("Nr: " + Nr);
            Console.WriteLine("Nb: " + Nb);
            while (i < Nk)
            {
                w[i] = 0x00000000;
                w[i] |= key[4 * i] << 24;
                w[i] |= key[4 * i + 1] << 16;
                w[i] |= key[4 * i + 2] << 8;
                w[i] |= key[4 * i + 3];
                i++;
            }
            i = Nk;
            while (i < Nb * (Nr + 1))
            {
                temp = w[i - 1];
                if (i % Nk == 0)
                {
                    temp = subWord(rotWord(temp)) ^ (AesHelper.rCon[i / Nk] << 24);
                }
                else if (Nk > 6 && (i % Nk == 4))
                {
                    temp = subWord(temp);
                }
                else
                {
                }
                w[i] = w[i - Nk] ^ temp;
                i++;
            }
            return w;
        }
        private int[][] mixColumns(int[][] state)
        {
            int temp0, temp1, temp2, temp3;
            for (int c = 0; c < Nb; c++)
            {

                temp0 = mult(0x02, state[0][c]) ^ mult(0x03, state[1][c]) ^ state[2][c] ^ state[3][c];
                temp1 = state[0][c] ^ mult(0x02, state[1][c]) ^ mult(0x03, state[2][c]) ^ state[3][c];
                temp2 = state[0][c] ^ state[1][c] ^ mult(0x02, state[2][c]) ^ mult(0x03, state[3][c]);
                temp3 = mult(0x03, state[0][c]) ^ state[1][c] ^ state[2][c] ^ mult(0x02, state[3][c]);

                state[0][c] = temp0;
                state[1][c] = temp1;
                state[2][c] = temp2;
                state[3][c] = temp3;
            }
            return state;
        }

        private static int mult(int a, int b)
        {
            int sum = 0;
            while (a != 0)
            {
                if ((a & 1) != 0)
                {
                    sum = sum ^ b;
                }
                b = xtime(b);
                a = (int)((uint)a) >> 1;
            }
            return sum;
        }
        private static int rotWord(int word)
        {
            var temp1 = word << 8;
            var temp2 = (int)(((uint)(word & 0xFF000000)) >> 24);
            var result = temp1 | temp2;
            return result;
        }
        private int[][] shiftRows(int[][] state)
        {
            int temp1, temp2, temp3, i;

            temp1 = state[1][0];
            for (i = 0; i < Nb - 1; i++)
            {
                state[1][i] = state[1][(i + 1) % Nb];
            }
            state[1][Nb - 1] = temp1;

            temp1 = state[2][0];
            temp2 = state[2][1];
            for (i = 0; i < Nb - 2; i++)
            {
                state[2][i] = state[2][(i + 2) % Nb];
            }
            state[2][Nb - 2] = temp1;
            state[2][Nb - 1] = temp2;

            temp1 = state[3][0];
            temp2 = state[3][1];
            temp3 = state[3][2];
            for (i = 0; i < Nb - 3; i++)
            {
                state[3][i] = state[3][(i + 3) % Nb];
            }
            state[3][Nb - 3] = temp1;
            state[3][Nb - 2] = temp2;
            state[3][Nb - 1] = temp3;

            return state;
        }

        private int[][] subBytes(int[][] state)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < Nb; j++)
                {
                    state[i][j] = subWord(state[i][j]) & 0xFF;
                }
            }
            return state;
        }

        private static int subWord(int word)
        {
            int subWord = 0;
            for (int i = 24; i >= 0; i -= 8)
            {
                var temp = word << i;
                int input = (int)(((uint)(word << i)) >> 24);
                subWord |= AesHelper.sBox[input] << (24 - i);
            }
            return subWord;
        }

        private static int xtime(int b)
        {
            if ((b & 0x80) == 0)
            {
                return b << 1;
            }
            return (b << 1) ^ 0x11b;
        }

        private static byte[] xor(byte[] a, byte[] b)
        {
            byte[] result = new byte[Math.Min(a.Length, b.Length)];
            for (int j = 0; j < result.Length; j++)
            {
                int xor = a[j] ^ b[j];
                result[j] = (byte)(0xff & xor);
            }
            return result;
        }

        public byte[] ECB_encrypt(byte[] text)
        {
            MemoryStream output = new MemoryStream();
            for (int i = 0; i < text.Length; i += 16)
            {
                try
                {
                    var byteArray = encrypt(copyOfRange(text, i, i + 16));
                    output.Write(byteArray);
                }
                catch (IOException e)
                {
                    Console.WriteLine(e.Data);
                }
            }
            return output.ToArray();
        }

        public byte[] ECB_decrypt(byte[] text)
        {
            MemoryStream output = new MemoryStream();
            for (int i = 0; i < text.Length; i += 16)
            {
                try
                {
                    var byteArray = decrypt(copyOfRange(text, i, i + 16));
                    output.Write(byteArray);
                }
                catch (IOException e)
                {
                    Console.WriteLine(e.Data);
                }
            }
            return output.ToArray();
        }

        public byte[] CBC_encrypt(byte[] text)
        {
            byte[] previousBlock = null;
            MemoryStream output = new MemoryStream();
            for (int i = 0; i < text.Length; i += 16)
            {
                byte[] part = copyOfRange(text, i, i + 16);
                try
                {
                    if (previousBlock == null) previousBlock = iv;
                    part = xor(previousBlock, part);
                    previousBlock = encrypt(part);
                    output.Write(previousBlock);
                }
                catch (IOException e)
                {
                    Console.WriteLine(e.Data);
                }
            }
            return output.ToArray();
        }

        public byte[] CBC_decrypt(byte[] text)
        {
            byte[] previousBlock = null;
            MemoryStream output = new MemoryStream();
            for (int i = 0; i < text.Length; i += 16)
            {
                byte[] part = copyOfRange(text, i, i + 16);
                byte[] tmp = decrypt(part);
                try
                {
                    if (previousBlock == null) previousBlock = iv;
                    tmp = xor(previousBlock, tmp);
                    previousBlock = part;
                    output.Write(tmp);
                }
                catch (IOException e)
                {
                    Console.WriteLine(e.Data);
                }
            }
            return output.ToArray();
        }
        byte[] copyOfRange(byte[] src, int start, int end)
        {
            int len = end - start;
            byte[] dest = new byte[len];
            Array.Copy(src, start, dest, 0, len);
            return dest;
        }
    }
}