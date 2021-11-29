namespace Aes_Bin_Tam
{
    public class Aes
    {
        private int currentRound;
        private static int Nb = 4;
        private int Nr;
        private int Nk;
        private int[,,] state;
        private int[] w;
        private int[] key;
        private byte[] iv;

        public Aes(byte[] key)
        {
            init(key, null);
        }

        public Aes(byte[] key, byte[] iv)
        {
            init(key, iv);
        }


        private void init(byte[] key, byte[] iv)
        {
            this.iv = iv;
            this.key = new int[key.Length];
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


            var state = new int[2, 4, Nb];
            w = new int[Nb * (Nr + 1)];
            expandKey();
        }
        private int[,] addRoundKey(int[,] s, int round)
        {
            for (int c = 0; c < Nb; c++)
            {
                for (int r = 0; r < 4; r++)
                {
                    s[r,c] = s[r,c] ^ ((w[round * Nb + c] << (r * 8)) >> 24);
                }
            }
            return s;
        }
        private int[,] cipher(int[,] input, int[,] output)
        {
            for (int i = 0; i < input.Length; i++)
            {
                for (int j = 0; j < input.Length; j++)
                {
                    output[i,j] = input[i,j];
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

        private int[,] decipher(int[,] input, int[,] output)
        {
            for (int i = 0; i < input.Length; i++)
            {
                for (int j = 0; j < input.Length; j++)
                {
                    output[i,j] = input[i,j];
                }
            }
            currentRound = Nr;
            addRoundKey(output, currentRound);

            for (currentRound = Nr - 1; currentRound > 0; currentRound--)
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
                    state[0, j, i] = text[i * Nb + j] & 0xff;
                }
            }

            decipher(convertTo2Array(0,state,4,Nb), convertTo2Array(1,state,4,Nb));
            for (int i = 0; i < Nb; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    output[i * Nb + j] = (byte)(state[1, j, i] & 0xff);
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
                    state[0, j, i] = text[i * Nb + j] & 0xff;
                }
            }

            decipher(convertTo2Array(0,state,4,Nb), convertTo2Array(1,state,4,Nb));
            for (int i = 0; i < Nb; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    output[i * Nb + j] = (byte)(state[1, j, i] & 0xff);
                }
            }
            return output;
        }

        private int [,] convertTo2Array(int mode,int[,,] state,int row,int columns){
            int [,] result = new int[row,columns];
            for(int i = 0;i<row;i++){
                for(int j = 0;j<columns;j++)
                result[i,j] = state[mode,i,j];
            }
            return result;
        }

        private int[,] invMixColumns(int[,] state)
        {
            int temp0, temp1, temp2, temp3;
            for (int c = 0; c < Nb; c++)
            {
                temp0 = mult(0x0e, state[0,c]) ^ mult(0x0b, state[1,c]) ^ mult(0x0d, state[2,c]) ^ mult(0x09, state[3,c]);
                temp1 = mult(0x09, state[0,c]) ^ mult(0x0e, state[1,c]) ^ mult(0x0b, state[2,c]) ^ mult(0x0d, state[3,c]);
                temp2 = mult(0x0d, state[0,c]) ^ mult(0x09, state[1,c]) ^ mult(0x0e, state[2,c]) ^ mult(0x0b, state[3,c]);
                temp3 = mult(0x0b, state[0,c]) ^ mult(0x0d, state[1,c]) ^ mult(0x09, state[2,c]) ^ mult(0x0e, state[3,c]);

                state[0,c] = temp0;
                state[1,c] = temp1;
                state[2,c] = temp2;
                state[3,c] = temp3;
            }
            return state;
        }
        private int[,] invShiftRows(int[,] state)
        {
            int temp1, temp2, temp3, i;

            temp1 = state[1,Nb - 1];
            for (i = Nb - 1; i > 0; i--)
            {
                state[1,i] = state[1,(i - 1) % Nb];
            }
            state[1,0] = temp1;

            temp1 = state[2,Nb - 1];
            temp2 = state[2,Nb - 2];
            for (i = Nb - 1; i > 1; i--)
            {
                state[2,i] = state[2,(i - 2) % Nb];
            }
            state[2,1] = temp1;
            state[2,0] = temp2;

            temp1 = state[3,Nb - 3];
            temp2 = state[3,Nb - 2];
            temp3 = state[3,Nb - 1];
            for (i = Nb - 1; i > 2; i--)
            {
                state[3,i] = state[3,(i - 3) % Nb];
            }
            state[3,0] = temp1;
            state[3,1] = temp2;
            state[3,2] = temp3;

            return state;
        }

        private int[,] invSubBytes(int[,] state)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < Nb; j++)
                {
                    state[i,j] = invSubWord(state[i,j]) & 0xFF;
                }
            }
            return state;
        }

        private static int invSubWord(int word)
        {
            int subWord = 0;
            for (int i = 24; i >= 0; i -= 8)
            {
                int input = word << i >> 24;
                subWord |= AesHelper.rsBox[input] << (24 - i);
            }
            return subWord;
        }
        private int[] expandKey()
        {
            int temp, i = 0;
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
        private int[,] mixColumns(int[,] state)
        {
            int temp0, temp1, temp2, temp3;
            for (int c = 0; c < Nb; c++)
            {

                temp0 = mult(0x02, state[0,c]) ^ mult(0x03, state[1,c]) ^ state[2,c] ^ state[3,c];
                temp1 = state[0,c] ^ mult(0x02, state[1,c]) ^ mult(0x03, state[2,c]) ^ state[3,c];
                temp2 = state[0,c] ^ state[1,c] ^ mult(0x02, state[2,c]) ^ mult(0x03, state[3,c]);
                temp3 = mult(0x03, state[0,c]) ^ state[1,c] ^ state[2,c] ^ mult(0x02, state[3,c]);

                state[0,c] = temp0;
                state[1,c] = temp1;
                state[2,c] = temp2;
                state[3,c] = temp3;
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
                a = a >> 1;
            }
            return sum;
        }
        private static int rotWord(int word)
        {
            return (int)((word << 8) | ((word & 0xFF000000) >> 24));
        }
        private int[,] shiftRows(int[,] state)
        {
            int temp1, temp2, temp3, i;

            temp1 = state[1,0];
            for (i = 0; i < Nb - 1; i++)
            {
                state[1,i] = state[1,(i + 1) % Nb];
            }
            state[1,Nb - 1] = temp1;

            temp1 = state[2,0];
            temp2 = state[2,1];
            for (i = 0; i < Nb - 2; i++)
            {
                state[2,i] = state[2,(i + 2) % Nb];
            }
            state[2,Nb - 2] = temp1;
            state[2,Nb - 1] = temp2;

            temp1 = state[3,0];
            temp2 = state[3,1];
            temp3 = state[3,2];
            for (i = 0; i < Nb - 3; i++)
            {
                state[3,i] = state[3,(i + 3) % Nb];
            }
            state[3,Nb - 3] = temp1;
            state[3,Nb - 2] = temp2;
            state[3,Nb - 1] = temp3;

            return state;
        }

        private int[,] subBytes(int[,] state)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < Nb; j++)
                {
                    state[i,j] = subWord(state[i,j]) & 0xFF;
                }
            }
            return state;
        }

        private static int subWord(int word)
        {
            int subWord = 0;
            for (int i = 24; i >= 0; i -= 8)
            {
                int input = word << i >> 24;
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
                    output.Write(encrypt(copyOfRange(text, i, i + 16)));
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
                    output.Write(decrypt(copyOfRange(text, i, i + 16)));
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