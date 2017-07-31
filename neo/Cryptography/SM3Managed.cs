using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

namespace Neo.Cryptography
{
    [ComVisible(true)]
    public class SM3Managed : HashAlgorithm
    {
        private uint[] total;
        private uint[] state;
        private byte[] buffer;

        public const uint SM3_DIGEST_LEN = 32;
        public const uint MSG_BLOCK_LEN = 64;

        public const int T1 = 0x79cc4519;
        public const int T2 = 0x7a879d8a;

        private static byte[] sm3Padding = {
                0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };

        public override int HashSize => 256;

        //
        // public constructors
        //
        public SM3Managed()
        {
            total = new uint[2];
            state = new uint[8];
            buffer = new byte[MSG_BLOCK_LEN];

            InitializeState();
        }

        //
        // public methods
        //
        public override void Initialize()
        {
            InitializeState();

            // Zeroize potentially sensitive information.
            Array.Clear(buffer, 0, buffer.Length);
        }

        [System.Security.SecuritySafeCritical]  // auto-generated
        protected override void HashCore(byte[] rgb, int ibStart, int cbSize)
        {
            _HashData(rgb, ibStart, cbSize);
        }

        [System.Security.SecuritySafeCritical]  // auto-generated
        protected override byte[] HashFinal()
        {
            return _EndHash();
        }

        //
        // private methods
        //
        private void InitializeState()
        {
            total[0] = 0;
            total[1] = 0;

            state[0] = 0x7380166f;
            state[1] = 0x4914b2b9;
            state[2] = 0x172442d7;
            state[3] = 0xda8a0600;
            state[4] = 0xa96f30bc;
            state[5] = 0x163138aa;
            state[6] = 0xe38dee4d;
            state[7] = 0xb0fb0e4e;
        }

        private unsafe void _HashData(byte[] partIn, int ibStart, int cbSize)
        {
            uint left, fill;
            if (cbSize <= 0)
                return;

            uint len = (uint)cbSize;
            uint iv = (uint)ibStart;

            left = total[0] & 0x3F;
            fill = 64 - left;

            total[0] += len;
            total[0] &= 0xFFFFFFFF;

            if (total[0] < len)
                total[1]++;

            if (left != 0 && (len >= fill))
            {
                Buffer.BlockCopy(partIn, (int)iv, buffer, (int)left, (int)fill);
                Sm3Process(buffer);
                len -= fill;
                iv += fill;
                left = 0;
            }
            while (len >= MSG_BLOCK_LEN)
            {
                byte[] processTmp = new byte[MSG_BLOCK_LEN];
                Buffer.BlockCopy(partIn, (int)iv, processTmp, 0, (int)MSG_BLOCK_LEN);

                Sm3Process(processTmp);
                len -= MSG_BLOCK_LEN;
                iv += MSG_BLOCK_LEN;
            }
            if (len != 0)
            {
                Buffer.BlockCopy(partIn, (int)iv, buffer, (int)left, (int)len);
            }
        }

        private byte[] _EndHash()
        {
            uint last, padNum;
            uint high, low;
            byte[] msgLen = new byte[8];
            byte[] hash = new byte[SM3_DIGEST_LEN];

            high = (total[0] >> 29) | (total[1] << 3);
            low = (total[0] << 3);

            msgLen[3] = (byte)(high & 0xff);
            msgLen[2] = (byte)((high >> 8) & 0xff);
            msgLen[1] = (byte)((high >> 16) & 0xff);
            msgLen[0] = (byte)((high >> 24) & 0xff);

            msgLen[7] = (byte)(low & 0xff);
            msgLen[6] = (byte)((low >> 8) & 0xff);
            msgLen[5] = (byte)((low >> 16) & 0xff);
            msgLen[4] = (byte)((low >> 24) & 0xff);

            last = total[0] & 0x3F;
            padNum = (last < 56) ? (56 - last) : (120 - last);

            _HashData(sm3Padding, 0, (int)padNum);
            _HashData(msgLen, 0, 8);

            for (int i = 0; i < 8; i++)
            {
                hash[4 * i] = (byte)((state[i] >> 24) & 0xff);
                hash[4 * i + 1] = (byte)((state[i] >> 16) & 0xff);
                hash[4 * i + 2] = (byte)((state[i] >> 8) & 0xff);
                hash[4 * i + 3] = (byte)((state[i]) & 0xff);
            }

            return hash;
        }

        private static uint S(uint x, int n)
        {
            return ((x << n) | (x >> (32 - n)));
        }

        private static uint P0(uint x)
        {
            return (x ^ S(x, 9) ^ S(x, 17));
        }

        private static uint P1(uint x)
        {
            return (x ^ S(x, 15) ^ S(x, 23));
        }

        private static uint PW(uint[] W, int t, ref uint temp)
        {
            temp = W[t - 16] ^ W[t - 9] ^ (S(W[t - 3], 15));
            return P1(temp) ^ W[t - 6] ^ (S(W[t - 13], 7));
        }

        private static uint FF1(uint x, uint y, uint z)
        {
            return (x ^ y ^ z);
        }

        private static uint FF2(uint x, uint y, uint z)
        {
            return ((x & y) | (x & z) | (y & z));
        }

        private static uint GG1(uint x, uint y, uint z)
        {
            return (x ^ y ^ z);
        }

        private static uint GG2(uint x, uint y, uint z)
        {
            return ((x & y) | ((~x) & z));
        }

        private void Sm3Process(byte[] data)
        {
            uint temp = 0;
            uint A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2;
            uint[] W = new uint[68];
            uint[] WP = new uint[68];
            int i, j, k;

            for (i = 0; i < 16; i++)
            {
                W[i] = (uint)((data[4 * i + 3]) | (data[4 * i + 2] << 8) |
                    (data[4 * i + 1] << 16) | (data[4 * i] << 24));
            }

            W[16] = PW(W, 16, ref temp);
            W[17] = PW(W, 17, ref temp);
            W[18] = PW(W, 18, ref temp);
            W[19] = PW(W, 19, ref temp);

            A = state[0];
            B = state[1];
            C = state[2];
            D = state[3];
            E = state[4];
            F = state[5];
            G = state[6];
            H = state[7];

            for (i = 0; i < 16; i++)
            {
                WP[i] = W[i] ^ W[i + 4];

                SS1 = S(A, 12) + E + S(T1, i);
                SS1 = S(SS1, 7);
                SS2 = SS1 ^ S(A, 12);
                TT1 = FF1(A, B, C) + D + SS2 + WP[i];
                TT2 = GG1(E, F, G) + H + SS1 + W[i];
                D = C;
                C = S(B, 9);
                B = A;
                A = TT1;
                H = G;
                G = S(F, 19);
                F = E;
                E = P0(TT2);
            }

            for (i = 16; i < 64; i++)
            {
                k = i + 4;
                W[k] = PW(W, k, ref temp);
                WP[i] = W[i] ^ W[i + 4];

                j = i % 32;

                SS1 = S(A, 12) + E + S(T2, j);
                SS1 = S(SS1, 7);
                SS2 = SS1 ^ S(A, 12);
                TT1 = FF2(A, B, C) + D + SS2 + WP[i];
                TT2 = GG2(E, F, G) + H + SS1 + W[i];
                D = C;
                C = S(B, 9);
                B = A;
                A = TT1;
                H = G;
                G = S(F, 19);
                F = E;
                E = P0(TT2);
            }

            state[0] ^= A;
            state[1] ^= B;
            state[2] ^= C;
            state[3] ^= D;
            state[4] ^= E;
            state[5] ^= F;
            state[6] ^= G;
            state[7] ^= H;
        }
    }
}

