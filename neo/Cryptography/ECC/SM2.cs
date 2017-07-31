using System;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace Neo.Cryptography.ECC
{
    /// <summary>
    /// provide China National SM2 crypto algorithm.
    /// </summary>
    public class SM2
    {
        private readonly byte[] privateKey;
        private readonly ECPoint publicKey;
        private readonly ECCurve curve;

        /// <summary>
        /// Create new sm2 object according by privatekey, the object can be used to create a signature.
        /// </summary>
        /// <param name="privateKey">privateKey</param>
        /// <param name="curve">curve param</param>
        public SM2(byte[] privateKey, ECCurve curve)
            : this(curve.G * privateKey)
        {
            this.privateKey = privateKey;
        }

        /// <summary>
        /// Create new sm2 object according by privatekey, the object can be used to verify a signature.
        /// </summary>
        /// <param name="publicKey">公钥</param>
        public SM2(ECPoint publicKey)
        {
            this.publicKey = publicKey;
            this.curve = publicKey.Curve;
        }

        private BigInteger CalculateE(BigInteger n, byte[] message)
        {
            int messageBitLength = message.Length * 8;
            BigInteger trunc = new BigInteger(message.Reverse().Concat(new byte[1]).ToArray());
            if (n.GetBitLength() < messageBitLength)
            {
                trunc >>= messageBitLength - n.GetBitLength();
            }
            return trunc;
        }

        /// <summary>
        /// Create sm2 signature
        /// </summary>
        /// <param name="message">message to be signed</param>
        /// <returns>sm2 signature（r,s）</returns>
        public BigInteger[] GenerateSignature(byte[] message)
        {
            if (privateKey == null) throw new InvalidOperationException();

            BigInteger e = new BigInteger(message.Reverse().Concat(new byte[1]).ToArray());
            BigInteger d = new BigInteger(privateKey.Reverse().Concat(new byte[1]).ToArray());
            BigInteger r, s;

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                do
                {
                    BigInteger k;
                    do
                    {
                        do
                        {
                            k = rng.NextBigInteger(curve.N.GetBitLength());
                        }
                        while (k.Sign == 0 || k.CompareTo(curve.N) >= 0);

                        ECPoint p = ECPoint.Multiply(curve.G, k);
                        r = (e + p.X.Value).Mod(curve.N);
                    }
                    while (r.Sign == 0);

                    if (r.Sign < 0) r += curve.N;

                    BigInteger t1 = (d + 1).ModInverse(curve.N);
                    BigInteger t2 = (k - r * d).Mod(curve.N);

                    s = (t1 * t2).Mod(curve.N);
                }
                while (s.Sign == 0);

                // r and s must between 1 and N - 1
                if (r.Sign < 0) r += curve.N;
                if (s.Sign < 0) s += curve.N;
            }
            return new BigInteger[] { r, s };
        }

        private static ECPoint SumOfTwoMultiplies(ECPoint P, BigInteger k, ECPoint Q, BigInteger l)
        {
            int m = Math.Max(k.GetBitLength(), l.GetBitLength());
            ECPoint Z = P + Q;
            ECPoint R = P.Curve.Infinity;
            for (int i = m - 1; i >= 0; --i)
            {
                R = R.Twice();
                if (k.TestBit(i))
                {
                    if (l.TestBit(i))
                        R = R + Z;
                    else
                        R = R + P;
                }
                else
                {
                    if (l.TestBit(i))
                        R = R + Q;
                }
            }
            return R;
        }

        /// <summary>
        /// verify a signature
        /// </summary>
        /// <param name="message">message to be verified</param>
        /// <param name="r">r of sm2 signature</param>
        /// <param name="s">s of sm2 signature</param>
        /// <returns>result</returns>
        public bool VerifySignature(byte[] message, BigInteger r, BigInteger s)
        {
            if (r.Sign < 1 || s.Sign < 1 || r > curve.N || s > curve.N)
            {
                return false;
            }

            BigInteger t = (r + s).Mod(curve.N);
            ECPoint point = SumOfTwoMultiplies(curve.G, s, publicKey, t);

            BigInteger e = new BigInteger(message.Reverse().Concat(new byte[1]).ToArray());
            BigInteger R = (e + point.X.Value).Mod(curve.N);

            return 0 == R.CompareTo(r);
        }
    }
}
