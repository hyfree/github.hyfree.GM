﻿using System;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;

namespace github.hyfree.GM.SM2
{
    public class SM2Factory
    {
        public static SM2Factory Instance
        {
            get
            {
                return new SM2Factory();
            }

        }
        public static SM2Factory InstanceTest
        {
            get
            {
                return new SM2Factory();
            }

        }
        /// <summary>
        /// 国密曲线参数
        /// </summary>
        public static readonly string[] sm2_param = {
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",// p,0
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",// a,1
            "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",// b,2
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",// n,3
            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",// gx,4
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0" // gy,5
        };

        public string[] ecc_param = sm2_param;

        public readonly BigInteger ecc_p;
        public readonly BigInteger ecc_a;
        public readonly BigInteger ecc_b;
        public readonly BigInteger ecc_n;
        public readonly BigInteger ecc_gx;
        public readonly BigInteger ecc_gy;

        public readonly ECCurve ecc_curve;
        public readonly ECPoint ecc_point_g;

        public readonly ECDomainParameters ecc_bc_spec;

        public readonly ECKeyPairGenerator ecc_key_pair_generator;

        private SM2Factory()
        {
            ecc_param = sm2_param;

            ECFieldElement ecc_gx_fieldelement;
            ECFieldElement ecc_gy_fieldelement;

            ecc_p = new BigInteger(ecc_param[0], 16);
            ecc_a = new BigInteger(ecc_param[1], 16);
            ecc_b = new BigInteger(ecc_param[2], 16);
            ecc_n = new BigInteger(ecc_param[3], 16);
            ecc_gx = new BigInteger(ecc_param[4], 16);
            ecc_gy = new BigInteger(ecc_param[5], 16);


            ecc_gx_fieldelement = new FpFieldElement(ecc_p, ecc_gx);
            ecc_gy_fieldelement = new FpFieldElement(ecc_p, ecc_gy);

            ecc_curve = new FpCurve(ecc_p, ecc_a, ecc_b);
            ecc_point_g = new FpPoint(ecc_curve, ecc_gx_fieldelement, ecc_gy_fieldelement);

            ecc_bc_spec = new ECDomainParameters(ecc_curve, ecc_point_g, ecc_n);

            ECKeyGenerationParameters ecc_ecgenparam;
            ecc_ecgenparam = new ECKeyGenerationParameters(ecc_bc_spec, new SecureRandom());

            ecc_key_pair_generator = new ECKeyPairGenerator();
            ecc_key_pair_generator.Init(ecc_ecgenparam);
        }
        public SM2Signature Sm2Sign(byte[] md, BigInteger userD, ECPoint userKey)
        {
            BigInteger e = new BigInteger(1, md);
            BigInteger k = null;
            ECPoint kp = null;
            BigInteger r = null;
            BigInteger s = null;
            do
            {
                do
                {
                    // 正式环境
                    AsymmetricCipherKeyPair keypair = ecc_key_pair_generator.GenerateKeyPair();
                    ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters)keypair.Private;
                    ECPublicKeyParameters ecpub = (ECPublicKeyParameters)keypair.Public;
                    k = ecpriv.D;
                    kp = ecpub.Q;
                    //System.out.println("BigInteger:" + k + "\nECPoint:" + kp);

                    //System.out.println("计算曲线点X1: "+ kp.getXCoord().toBigInteger().toString(16));
                    //System.out.println("计算曲线点Y1: "+ kp.getYCoord().toBigInteger().toString(16));
                    //System.out.println("");
                    // r
                    r = e.Add(kp.XCoord.ToBigInteger());
                    r = r.Mod(this.ecc_n);
                } while (r.Equals(BigInteger.Zero) || r.Add(k).Equals(this.ecc_n) || r.ToString(16).Length != 64);

                // (1 + dA)~-1
                BigInteger da_1 = userD.Add(BigInteger.One);
                da_1 = da_1.ModInverse(this.ecc_n);
                // s
                s = r.Multiply(userD);
                s = k.Subtract(s).Mod(this.ecc_n);
                s = da_1.Multiply(s).Mod(this.ecc_n);
            } while (s.Equals(BigInteger.Zero) || s.ToString(16).Length != 64);
            var sM2Signature = new SM2Signature
            {
                R = r.ToByteArray32(),
                S = s.ToByteArray32()
            };
            return sM2Signature;
        }

        public SM2Result Sm2Verify(byte[] md, ECPoint userKey, BigInteger r, BigInteger s)
        {
            var sm2Result=new SM2Result();
          
            BigInteger e = new BigInteger(1, md);
            BigInteger t = r.Add(s).Mod(this.ecc_n);
            if (t.Equals(BigInteger.Zero))
            {
                return sm2Result;
            }
            else
            {
                ECPoint x1y1 = ecc_point_g.Multiply(s);
                //System.out.println("计算曲线点X0: "+ x1y1.normalize().getXCoord().toBigInteger().toString(16));
                //System.out.println("计算曲线点Y0: "+ x1y1.normalize().getYCoord().toBigInteger().toString(16));
                //System.out.println("");

                x1y1 = x1y1.Add(userKey.Multiply(t));
                //System.out.println("计算曲线点X1: "+ x1y1.normalize().getXCoord().toBigInteger().toString(16));
                //System.out.println("计算曲线点Y1: "+ x1y1.normalize().getYCoord().toBigInteger().toString(16));
                //System.out.println("");
                sm2Result.R = e.Add(x1y1.Normalize().XCoord.ToBigInteger()).Mod(this.ecc_n);
                //System.out.println("R: " + sm2Result.R.toString(16));
                return sm2Result;
            }
        }
        public virtual byte[] Sm2GetZ(byte[] userId, ECPoint userKey)
        {
            SM3Digest sm3 = new SM3Digest();
            byte[] p;
            // userId length
            int len = userId.Length * 8;
            sm3.Update((byte)(len >> 8 & 0x00ff));
            sm3.Update((byte)(len & 0x00ff));

            // userId
            sm3.BlockUpdate(userId, 0, userId.Length);

            // a,b
            p = ecc_a.ToByteArray32();
            sm3.BlockUpdate(p, 0, p.Length);
            p = ecc_b.ToByteArray32();
            sm3.BlockUpdate(p, 0, p.Length);
            // gx,gy
            p = ecc_gx.ToByteArray32();
            sm3.BlockUpdate(p, 0, p.Length);
            p = ecc_gy.ToByteArray32();
            sm3.BlockUpdate(p, 0, p.Length);

            // x,y
            p = userKey.Normalize().XCoord.ToBigInteger().ToByteArray32();
            sm3.BlockUpdate(p, 0, p.Length);
            p = userKey.Normalize().YCoord.ToBigInteger().ToByteArray32();
            sm3.BlockUpdate(p, 0, p.Length);

            // Z
            byte[] md = new byte[sm3.GetDigestSize()];
            sm3.DoFinal(md, 0);

            return md;
        }

    }
}
