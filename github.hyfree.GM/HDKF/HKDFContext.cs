using System;
using System.Collections.Generic;
using System.Text;

namespace github.hyfree.GM.HDKF
{

    public class HKDFContext
    {
        const int  SHAMaxHashSize=32;
        int whichSha;

      

        int hashSize;

         byte[] prk=new byte[SHAMaxHashSize];

        int Computed;

        int Corrupted;
    }
}
