/******************************************************
 *     ROMVault2 is written by Gordon J.              *
 *     Contact gordon@romvault.com                    *
 *     Copyright 2014                                 *
 ******************************************************/

using System.IO;
using RomVaultX.SupportedFiles.Files;

namespace ROMVault2.SupportedFiles.Files
{
    public static class UnCompFiles
    {
        private const int Buffersize = 4096 * 1024;
        private static readonly byte[] Buffer0;
        private static readonly byte[] Buffer1;

        static UnCompFiles()
        {
            Buffer0 = new byte[Buffersize];
            Buffer1 = new byte[Buffersize];
        }

        public static int CheckSumRead(string filename, bool testDeep, out byte[] crc, out byte[] bMD5, out byte[] bSHA1,out long sizeAdjust)
        {
            bMD5 = null;
            bSHA1 = null;
            crc = null;

            Stream ds = null;
            ThreadLoadBuffer lbuffer = null;
            ThreadCRC tcrc32 = null;
            ThreadMD5 tmd5 = null;
            ThreadSHA1 tsha1 = null;
            bool match = false;

            sizeAdjust = 0;
            try
            {
                int errorCode = IO.FileStream.OpenFileRead(filename, out ds);
                if (errorCode != 0)
                    return errorCode;

                lbuffer = new ThreadLoadBuffer(ds);
                tcrc32 = new ThreadCRC();
                if (testDeep)
                {
                    tmd5 = new ThreadMD5();
                    tsha1 = new ThreadSHA1();
                }

                long sizetogo = ds.Length;

                // Pre load the first buffer0
                int sizeNext = sizetogo > Buffersize ? Buffersize : (int)sizetogo;
                ds.Read(Buffer0, 0, sizeNext);
                int sizebuffer = sizeNext;
                sizetogo -= sizeNext;
                bool whichBuffer = true;

                // Check for header no-intro style
                byte[] cmp1 = new byte[] { 0x41, 0x54, 0x41, 0x52, 0x49, 0x37, 0x38, 0x30, 0x30 };
                byte[] cmp60 = new byte[] { 0x00,0x00,0x00,0x00,0x41,0x43,0x54,0x55,0x41,0x4C,0x20,0x43,0x41,0x52,0x54,0x20,0x44,0x41,0x54,0x41,0x20,0x53,0x54,0x41,0x52,0x54,0x53,0x20,0x48,0x45,0x52,0x45 };

                match = true;
                for (int a=0;a<cmp1.Length;a++)
                {
                    if (Buffer0[1+a]!=cmp1[a])
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                {
                    for (int a = 0; a < cmp60.Length; a++)
                    {
                        if (Buffer0[0x60 + a] != cmp60[a])
                        {
                            match = false;
                            break;
                        }
                    }
                }

                if (match)
                {
                    ReportError.LogOut("TADA");
                    sizebuffer -= 0x80; // shrink the size of the buffer
                    sizeAdjust = -0x80;
                    System.Array.Copy(Buffer0, 0x80, Buffer0, 0, sizebuffer);
                }

                while (sizebuffer > 0 && !lbuffer.errorState)
                {
                    sizeNext = sizetogo > Buffersize ? Buffersize : (int)sizetogo;

                    if (sizeNext > 0)
                        lbuffer.Trigger(whichBuffer ? Buffer1 : Buffer0, sizeNext);

                    byte[] buffer = whichBuffer ? Buffer0 : Buffer1;
                    tcrc32.Trigger(buffer, sizebuffer);
                    tmd5?.Trigger(buffer, sizebuffer);
                    tsha1?.Trigger(buffer, sizebuffer);

                    if (sizeNext > 0)
                        lbuffer.Wait();
                    tcrc32.Wait();
                    tmd5?.Wait();
                    tsha1?.Wait();

                    sizebuffer = sizeNext;
                    sizetogo -= sizeNext;
                    whichBuffer = !whichBuffer;
                }

                lbuffer.Finish();
                tcrc32.Finish();
                tmd5?.Finish();
                tsha1?.Finish();

                ds.Close();
            }
            catch
            {
                ds?.Close();
                lbuffer?.Dispose();
                tcrc32?.Dispose();
                tmd5?.Dispose();
                tsha1?.Dispose();

                return 0x17; // need to remember what this number is for
            }

            if (lbuffer.errorState)
            {
                ds?.Close();
                lbuffer?.Dispose();
                tcrc32?.Dispose();
                tmd5?.Dispose();
                tsha1?.Dispose();

                return 0x17; // need to remember what this number is for
            }

            crc = tcrc32.Hash;
            if (testDeep)
            {
                bMD5 = tmd5.Hash;
                bSHA1 = tsha1.Hash;
            }

            lbuffer.Dispose();
            tcrc32.Dispose();
            tmd5?.Dispose();
            tsha1?.Dispose();
            
            return 0;
        }
    }
}
