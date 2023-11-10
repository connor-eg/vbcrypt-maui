using System.Security.Cryptography;
using System.Text;

namespace Core;

internal class CryptHandler : IDisposable
{
    private readonly SymmetricAlgorithm CryptAlgorithmInstance;
    private readonly HashAlgorithm HashAlgorithmInstance;

    private static readonly Random StringGeneratorRandom = new();

    public CryptHandler(SymmetricAlgorithm CryptAlgorithmInstance, HashAlgorithm HashAlgorithmInstance)
    {
        this.CryptAlgorithmInstance = CryptAlgorithmInstance;
        this.HashAlgorithmInstance = HashAlgorithmInstance;
    }

    // This class is meant to be managed by the using keyword.
    public void Dispose()
    {
        GC.SuppressFinalize(this);
        CryptAlgorithmInstance.Clear();
        HashAlgorithmInstance.Clear();
    }

    // Hanles improper handling of this class
    ~CryptHandler()
    {
        CryptAlgorithmInstance.Clear();
        HashAlgorithmInstance.Clear();
    }

    public void HashAndSetKey(byte[] bytes)
    {
        CryptAlgorithmInstance.Key = HashAlgorithmInstance.ComputeHash(bytes);
    }

    public void Decrypt(string[] files, bool deleteOnFinish = false)
    {
        if (files.Length == 0) return;
        foreach (string file in files)
        {
            if (!File.Exists(file))
            {
                Console.WriteLine($"Cannot find/access file {file}");
                continue;
            }

            Console.Write($"Decrypting {file}... ");

            bool hasVbcrExt = file.EndsWith(".vbcr"); // This is called "terse name" when really it should be called "correct extension."
            string outFileName = ""; // This has to be way out here for error handling later.

            try
            {
                using (FileStream inStream = File.OpenRead(file))
                {
                    // Recover the IV, which was written in plaintext to the first 16 bytes of the file.
                    byte[] recoveredIV = new byte[16];
                    inStream.ReadExactly(recoveredIV, 0, 16);
                    CryptAlgorithmInstance.IV = recoveredIV;

                    using CryptoStream cStream = new(inStream, CryptAlgorithmInstance.CreateDecryptor(), CryptoStreamMode.Read);

                    //Attempt to recover the eight null-bytes that serve as a password check (quick password check)
                    byte[] checksumBytes = new byte[8];
                    cStream.ReadExactly(checksumBytes, 0, 8);
                    for (int i = 0; i < 8; i++)
                    {
                        if (checksumBytes[i] != 0)
                        {
                            throw new UnauthorizedAccessException("The password provided was incorrect.");
                        }
                    }

                    //Recover the size of the original file name and interpret.
                    byte[] origNameSizeBytes = new byte[4];
                    cStream.ReadExactly(origNameSizeBytes, 0, 4);
                    int origNameSize = BitConverter.ToInt32(origNameSizeBytes);
                    if (origNameSize > 0)
                    {
                        byte[] origNameBytes = new byte[origNameSize];
                        // Fun fact: there's this really funny interpretation of "reading" in C#'s CryptoStream where when you want to read N
                        // bytes into a buffer, it just quits after reading between 1 and N bytes. It looks like they had to add a "ReadExactly" method
                        // if you want to actually read exactly N bytes. Brilliant.
                        cStream.ReadExactly(origNameBytes, 0, origNameSize);
                        outFileName = Encoding.UTF8.GetString(origNameBytes);
                    }
                    else
                    {
                        outFileName = hasVbcrExt ? $"{file[..^4]}" : $"{file}.decrypted";
                    }

                    // Now we know the file name we want to use.
                    using FileStream outStream = File.OpenWrite(outFileName);

                    //Get the rest of the data from the file from this point.
                    cStream.CopyTo(outStream);
                    outStream.Flush();
                    cStream.Clear();
                    Console.WriteLine(hasVbcrExt ? $"done. Saved as {outFileName}" : $"done. Remember to remove '.decrypted' from the resulting file {outFileName}");
                }
                if (deleteOnFinish) File.Delete(file);
            }
            catch (EndOfStreamException)
            {
                Console.Write("failed. Reason: this file is too small to contain any encrypted data.");
            }
            catch (Exception e)
            {
                Console.Write("failed. Reason: ");
                Console.WriteLine(e.Message);
                if (File.Exists(outFileName)) File.Delete(outFileName);
            }
        }
    }

    public void Encrypt(string[] files, bool deleteOnFinish = false, bool obfuscateNames = false)
    {
        if (files.Length == 0) return;
        Span<byte> zeroFill = stackalloc byte[8];
        zeroFill.Clear(); // Not actually sure if this is necessary but it never hurts to be sure.
        foreach (string file in files)
        {
            if (!File.Exists(file))
            {
                Console.WriteLine($"Cannot find file {file}...");
                continue;
            }

            Console.Write($"Encrypting {file}... ");

            CryptAlgorithmInstance.GenerateIV();

            string outFileName = $"{file}.vbcr";
            if (obfuscateNames)
            {
                do
                {
                    outFileName = $"{GenerateRandomString(12)}.vbcr";
                } while (File.Exists(outFileName)); // Handling the extremely low odds of a name collision.
            }
            byte[] oldNameBytes = obfuscateNames ? Encoding.UTF8.GetBytes(Path.GetFileName(file)) : Array.Empty<byte>();
            byte[] sizeOfBytes = BitConverter.GetBytes(oldNameBytes.Length);

            try
            {
                using (FileStream inStream = File.OpenRead(file))
                {
                    using FileStream outStream = File.OpenWrite(outFileName);
                    using CryptoStream cStream = new(outStream, CryptAlgorithmInstance.CreateEncryptor(), CryptoStreamMode.Write);
                    outStream.Write(CryptAlgorithmInstance.IV, 0, 16); // Write the IV to the beginning of the file for later decryption
                    cStream.Write(zeroFill.ToArray()); // Write 8 encrypted zero bytes to the file to serve as a checksum / password check when decrypting.
                    cStream.Write(sizeOfBytes); // Handling storing the original file name in the encrypted file if the user asked for that.
                    if (obfuscateNames) cStream.Write(oldNameBytes);
                    // Now we encrypt and write the contents of the original file to the output stream
                    inStream.CopyTo(cStream);
                    cStream.FlushFinalBlock();
                    cStream.Clear();

                    Console.WriteLine($"done. Saved to {outFileName}");
                }

                if (deleteOnFinish) File.Delete(file);
            }
            catch (Exception e)
            {
                Console.Write("failed. Reason: ");
                Console.WriteLine(e.Message);
                if (File.Exists(outFileName)) File.Delete(outFileName);
            }
        }
    }

    // Helper method to do... exactly what it looks like it does.
    private static string GenerateRandomString(int size = 16)
    {
        const string characters = "QWERTYUIOPASDFGHJKLZXCVBNM1234567890qwertyuiopasdfghjklzxcvbnm";
        StringBuilder sb = new();
        for (int i = 0; i < size; i++)
        {
            sb.Append(characters[StringGeneratorRandom.Next(characters.Length)]);
        }
        return sb.ToString();
    }
}