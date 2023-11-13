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

    // Handles improper handling of this class
    ~CryptHandler()
    {
        CryptAlgorithmInstance.Clear();
        HashAlgorithmInstance.Clear();
    }

    public void HashAndSetKey(byte[] bytes)
    {
        // The purpose of this hash algorithm is to normalize the input to the size of a key
        // while preventing collissions between different passwords (making brute forcing harder).
        CryptAlgorithmInstance.Key = HashAlgorithmInstance.ComputeHash(bytes);
    }

    // It is amazing how much this shrunk down when I moved the Stream handling to the UI.
    public void Encrypt(Stream input, byte[] nameBytesToStore, Stream output)
    {
        Span<byte> zeroFill = stackalloc byte[8];
        zeroFill.Clear(); // Not actually sure if this is necessary but it never hurts to be sure.
        CryptAlgorithmInstance.GenerateIV(); // Necessary since this can run multiple times in succession
        byte[] sizeOfBytes = BitConverter.GetBytes(nameBytesToStore.Length); // little bit easier, but it's not great to have to pass in nameBytesToStore.
        using CryptoStream cStream = new(output, CryptAlgorithmInstance.CreateEncryptor(), CryptoStreamMode.Write);
        output.Write(CryptAlgorithmInstance.IV, 0, 16); // Write the IV to the beginning of the file for later decryption
        cStream.Write(zeroFill.ToArray()); // Write 8 encrypted zero bytes to the file to serve as a checksum / password check when decrypting.
        cStream.Write(sizeOfBytes); // Handling storing the original file name in the encrypted file if the user asked for that.
        cStream.Write(nameBytesToStore); // Storing the name bytes if there are any (can be a length 0 array)
        input.CopyTo(cStream); // Actually encrypting the file
        cStream.FlushFinalBlock(); // Finalization
        cStream.Clear();
    }

    // This method also shrunk down, but not nearly as much as Encrypt() did.
    public string Decrypt(Stream input, string inputFileName, string outputFolderPath)
    {
        bool hasVbcrExt = inputFileName.EndsWith(".vbcr");
        // Recover the IV from the first 16 bytes of the file. DO NOT DO THE OBVIOUS REFACTOR OF REMOVING recoveredIV.
        byte[] recoveredIV = new byte[16];
        input.ReadExactly(recoveredIV, 0, 16);
        CryptAlgorithmInstance.IV = recoveredIV; // If you set this without a buffer it causes issues. No idea why.
        using CryptoStream cStream = new(input, CryptAlgorithmInstance.CreateDecryptor(), CryptoStreamMode.Read);
        // Attempt to recover the eight null-bytes that serve as a quick password check
        byte[] checksumBytes = new byte[8];
        cStream.ReadExactly(checksumBytes, 0, 8);
        for (int i = 0; i < 8; i++)
        {
            if (checksumBytes[i] != 0)
            {
                throw new CryptographicException("The password provided was incorrect.");
            }
        }
        // Recover the size of the original file name and interpret, then open an output stream.
        string outFileName;
        byte[] origNameSizeBytes = new byte[4];
        cStream.ReadExactly(origNameSizeBytes, 0, 4);
        int origNameSize = BitConverter.ToInt32(origNameSizeBytes);
        if (origNameSize > 0)
        {
            byte[] origNameBytes = new byte[origNameSize];
            cStream.ReadExactly(origNameBytes, 0, origNameSize);
            outFileName = Encoding.UTF8.GetString(origNameBytes);
        }
        else
            outFileName = hasVbcrExt ? $"{inputFileName[..^4]}" : $"{inputFileName}.decrypted";
        using FileStream outStream = File.OpenWrite(Path.Combine(outputFolderPath, outFileName));
        // And we're off; we can decrypt data until EOF.
        cStream.CopyTo(outStream);
        outStream.Flush();
        cStream.Clear();
        return outFileName; // Used to update the output box in the UI.
    }

    // Helper method to do... exactly what it looks like it does.
    public static string GenerateRandomString(int size = 16)
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