using CommunityToolkit.Maui.Storage;
using Core;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace vbcrypt_maui;

[SupportedOSPlatform("Android26.0")] // needed to clean up some green squiggly lines
[SupportedOSPlatform("iOS14.0")]
[SupportedOSPlatform("MacCatalyst14.0")] // not even sure if this would support these lol
[SupportedOSPlatform("Windows")]
public partial class MainPage : ContentPage
{
    private const string DEFAULT_PASSWORD = "Putting the 'default' in 'the user failed to provide a password and now we have to use a default.'";

    private readonly SymmetricAlgorithm cryptAlgo;
    private readonly HashAlgorithm hashAlgo;
    private readonly Core.CryptHandler cryptHandler;
    public MainPage()
	{
        // I know this doesn't take full advantage of the dependency injection that I set up for
        // CryptHandler, but currently there's only one implementation of SymmetricAlgorithm that
        // is considered secure, and using it with the largest key size is considered "correct."
        // Given that SHA256 is secure and generates a key of the right size... why not use that?
        cryptAlgo = Aes.Create();
        cryptAlgo.KeySize = 256;
        hashAlgo = SHA256.Create(); // The security of this hash algorithm matters because it reduces the chance of a key collision (making brute force harder)
        cryptHandler = new(cryptAlgo, hashAlgo);

        InitializeComponent();
	}

    private async void Button_Encrypt_Clicked(object sender, EventArgs e)
    {
        try
        {
            SetKeyFromUser();
            var inputFileListResult = await FilePicker.PickMultipleAsync(); // Get files to operate on
            if (!inputFileListResult.Any()) return; // In case the user cancels
            var outputDirectoryResult = await FolderPicker.Default.PickAsync(CancellationToken.None);
            if (!outputDirectoryResult.IsSuccessful) return;
            foreach (var inputFileResult in inputFileListResult)
            {
                Stream inputFile = await inputFileResult.OpenReadAsync();
                bool doObfuscate = Option_Obfuscate.IsChecked; // In case the user decides to be funny and click the checkbox between these two statements. Isn't asynchrony wonderful?
                string outFileName = doObfuscate ? $"{CryptHandler.GenerateRandomString(12)}.vbcr" : $"{inputFileResult.FileName}.vbcr";
                byte[] originalNameBytes = doObfuscate ? Encoding.UTF8.GetBytes(inputFileResult.FileName) : Array.Empty<byte>();
                Stream outputFile = File.OpenWrite(Path.Combine(outputDirectoryResult.Folder.Path, outFileName));
                cryptHandler.Encrypt(inputFile, originalNameBytes, outputFile);
                OutputLogBox.Text += $"\n{inputFileResult.FileName} was encrypted to {outFileName}";
            }
        }
        catch (Exception ex)
        {
            await DisplayAlert("A problem occurred", ex.Message, "OK");
        }
    }
    private async void Button_Decrypt_Clicked(object sender, EventArgs e)
    {
        try
        {
            SetKeyFromUser();
            var inputFileListResult = await FilePicker.PickMultipleAsync(); // Get files to operate on
            if (!inputFileListResult.Any()) return; // In case the user cancels
            var outputDirectoryResult = await FolderPicker.Default.PickAsync(CancellationToken.None);
            if (!outputDirectoryResult.IsSuccessful) return;
            foreach (var inputFileResult in inputFileListResult)
            {
                Stream inputFile = await inputFileResult.OpenReadAsync();
                var outFileName = cryptHandler.Decrypt(inputFile, inputFileResult.FileName, outputDirectoryResult.Folder.Path);
                OutputLogBox.Text += $"\n{inputFileResult.FileName} was decrypted to {outFileName}";
            }
        }
        catch (Exception ex)
        {
            await DisplayAlert("A problem occurred", ex.Message, "OK");
        }
    }

    //Helper method to turn the user-provided password into a valid encryption key
    private void SetKeyFromUser()
    {
        var password = Entry_KeyField.Text;
        if (string.IsNullOrEmpty(password)) password = DEFAULT_PASSWORD;
        password = password.Normalize(); // ArgumentException should never be thrown because the user should never type invalid/unprintable Unicode.
                                         // I don't think it's worth handling gracefully. If the user wants to be funny, they will be rewarded with an error.
                                         // The reason Normalize is called here is to prevent a potential issue where two Unicode variations of the
                                         // same password key would create two encryption keys.
        cryptHandler.HashAndSetKey(Encoding.UTF8.GetBytes(password));
    }
}