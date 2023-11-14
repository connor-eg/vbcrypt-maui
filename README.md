# vbcrypt-maui
A GUI version of VBCrypt (https://github.com/connor-eg/vbcrypt), written using .NET MAUI. 

The idea of this project was to help me on my journey to learn some C# and .NET MAUI, and I have a better grasp on those things now.
The app allows you to encrypt or decrypt multiple files at once, and sends the processed files to a directory of your choosing.

## Features
- Works on Windows and Android devices (I do not have an iAnything but the source code is available if you'd like to compile it yourself for Mac/iPhone)
- Can encrypt files using a password
- Can decrypt files, so long as the password is the same as what was used for encryption
- Can obfuscate file names when encrypting files, and recover them on decryption
- Uses AES-256 and SHA256 (and may even use them correctly).

## Known issues
- Looks hideous in dark mode when tested on my phone.

# DISCLAIMER
I cannot guarantee that this software produces files that are A) secure or B) able to be recovered later.
If you use this software to encrypt your precious family photos and can't get them back, that is neither my fault nor my problem.

This is free software; caveat emptor.
