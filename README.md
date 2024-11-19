# rsa-aes-encryption-decryption-qtcpp

This multi-platform app, `rsa-aes-encryption-decryption-qtcpp`, is openssl app representing its function in RSA and AES algorithms in nice graphical view for the user. Resulting keys can be saved for later use in any format user wants (.pem) by default, or saving/loading encrypted or decrypted files. It can also combine RSA and AES encryption and also decrypt files encrypted with that standard.

## Installation

Please download one of the binaries from the TBA[Releases]() page. Currently available platforms are Windows and Linux with Mac support coming soon. If you would like to build `rsa-aes-encryption-decryption-qtcpp` from source instead, see TBA[BUILDING.md]().

## Usage

Opening binary for your OS opens up GUI that hold three sections, each section will be explained in its own paragraph.

### RSA Tools

This section holds all functions related to RSA only encryption and decryption. 
First action would be generating new key-pairs, which could be achieved with a button on right hand side of RSA Tools section. Combo box above the button `Generate Key Pair` holds choice for RSA key size. Minimal recommended size for RSA keys are 2048, while all choices include 2048, 3072 and 4096.
Second action would be writing/opening info you want to encrypt or decrypt. Top button in the section is Open File button, which lets users open the file they want to encrypt/decrypt, chosen file will be shown textually in text box below which can be additionally edited (only for encryption, edits will ruin decryption). User can choose not to open a file for encryption and just write needed info directly into text box below the button.
Next action would be loading the key with `Load key` button. Default filter is .pem, but user can choose any file that holds the keys. In case of encryption user needs to choose public key, while for decryption private key from same key pair in which public key was used for encryption.
After loading the key, user chooses selected action, encryption with public key or decryption with private key. Resulting text will be printed in text browser below which can then be save with `Save File` button.

### AES Tools

This section holds all functions related to AES only encryption and decryption. 
First action would be generating new key but is not needed. Generation could be achieved with a button on right hand side of AES Tools section with button called `Generate AES Key`. This will generate random bytes for the key, but if not chosen while encrypting program will generate key by itself and prompt user for save location.
Second action like RSA would be writing/opening info you want to encrypt or decrypt. Top button in the section is Open File button, which lets users open the file they want to encrypt/decrypt, chosen file will be shown textually in text box below which can be additionally edited (only for encryption, edits will ruin decryption). User can choose not to open a file for encryption and just write needed info directly into text box below the button.
Next action would be loading the key with `Load key` button. Default filter is .pem, but user can choose any file that holds the keys. In case of encryption if user doesn't choose the key the program will generate one and prompt user for save location, for decryption user must choose a key.
After loading the key, user chooses selected action, encryption or decryption. Resulting text will be printed in text browser below which can then be save with `Save File` button.

### Combined encryption and decryption

This section holds all function for hybrid encryption and decryption of both algorithms. Combined functionality offers encryption and decryption of large files with AES while encrypting the key that is appended with the text with RSA algorithm.
First action as with RSA would be generating key-pairs, refer to RSA Tools section for help.
After user loads RSA key, public for encryption and private for decryption, user can choose to encrypt or decrypt the file.
Resulting action will be shown in text browser on the right hand side of combined section. Generated text can be saved.

## Notes

Built binaries use OpenSSL indicated on the release page (latest 3.4.0). If you want to use your own OpenSSL library, build application from source or download one of shared library builds.
