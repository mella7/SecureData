# SecureData

'''
 __                             ___      _        
/ _\ ___  ___ _   _ _ __ ___   /   \__ _| |_ __ _ 
\ \ / _ \/ __| | | | '__/ _ \ / /\ / _` | __/ _` |
_\ \  __/ (__| |_| | | |  __// /_// (_| | || (_| |
\__/\___|\___|\__,_|_|  \___/___,' \__,_|\__\__,_|
'''
                                                  

SecureData is a basic Python-based application that offers robust functionalities for user data security, encryption, and authentication. This project caters to two major aspects: Registration and Authentication, ensuring secure handling of sensitive information.

I developed this mini-project as part of my coursework for the 'Python Programming' subject at Tek Up University.

This is the assignment that was required:
 
1- Registration
  1-a Email (should be valid (Regular Expression))
  1-b Pwd (typed in an invisible way, a password that is composed of 1 uppercase letter, 1 lowercase letter, 1 digit, 1 special character, and has a length     of 8)
  Ind. Email:Login will be recorded in a file named 'Enregistrement.txt'.

2- Authentication
  2-a: Email
  2-b: Pwd
  If the credentials exist in 'Enregistrement.txt', a menu will appear (see further). Otherwise, the user will be prompted to register.
  Ind. The menu, once authenticated, is as follows:
    A- Provide a word to be hashed (in invisible mode)
      a- Hash the word with sha256
      b- Hash the word by generating a salt (bcrypt)
      c- Attack the inserted word by dictionary.
      d- Return to the main menu
     B- Encryption (RSA)
      a- Generate key pairs into a file
      b- Encrypt a message of your choice using RSA
      c- Decrypt the message (b)
      d- Sign a message of your choice using RSA
      e- Verify the signature of the message (d)
      f- Return to the main menu
    C- Certificate (RSA)
      a- Generate key pairs into a file
      b- Generate a self-signed certificate using RSA
      c- Encrypt a message of your choice using this certificate
      d- Return to the main menu
      
## Notes

For proper execution, ensure you have all the required Python libraries. You can install these dependencies using the following command:

```bash
pip install -r requirements.txt


