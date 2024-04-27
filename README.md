# pw-manager
simple pw manager with a UI, uses hazmat and fernet encryption.

Just something i made in my free time, I know it could be more secure.

# Usage

When running for first time it will ask you to set a one time password, set that password and it will create a password.pk1 file within Appdata/Local/LemonPW/LemonPW/LemonPW, the password will be encrypted with the master fernet key you set (will add a function to generate one later).

To login just type in your password and then the program will encrypt the entered password with the master fernet key and compare them with the contenets of password.pk1.

To add passwords just enter in the name of your username/email, password, and website its for then click save, this will create another folder within the Appdata/Local/LemonPW/LemonPW/LemonPW, with the format 'username_website', within this folder password.txt will be created which is encrypted with a random fernet key, there will also be key.txt including the fernet key for that password encrypted with hazmat master key.

To retrieve your passwords go to the second tab and just click the password you want and it will be copied to your clipboard.


