# Ransomware
A ransomware made in rust (just for fun)

## How to use
- First run ther server.js file
- Then run the virus with the action you wanna do as the argument (either `run` or `restore`)
- Since cargo has its own arguments, the line to pass the arguments to the program itself would look something like `cargo run -- run` or `cargo run -- restore`

### Run
The run command takes a target directory to encrypt (the default being './test') and, if the server is running, encrypts the files in the folder recursively and sends the encryption key to the server. The key will be printed on the screen by the server and needs to be stored in order to get the files back.

### Restore
The restore command takes the directory of the file where the key is stored (default being 'key.txt') and a target directory(default './test') and decrypts the files recursively in the target directory.

## Notes
- The virus can encrypt everything (i think), txt files, images, exe... but obviously be careful about losing them, if there's no key they can't be restored
- As of now, the virus is using AES-256-GCM from the ring crate, but i have plans to (maybe) write my own encryption later
