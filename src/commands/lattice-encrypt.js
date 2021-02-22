/*

example: 
  
  lattice-encrypt \
    { kyber | ecdsa | aes-128 | aes-192 | aes-256 } \
    { /dataFile | "someText" } \
    { /enc_dataFile | JSON_stdout } \
    -p { pubKeyFile | JSON | transactionHash }
    -s { shared_KeyFile } \
	-e encryptionPass for sharedKeyFile

Command will encrypt data using the encryption method mentioned. if aes-* is chosen user will also 
need to provide the shared_keylist the other user also possesses.

if pub-key is given the receiving users keys will be used to encrypt the data, otherwise use kyber or ecdsa keys 
to encrypt data (shake the keys and use in AES?)


// 128-bit, 192-bit and 256-bit keys
var key_128 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
var key_192 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
               16, 17, 18, 19, 20, 21, 22, 23];
var key_256 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
               16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
               29, 30, 31];


*/