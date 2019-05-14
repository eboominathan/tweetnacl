const express = require('express');
const port = process.env.PORT || 8000; /* setting up port */;
const path = require("path");
const app = express();




const nacl = require("tweetnacl") // cryptographic functions
const util = require("tweetnacl-util") // encoding & decoding 





function encrypt(receiverPublicKey, msgParams) {
  const ephemeralKeyPair = nacl.box.keyPair()  
  const pubKeyUInt8Array = util.decodeBase64(receiverPublicKey)  
  const msgParamsUInt8Array = util.decodeUTF8(msgParams)  
  const nonce = nacl.randomBytes(nacl.box.nonceLength)
  const encryptedMessage = nacl.box(
     msgParamsUInt8Array,
     nonce,        
     pubKeyUInt8Array,
     ephemeralKeyPair.secretKey
  )  
  return {    
    ciphertext: util.encodeBase64(encryptedMessage),    
    ephemPubKey: util.encodeBase64(ephemeralKeyPair.publicKey),
    nonce: util.encodeBase64(nonce),     
    version: "x25519-xsalsa20-poly1305"  
  }
  
}


/* Decrypt a message with a base64 encoded secretKey (privateKey) */
function decrypt(receiverSecretKey, encryptedData) {  
  const receiverSecretKeyUint8Array = util.decodeBase64(
      receiverSecretKey
  )      
  const nonce = util.decodeBase64(encryptedData.nonce)      
  const ciphertext = util.decodeBase64(encryptedData.ciphertext)      
  const ephemPubKey = util.decodeBase64(encryptedData.ephemPubKey)      
  const decryptedMessage = nacl.box.open(
      ciphertext, 
      nonce,          
      ephemPubKey, 
      receiverSecretKeyUint8Array
  )
  return util.encodeUTF8(decryptedMessage)        
}



let result = encrypt('wOwSTana8C/tgFpQOb5OWV3Qekn5jk+BxPBAVEO/Buc=','Hello Boomi');
console.log(result);

// app.listen(port, () => {
//     console.log('Server is up and running on port number ' + port);
// });
