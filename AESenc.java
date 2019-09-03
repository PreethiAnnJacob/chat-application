/*The java.security package contains the classes and interfaces that implement the Java security architecture. These classes can be divided into two broad categories. 
First, there are classes that implement access control and prevent untrusted code from performing sensitive operations. 
Second, there are authentication classes that implement message digests and digital signatures and can authenticate Java classes and other objects.*/
import java.security.*;

/*Package java.security.spec Description
Provides classes and interfaces for key specifications and algorithm parameter specifications.
A key specification is a transparent representation of the key material that constitutes a key. 
A key may be specified in an algorithm-specific way, or in an algorithm-independent encoding format (such as ASN.1). 
This package contains key specifications for DSA public and private keys, RSA public and private keys, 
PKCS #8 private keys in DER-encoded format, and X.509 public and private keys in DER-encoded format.
An algorithm parameter specification is a transparent representation of the sets of parameters used with an algorithm. 
This package contains an algorithm parameter specification for parameters used with the DSA algorithm.*/
import java.security.spec.InvalidKeySpecException;
//InvalidKeySpecException   :   This is the exception for invalid key specifications.

import javax.crypto.*;//The javax.crypto package defines classes and interfaces for various cryptographic operations.

/*SecretKeySpec class is a transparent and algorithm-independent representation of a secret key. 
This class is useful only for encryption algorithms (such as DES and DESede) whose secret keys can be represented as arbitrary byte arrays and do not require auxiliary parameters. */
import javax.crypto.spec.SecretKeySpec;

import sun.misc.*;

class AESenc {

    private static final String ALGO = "AES";
    private static final byte[] keyValue
            = new byte[]{'Z', '4', 'e', 't', 'e', '_', 't',
                'S', '-', '!', '2', '%', 't', 'K', 'e', ';'};

    public static String encrypt(String Data) throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = c.doFinal(Data.getBytes());//call the doFinal() with the data to encrypt or decrypt

        /*public byte[] getBytes(String charsetName)    :   It encodes the String into sequence of bytes using the specified charset and return the array of those bytes. 
                                                            It throws UnsupportedEncodingException – If the specified charset is not supported.
        public byte[] getBytes()                        :   It encodes the String using default charset method.*/

        String encryptedValue = new BASE64Encoder().encode(encVal);
        /*public byte[] encode(byte[] src)              :   Encodes all bytes from the specified byte array into a newly-allocated byte array using the Base64 encoding scheme.*/

        return encryptedValue;
    }

    public static String decrypt(String encryptedData) throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedData);
        byte[] decValue = c.doFinal(decordedValue);
        String decryptedValue = new String(decValue);
        return decryptedValue;
    }
    
    private static Key generateKey() throws Exception {
        Key key = new SecretKeySpec(keyValue, ALGO);
        return key;
    }
}
