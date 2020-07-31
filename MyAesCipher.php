<?php

/**
 * AesCipher
 *
 * Encode/Decode text by password using AES-128-CBC algorithm
 */
class AesCipher
{
    const CIPHER = 'AES-128-CBC';
    const INIT_VECTOR_LENGTH = 16;

    /**
     * AesCipher constructor.
     *
     */
    public function __construct()
    {

    }

    public static function encryptStrAndToBase64($keyStr, $enStr)
    {
      try {
        // $result = encrypt($keyStr, $keyStr, utf8_encode($enStr));
        $ivBytes = substr(md5($keyStr), 0, static::INIT_VECTOR_LENGTH);
        $keyBytes = hash('sha256', $keyStr);
        $enBytes = utf8_encode($enStr);        
        return static::encrypt($ivBytes, $keyBytes, $enBytes);
      } catch (\Exception $e) {
        return $e->getMessage();
      }
    }

    public static function encrypt($ivBytes, $keyBytes, $bytes) {
      try {
        // Encrypt input text
        $raw = openssl_encrypt(
            $bytes,
            static::CIPHER,
            $keyBytes,
            OPENSSL_RAW_DATA,
            $ivBytes
        );

        $result = base64_encode($raw);

        if ($result === false) {
            // Operation failed
            return new static($ivBytes, null, openssl_error_string());
        }

        // Return successful encoded object
        return $result;
      } catch (\Exception $e) {
          // Operation failed
          return new static(isset($ivBytes), null, $e->getMessage());
      }
    }

    public static function decryptStrAndFromBase64($keyStr, $deStr) 
    {
        try {
            $deBytes = base64_decode(utf8_decode($deStr));
            $ivBytes = substr(md5($keyStr), 0, static::INIT_VECTOR_LENGTH);
            $keyBytes = hash('sha256', $keyStr);
            return static::decrypt($ivBytes, $keyBytes, $deBytes);
        } catch (\Exception $e) {
            return $e->getMessage();
        }
    }

    public static function decrypt($ivBytes, $keyBytes, $deBytes)
    {
        try {
            $decoded = openssl_decrypt(
                $deBytes,
                static::CIPHER,
                $keyBytes,
                OPENSSL_RAW_DATA,
                $ivBytes
            );
    
            if ($decoded === false) {
                // Operation failed
                return new static(isset($ivBytes), null, openssl_error_string());
            }

            // Return successful decoded object
            return $decoded;
        } catch (\Exception $e) {
            // Operation failed
            return new static(isset($ivBytes), null, $e->getMessage());
        }
    }

}

// USAGE

$secretKey = '26kozQaKwRuNJ24t';
$text = 'Some text';

$encrypted = AesCipher::encryptStrAndToBase64($secretKey, $text);
$decrypted = AesCipher::decryptStrAndFromBase64($secretKey, $encrypted);

echo($encrypted);
echo("</br>");
echo($decrypted);
