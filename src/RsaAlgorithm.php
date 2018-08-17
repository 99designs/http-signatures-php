<?php

namespace HttpSignatures;

class RsaAlgorithm implements AlgorithmInterface
{
    /** @var string */
    private $digestName;

    /**
     * @param string $digestName
     */
    public function __construct($digestName)
    {
        $this->digestName = $digestName;
    }

    /**
     * @return string
     */
    public function name()
    {
        return sprintf('rsa-%s', $this->digestName);
    }

    /**
     * @param string $key
     * @param string $data
     *
     * @return string
     */
    public function sign($key, $data)
    {
        switch ($this->digestName) {
          case 'sha224':
            $algo = OPENSSL_ALGO_SHA224;
            break;
          case 'sha256':
            $algo = OPENSSL_ALGO_SHA256;
            break;
          case 'sha384':
            $algo = OPENSSL_ALGO_SHA384;
            break;
          case 'sha512':
            $algo = OPENSSL_ALGO_SHA512;
            break;
          default:
            throw new Exception($this->digestName . " is not a supported hash format for RSA");
            break;
        }
        if ( ! openssl_get_privatekey($key) ) {
          throw new Exception("OpenSSL doesn't understand the supplied key (not valid or not found)");
        }
        $signature="";
        openssl_sign($data, $signature, $key, $algo);
        return $signature;
    }
}
