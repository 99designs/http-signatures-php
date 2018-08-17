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
        if ( ! openssl_get_privatekey($key) ) {
          throw new Exception("OpenSSL doesn't understand the supplied key (not valid or not found)");
        }
        $signature="";
        openssl_sign($data, $signature, $key, OPENSSL_ALGO_SHA256);
        return $signature;
    }
}
