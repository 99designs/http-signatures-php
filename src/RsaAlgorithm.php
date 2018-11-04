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
     *
     * @throws \HttpSignatures\Exception
     */
    public function sign($key, $data)
    {
        if (!openssl_sign($data, $signature, $key, $this->algo())) {
            throw new Exception('Failed to sign: '.openssl_error_string());
        }

        return $signature;
    }

    /**
     * @param string $signature
     * @param string $key
     * @param string $data
     *
     * @return bool
     */
    public function verify($signature, $key, $data)
    {
        return openssl_verify($data, base64_decode($signature), $key, $this->algo());
    }

    private function algo()
    {
        $algo = constant(sprintf('OPENSSL_ALGO_%s', strtoupper($this->digestName)));
        if (!$algo) {
            throw new Exception("Unsupported hash '$digestName'");
        }

        return $algo;
    }
}
