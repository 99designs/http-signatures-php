<?php

namespace HttpSignatures;

class HmacAlgorithm implements AlgorithmInterface
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
        return sprintf('hmac-%s', $this->digestName);
    }

    /**
     * @param string $secret
     * @param string $data
     *
     * @return string
     */
    public function sign($secret, $data)
    {
        return hash_hmac($this->digestName, $data, $secret, true);
    }

    /**
     * @param string $signature
     * @param string $secret
     * @param string $data
     *
     * @return bool
     */
    public function verify($signature, $secret, $data)
    {
        $expectedSignature = base64_encode($this->sign($secret, $data));

        return hash_equals($expectedSignature, $signature);
    }
}
