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
     * @param string $key
     * @param string $data
     *
     * @return string
     */
    public function sign($secret, $data)
    {
        return hash_hmac($this->digestName, $data, $secret, true);
    }

    public function verify($message, $signature, $verifyingKey)
    {
        return hash_equals(
            base64_encode($this->sign($verifyingKey, $message)),
            $signature
        );
    }
}
