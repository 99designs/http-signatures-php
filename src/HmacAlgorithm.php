<?php

namespace HttpSignatures;

class HmacAlgorithm implements AlgorithmInterface
{
    /** @var string */
    private $digestName;

    /** @var string */
    public $type = 'secret';

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
    public function sign($key, $data)
    {
        return hash_hmac($this->digestName, $data, $key, true);
    }
}
