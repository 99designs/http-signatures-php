<?php

namespace HttpSignatures;

class HmacAlgorithm
{
    private $digestName;

    public function __construct($digestName)
    {
        $this->digestName = $digestName;
    }

    public function name()
    {
        return sprintf('hmac-%s', $this->digestName);
    }

    public function sign($key, $data)
    {
        return hash_hmac($this->digestName, $data, $key, true);
    }
}
