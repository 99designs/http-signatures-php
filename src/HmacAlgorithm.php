<?php

namespace HttpSignatures;

class HmacAlgorithm
{
    private $digestName;

    public function __construct($digestName)
    {
        $this->digestName = $digestName;
    }
}
