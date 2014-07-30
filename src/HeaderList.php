<?php

namespace HttpSignatures;

class HeaderList
{
    public $names;

    public function __construct($names)
    {
        $this->names = array_map(
            array($this, "normalize"),
            $names
        );
    }

    public function __toString()
    {
        return implode(' ', $this->names);
    }

    private function normalize($name)
    {
        return strtolower($name);
    }
}
