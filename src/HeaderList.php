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

    public static function fromString($string)
    {
        return new static(explode(' ', $string));
    }

    public function string()
    {
        return implode(' ', $this->names);
    }

    private function normalize($name)
    {
        return strtolower($name);
    }
}
