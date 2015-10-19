<?php

namespace HttpSignatures;

class HeaderList
{
    /** @var array */
    public $names;

    /**
     * @param array $names
     */
    public function __construct($names)
    {
        $this->names = array_map(
            array($this, 'normalize'),
            $names
        );
    }

    /**
     * @param $string
     *
     * @return HeaderList
     */
    public static function fromString($string)
    {
        return new static(explode(' ', $string));
    }

    /**
     * @return string
     */
    public function string()
    {
        return implode(' ', $this->names);
    }

    /**
     * @param $name
     *
     * @return string
     */
    private function normalize($name)
    {
        return strtolower($name);
    }
}
