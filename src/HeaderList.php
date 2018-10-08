<?php

namespace HttpSignatures;

class HeaderList
{
    /** @var array */
    public $names;

    /** @var bool */
    private $headersSpecified = false;

    /**
     * @param array $names
     */
    public function __construct(array $names = null)
    {
        if (is_null($names)) {
            $this->names = ['date'];
        } else {
            $this->names = array_map(
                [$this, 'normalize'],
                $names
            );
            $this->headersSpecified = true;
        }
    }

    /**
     * @param $string
     *
     * @return HeaderList
     */
    public static function fromString($string)
    {
        if (is_null($string)) {
            return ['date'];
        } else {
            return new static(explode(' ', $string));
        }
    }

    /**
     * @return string
     */
    public function string()
    {
        return implode(' ', $this->names);
    }

    /**
     * @return bool
     */
    public function headersSpecified()
    {
        return $this->headersSpecified;
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
