<?php

namespace HttpSignatures;

class Key
{
    /** @var string */
    public $id;

    /** @var string */
    public $secret;

    /**
     * @param string $id
     * @param string $secret
     */
    public function __construct($id, $secret)
    {
        $this->id = $id;
        $this->secret = $secret;
    }
}
