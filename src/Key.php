<?php

namespace HttpSignatures;

class Key
{
    public $id;
    public $secret;

    public function __construct($id, $secret)
    {
        $this->id = $id;
        $this->secret = $secret;
    }
}
