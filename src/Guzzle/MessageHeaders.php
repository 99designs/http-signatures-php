<?php

namespace HttpSignatures\Guzzle;

class MessageHeaders
{
    private $request;

    public function __construct($request)
    {
        $this->request = $request;
    }

    public function has($header)
    {
        return $this->request->hasHeader($header);
    }

    public function get($header)
    {
        return $this->request->getHeader($header);
    }

    public function set($header, $value)
    {
        $this->request->setHeader($header, $value);
    }
}
