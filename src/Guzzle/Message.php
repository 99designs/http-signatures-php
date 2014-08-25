<?php

namespace HttpSignatures\Guzzle;

class Message
{
    private $request;
    public $headers;

    public function __construct($request)
    {
        $this->request = $request;
        $this->headers = new MessageHeaders($request);
    }

    public function getQueryString()
    {
        return $this->request->getQuery(true);
    }

    public function getMethod()
    {
        return $this->request->getMethod();
    }

    public function getPathInfo()
    {
        return $this->request->getPath();
    }
}
