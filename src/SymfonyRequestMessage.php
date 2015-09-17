<?php

namespace HttpSignatures;

class SymfonyRequestMessage
{
    private $request;
    public $headers;

    public function __construct($request)
    {
        $this->request = $request;
        $this->headers = $request->headers;
    }

    public function getPathInfo()
    {
        return $this->request->getPathInfo();
    }

    public function getQueryString()
    {
        // Symfony\Component\HttpFoundation\Request::getQueryString() is not
        // suitable for HTTP signatures as it mangles the query string.
        if ($this->request->getQueryString() === null) {
            return null;
        } else {
            return $this->request->server->get('QUERY_STRING');
        }
    }

    public function getMethod()
    {
        return $this->request->getMethod();
    }
}
