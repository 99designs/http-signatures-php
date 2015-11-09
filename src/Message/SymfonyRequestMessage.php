<?php

namespace HttpSignatures\Message;

use Symfony\Component\HttpFoundation\Request;

class SymfonyRequestMessage implements MessageInterface
{
    /**
     * @var Request
     */
    private $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    public function getHeaders()
    {
        return $this->request->headers->all();
    }

    public function setHeader($header, $value)
    {
        $this->request->headers->set($header, $value);
    }

    public function getRequestTarget()
    {
        $path = $this->getPathInfo();
        $qs = $this->getQueryString();
        if ($qs === null) {
            return $path;
        } else {
            return "$path?$qs";
        }
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
