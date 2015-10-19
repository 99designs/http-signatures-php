<?php

namespace HttpSignatures;

use Symfony\Component\HttpFoundation\ParameterBag;
use Symfony\Component\HttpFoundation\Request;

class SymfonyRequestMessage
{
    /** @var Request */
    private $request;

    /** @var ParameterBag */
    public $headers;

    /**
     * @param Request $request
     */
    public function __construct($request)
    {
        $this->request = $request;
        $this->headers = $request->headers;
    }

    /**
     * @return string
     */
    public function getPathInfo()
    {
        return $this->request->getPathInfo();
    }

    /**
     * @return string|null
     */
    public function getQueryString()
    {
        // Symfony\Component\HttpFoundation\Request::getQueryString() is not
        // suitable for HTTP signatures as it mangles the query string.
        if ($this->request->getQueryString() === null) {
            return;
        } else {
            return $this->request->server->get('QUERY_STRING');
        }
    }

    /**
     * @return string
     */
    public function getMethod()
    {
        return $this->request->getMethod();
    }
}
