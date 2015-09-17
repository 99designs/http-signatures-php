<?php

namespace HttpSignatures;

use HttpSignatures\SymfonyRequestMessage;

class SigningString
{
    private $headerList;
    private $message;

    public function __construct($headerList, $message)
    {
        $this->headerList = $headerList;
        if ($message instanceof \Symfony\Component\HttpFoundation\Request) {
            $this->message = new SymfonyRequestMessage($message);
        } else {
            $this->message = $message;
        }
    }

    public function string()
    {
        return implode("\n", $this->lines());
    }

    private function lines()
    {
        return array_map(
            array($this, 'line'),
            $this->headerList->names
        );
    }

    private function line($name)
    {
        if ($name == '(request-target)') {
            return $this->requestTargetLine();
        } else {
            return sprintf('%s: %s', $name, $this->headerValue($name));
        }
    }

    private function headerValue($name)
    {
        $headers = $this->message->headers;
        if ($headers->has($name)) {
            return $headers->get($name);
        } else {
            throw new SignedHeaderNotPresentException("Header '$name' not in message");
        }
    }

    private function requestTargetLine()
    {
        return sprintf(
            '(request-target): %s %s',
            strtolower($this->message->getMethod()),
            $this->getPathWithQueryString()
        );
    }

    private function getPathWithQueryString()
    {
        $path = $this->message->getPathInfo();
        $qs = $this->message->getQueryString();
        if ($qs === null) {
            return $path;
        } else {
            return "$path?$qs";
        }
    }
}
