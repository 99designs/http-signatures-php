<?php

namespace HttpSignatures;

class SigningString
{
    private $headerList;
    private $message;

    public function __construct($headerList, $message)
    {
        $this->headerList = $headerList;
        $this->message = $message;
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
        $qs = $this->message->getQueryString();
        if ($qs === null) {
            return $this->message->getPathInfo();
        } else {
            return sprintf('%s?%s', $this->message->getPathInfo(), $qs);
        }
    }
}
