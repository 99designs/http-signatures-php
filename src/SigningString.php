<?php

namespace HttpSignatures;

use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;

class SigningString
{
    /** @var HeaderList */
    private $headerList;

    /** @var RequestInterface */
    private $message;

    /**
     * @param HeaderList $headerList
     * @param MessageInterface $message
     */
    public function __construct($headerList, $message)
    {
        $this->headerList = $headerList;
        $this->message = $message;
    }

    /**
     * @return string
     */
    public function string()
    {
        return implode("\n", $this->lines());
    }

    /**
     * @return array
     */
    private function lines()
    {
        return array_map(
            array($this, 'line'),
            $this->headerList->names
        );
    }

    /**
     * @param string $name
     * @return string
     * @throws SignedHeaderNotPresentException
     */
    private function line($name)
    {
        if ($name == '(request-target)') {
            return $this->requestTargetLine();
        } else {
            return sprintf('%s: %s', $name, $this->headerValue($name));
        }
    }

    /**
     * @param string $name
     * @return string
     * @throws SignedHeaderNotPresentException
     */
    private function headerValue($name)
    {
        if ($this->message->hasHeader($name)) {
            return $this->message->getHeader($name);
        } else {
            throw new SignedHeaderNotPresentException("Header '$name' not in message");
        }
    }

    /**
     * @return string
     */
    private function requestTargetLine()
    {
        return sprintf(
            '(request-target): %s %s',
            strtolower($this->message->getMethod()),
            $this->getPathWithQueryString()
        );
    }

    /**
     * @return string
     */
    private function getPathWithQueryString()
    {
        $path = $this->message->getUri()->getPath();
        $qs = $this->message->getUri()->getQuery();
        if ($qs === null) {
            return $path;
        } else {
            return "$path?$qs";
        }
    }
}
