<?php

namespace HttpSignatures;

use Psr\Http\Message\RequestInterface;

class SigningString
{
    /** @var HeaderList */
    private $headerList;

    /** @var RequestInterface */
    private $message;

    /**
     * @param HeaderList $headerList
     * @param RequestInterface $message
     */
    public function __construct(HeaderList $headerList, $message)
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
            [$this, 'line'],
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
            $header = $this->message->getHeader($name);
            return end($header);
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
        if (empty($qs)) {
            return $path;
        } else {
            return "$path?$qs";
        }
    }
}
