<?php

namespace HttpSignatures;

use Symfony\Component\HttpFoundation\Request;

class SigningString
{
    /** @var HeaderList */
    private $headerList;

    /** @var Request|SymfonyRequestMessage */
    private $message;

    /**
     * @param HeaderList                    $headerList
     * @param Request|SymfonyRequestMessage $message
     */
    public function __construct($headerList, $message)
    {
        $this->headerList = $headerList;
        if ($message instanceof Request) {
            $this->message = new SymfonyRequestMessage($message);
        } else {
            $this->message = $message;
        }
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
     *
     * @return string
     *
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
     *
     * @return string
     *
     * @throws SignedHeaderNotPresentException
     */
    private function headerValue($name)
    {
        $headers = $this->message->headers;
        if ($headers->has($name)) {
            return $headers->get($name);
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
        $path = $this->message->getPathInfo();
        $qs = $this->message->getQueryString();
        if ($qs === null) {
            return $path;
        } else {
            return "$path?$qs";
        }
    }
}
