<?php

namespace HttpSignatures;

use HttpSignatures\Message\MessageInterface;

class SigningString
{
    /** @var HeaderList */
    private $headerList;

    /**
     * @var MessageInterface
     */
    private $message;

    /**
     * @param HeaderList $headerList
     * @param MessageInterface $message
     */
    public function __construct($headerList, MessageInterface $message)
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
     * @param $name
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
     * @param $name
     * @return mixed
     * @throws SignedHeaderNotPresentException
     */
    private function headerValue($name)
    {
        $headers = $this->message->getHeaders();
        if (isset($headers[$name])) {
            return $headers[$name][0];
        } else {
            throw new SignedHeaderNotPresentException("Header '{$name}' not in message");
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
            $this->message->getRequestTarget()
        );
    }
}
