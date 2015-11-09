<?php

namespace HttpSignatures\Message;

interface MessageInterface
{
    public function getMethod();

    public function getRequestTarget();

    public function getHeaders();

    public function setHeader($header, $value);
}
