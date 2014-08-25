<?php

namespace HttpSignatures\Guzzle;

use Guzzle\Common\Event;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

class CreateRequestSubscriber implements EventSubscriberInterface
{
    private $context;

    function __construct($context)
    {
        $this->context = $context;
    }

    public static function getSubscribedEvents()
    {
        return array(
            'client.create_request' => 'signRequest'
        );
    }

    public function signRequest($e)
    {
        $this->context->signer()->sign(new Message($e['request']));
    }
}
