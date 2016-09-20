<?php

namespace HttpSignatures\tests;

use HttpSignatures\HeaderList;

class HeaderListTest extends \PHPUnit_Framework_TestCase
{
    public function testToString()
    {
        $hl = new HeaderList(['(request-target)', 'Date']);
        $this->assertEquals('(request-target) date', $hl->string());
    }

    public function testFromStringRoundTripNormalized()
    {
        $hl = HeaderList::fromString('(request-target) Accept');
        $this->assertEquals('(request-target) accept', $hl->string());
    }
}
