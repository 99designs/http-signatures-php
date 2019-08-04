<?php

namespace HttpSignatures\tests;

use HttpSignatures\HeaderList;
use PHPUnit\Framework\TestCase;

class HeaderListTest extends TestCase
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
