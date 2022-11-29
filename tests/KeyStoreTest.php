<?php

namespace HttpSignatures\tests;

use HttpSignatures\KeyStore;
use PHPUnit\Framework\TestCase;

class KeyStoreTest extends TestCase
{
    public function testFetchSuccess()
    {
        $ks = new KeyStore(['id' => 'secret']);
        $key = $ks->fetch('id');
        $this->assertEquals('id', $key->id);
        $this->assertEquals('secret', $key->secret);
    }

    public function testFetchFail()
    {
        $this->expectException(\HttpSignatures\Exception::class);
        $ks = new KeyStore(['id' => 'secret']);
        $key = $ks->fetch('nope');
    }
}
