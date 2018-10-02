<?php

namespace HttpSignatures\tests;

use HttpSignatures\KeyStore;

class KeyStoreTest extends \PHPUnit_Framework_TestCase
{
    public function testFetchSuccess()
    {
        $ks = new KeyStore(['id' => 'secret']);
        $key = $ks->fetch('id');
        $this->assertEquals('id', $key->id);
        $this->assertEquals('secret', $key->secret);
    }

    /**
     * @expectedException \HttpSignatures\Exception
     */
    public function testFetchFail()
    {
        $ks = new KeyStore(['id' => 'secret']);
        $key = $ks->fetch('nope');
    }
}
