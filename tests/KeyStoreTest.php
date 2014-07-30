<?php

namespace HttpSignatures\Test;

use HttpSignatures\KeyStore;

class KeyStoreTest extends \PHPUnit_Framework_TestCase
{
    public function testFetchSuccess()
    {
        $ks = new KeyStore(array('id' => 'secret'));
        $key = $ks->fetch('id');
        $this->assertEquals('id', $key->id);
        $this->assertEquals('secret', $key->secret);
    }

    /**
     * @expectedException HttpSignatures\Exception
     */
    public function testFetchFail()
    {
        $ks = new KeyStore(array('id' => 'secret'));
        $key = $ks->fetch('nope');
    }

    public function testOnlyKey()
    {
        $ks = new KeyStore(array('id' => 'secret'));
        $key = $ks->onlyKey();
        $this->assertEquals('id', $key->id);
        $this->assertEquals('secret', $key->secret);
    }

    /**
     * @expectedException HttpSignatures\Exception
     */
    public function testOnlyKeyFailsWithMultiple()
    {
        $ks = new KeyStore(array('id' => 'secret', 'another' => 'key'));
        $key = $ks->onlyKey();
    }
}
