<?php

namespace HttpSignatures\tests;

use HttpSignatures\HeaderList;
use HttpSignatures\HmacAlgorithm;
use HttpSignatures\Key;
use HttpSignatures\RsaAlgorithm;
use HttpSignatures\SignatureParameters;

class SignatureParametersTest extends \PHPUnit_Framework_TestCase
{
    public function testToString()
    {
        $key = new Key('pda', 'secret');
        $algorithm = new HmacAlgorithm('sha256');
        $headerList = new HeaderList(['(request-target)', 'date']);

        $signature = $this->getMockBuilder('HttpSignatures\Signature')
            ->disableOriginalConstructor()
            ->getMock();

        $signature
            ->expects($this->any())
            ->method('string')
            ->will($this->returnValue('thesignature'));

        $sp = new SignatureParameters($key, $algorithm, $headerList, $signature);

        $this->assertEquals(
            'keyId="pda",algorithm="hmac-sha256",headers="(request-target) date",signature="dGhlc2lnbmF0dXJl"',
            $sp->string()
        );
    }

    public function testRSAToString()
    {
        $key = new Key('rsaTest', 'secret');
        $algorithm = new RsaAlgorithm('sha256');
        $headerList = new HeaderList(['(request-target): post /inbox', 'date']);

        $signature = $this->getMockBuilder('HttpSignatures\Signature')
            ->disableOriginalConstructor()
            ->getMock();

        $signature
            ->expects($this->any())
            ->method('string')
            ->will($this->returnValue('thesignature'));

        $sp = new SignatureParameters($key, $algorithm, $headerList, $signature);

        $this->assertEquals(
            'keyId="rsaTest",algorithm="rsa-sha256",headers="(request-target): post /inbox date",signature="dGhlc2lnbmF0dXJl"',
            $sp->string()
        );
    }
}
