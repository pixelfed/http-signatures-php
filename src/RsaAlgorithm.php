<?php

namespace HttpSignatures;

class RsaAlgorithm implements AlgorithmInterface
{
    /** @var string */
    private $digestName;

    /**
     * @param string $digestName
     */
    public function __construct($digestName)
    {
        $this->digestName = $digestName;
    }

    /**
     * @return string
     */
    public function name()
    {
        return sprintf('rsa-%s', $this->digestName);
    }

    /**
     * @param string $key
     * @param string $data
     *
     * @return string
     */
    public function sign($key, $data)
    {
        $alg = OPENSSL_ALGO_SHA256;
        $pkey = openssl_pkey_get_private($key);
        $res = openssl_sign($data, $signature, $pkey, $alg);
        openssl_free_key($pkey);
        return $res;
    }
}
