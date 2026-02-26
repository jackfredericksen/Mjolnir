rule CryptoMiner_Generic : medium
{
    meta:
        description = "Detects cryptocurrency mining indicators"
        severity = "medium"
        author = "Mjolnir"

    strings:
        $pool1 = "stratum+tcp://" ascii wide
        $pool2 = "stratum+ssl://" ascii wide
        $pool3 = "pool.minergate" ascii wide
        $pool4 = "xmrpool.eu" ascii wide
        $pool5 = "nanopool.org" ascii wide
        $algo1 = "cryptonight" ascii wide nocase
        $algo2 = "randomx" ascii wide nocase
        $algo3 = "ethash" ascii wide nocase
        $wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii  // Bitcoin address pattern
        $xmr = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii     // Monero address pattern

    condition:
        (any of ($pool*)) or (any of ($algo*) and ($wallet or $xmr))
}
