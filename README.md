# HashBreaker by Giuseppe Seminara 

Tool implementato per l'applicazione di un noto attacco alle funzioni crittografiche, il "**[Length Extension Attack](https://en.wikipedia.org/wiki/Length_extension_attack)**", studiato come applicazione pratica per la tesi triennale in Ingegneria Informatica dal nome "[Hash Length Extension: analisi ed implementazione dell’attacco](https://documentcloud.adobe.com/link/review?uri=urn:aaid:scds:US:c102b015-c54f-425a-a14d-d8c971c58090)".

Hashbreaker è un tool che effettua l’estensione della lunghezza sulle funzioni hash costruite secondo [Merkle-Damagard](https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction), in particolare su: ``MD5, SHA1, SHA256 e SHA512``. Tale attacco è noto in letteratura da molto tempo ma ancora utilizzato stante l’enorme diffusione di tali funzioni. L’utilizzo del detto tool è al solo fine didattico, atto a comprovare la “fragilità” delle costruzioni di tali funzioni se usate in modo improprio.

Per comprendere al meglio come il tool è stato implementato leggi la [spiegazione](https://documentcloud.adobe.com/link/review?uri=urn:aaid:scds:US:c102b015-c54f-425a-a14d-d8c971c58090#pageNum=40).

## Usage

```
$ ./hashbreaker.py --data=<data> --signature=<signature> --format=<format> --append=<data> --secret=<length>[options]

    INPUT OPTIONS
    -d --data=<data>                   The original string that we're going to extend
    --data-format=<format>             The format the string is being passed in as. Default: raw.
                                       Valid formats: raw, hex
    -s --signature=<signature>         The original signature
    --signature-format=<format>        The format the signature is being passed in as. Default: hex.
                                       Valid formats: raw, hex
    -f --format=<format>               The hash-type of the signature.
                                       Valid types: md5, sha1, sha256, sha512
    -a --append=<data>                 The data to append to the string.
    --append-format=<format>           The format the string is being passed in as.Default: raw.
                                       Valid formats: raw, hex
    -l --secret=<length>               The length of the secret, if known. Default: 5.

    OUTPUT OPTIONS
    --out-data-format=<format>         Output data format.
                                       Valid formats: raw, hex
    --out-signature-format=<format>    Output signature format.
                                       Valid formats: hex

    OTHER OPTIONS
    -h --help                          Display the usage (this).
    --test                             Run the test suite.
```
