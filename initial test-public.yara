rule firefly_malware
{
        strings:
                $a = "\\firefly\\Release\\firefly.pdb"
        condition:
                any of them
}
