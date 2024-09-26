rule rtf_with_hyperlink
{
    meta:
        author         = "Nilanjana Saha"
        attribution    = "SEI Incident Response and Countermeasures"
        description    = "This rule detects RTF files containing a hyperlink to a phishing site."
        creation_date  = "2024-03-27"
        last_modified  = ""
        samples        = "453e22bea865bde28dafec12408f578670a49db8074c0a7b3e359a66c4a2c905"
        greetz         = "Thanks to the a1000 Reversing Labs Crew for the research assist"
        prod           = "true"
        family         = ""
        process        = "Upload the file to Twinwave, check for VT, ClamAV, confirmations. Once validated that this is malicious - remediate as required (e.g., block, contact end user, open intel on any identified IoCs, etc)."
        reference      = "https://app.twinwave.io/job/f4724ea3-95ca-4df6-8bd3-1c4b4350a3ba"

    strings:
        $pdf_header = { 7b 5c 72 74 66 31 }     // {\rtf1
        $string1    = "HYPERLINK"
        $string2    = "Download Link"
        $http_call  = "http"

    condition:
        $pdf_header at 0 and 
        all of ($string*) and 
        $http_call and 
        filesize > 3KB and filesize < 5KB
}
