rule URI {
    strings:
        $a = /[a-zA-Z]+\:\/\/[a-zA-Z0-9_\-\/.:]+/

    condition:
        $a
}