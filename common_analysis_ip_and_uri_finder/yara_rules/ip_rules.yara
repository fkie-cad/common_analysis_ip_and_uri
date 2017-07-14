rule IPv4 {
    strings:
        $a = /[\d]{1,3}(\.[\d]{1,3}){3}/

    condition:
        $a
}

rule IPv6 {
    strings:
        $a = /([\da-fA-F]{1,4})?\:([\da-fA-F]{1,4})?\:(([\da-fA-F]{1,4})?\:){0,5}([\da-fA-F]{1,4})?/
        $b = /([\da-fA-F]{1,4})?\:([\da-fA-F]{1,4})?\:(([\da-fA-F]{1,4})?\:){0,5}[\d]{1,3}(\.[\d]{1,3}){3}/

    condition:
        $a or $b
}